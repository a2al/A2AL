// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/chat"
	"github.com/a2al/a2al/internal/pow"
	"github.com/a2al/a2al/protocol"
	"golang.org/x/sync/singleflight"
)

type chatManager struct {
	baseDir string
	log     *slog.Logger
	mu      sync.Mutex
	open    map[a2al.Address]*chat.Store
	flight  singleflight.Group

	inviteMu    sync.Mutex
	inviteStep  map[a2al.Address]int
	inviteTimer map[a2al.Address]*time.Timer
}

func newChatManager(dataDir string, log *slog.Logger) *chatManager {
	return &chatManager{
		baseDir:     filepath.Join(dataDir, "agents"),
		log:         log,
		open:        make(map[a2al.Address]*chat.Store),
		inviteStep:  make(map[a2al.Address]int),
		inviteTimer: make(map[a2al.Address]*time.Timer),
	}
}

func (m *chatManager) store(aid a2al.Address) (*chat.Store, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.open[aid]; ok {
		return s, nil
	}
	s, err := chat.Open(filepath.Join(m.baseDir, hex.EncodeToString(aid[:]), "chat"))
	if err != nil {
		return nil, err
	}
	m.open[aid] = s
	return s, nil
}

func (m *chatManager) peek(aid a2al.Address) *chat.Store {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	s := m.open[aid]
	m.mu.Unlock()
	if s != nil {
		return s
	}
	roster := filepath.Join(m.baseDir, hex.EncodeToString(aid[:]), "chat", "roster.cbor")
	if _, err := os.Stat(roster); err != nil {
		return nil
	}
	s, err := m.store(aid)
	if err != nil {
		return nil
	}
	return s
}

func (d *Daemon) initChat() {
	if d.chats != nil {
		return
	}
	if d.dataDir == "" {
		return
	}
	d.chats = newChatManager(d.dataDir, d.log)
	d.registerChatConsumers()
	d.RegisterPending("chat_invites", d.chatPendingInvites)
	d.RegisterPending("chat_unread", d.chatPendingUnread)
}

func (d *Daemon) chatPendingInvites(aid a2al.Address) int {
	st := d.chats.peek(aid)
	if st == nil {
		return 0
	}
	return st.InPendingCount()
}

func (d *Daemon) chatPendingUnread(aid a2al.Address) int {
	st := d.chats.peek(aid)
	if st == nil {
		return 0
	}
	return st.TotalUnread()
}

func (d *Daemon) chatStore(aid a2al.Address) (*chat.Store, error) {
	if d.chats == nil {
		d.initChat()
	}
	if d.chats == nil {
		return nil, errNotFound
	}
	return d.chats.store(aid)
}

func (d *Daemon) registerChatConsumers() {
	d.RegisterEnvelopeConsumer(chat.KindInvite, d.onChatInvite)
	d.RegisterEnvelopeConsumer(chat.KindAccept, d.onChatAccept)
	d.RegisterEnvelopeConsumer(chat.KindRefuse, d.onChatRefuse)
	d.RegisterEnvelopeConsumer(chat.KindDing, d.onChatDing)
	d.RegisterEnvelopeConsumer(chat.KindPull, d.onChatPull)
	d.RegisterEnvelopeConsumer(chat.KindMsg, d.onChatMsg)
}

func (d *Daemon) onChatInvite(local, remote a2al.Address, _ string, body []byte) (bool, EnvelopeResult) {
	st, err := d.chatStore(local)
	if err != nil {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	e, ok := st.Get(remote)
	if ok {
		switch e.State {
		case chat.StateBlocked:
			return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
		case chat.StateMutual:
			d.enqueueChatHeal(local, remote)
			return true, EnvelopeResult{Code: protocol.EnvelopeOK}
		case chat.StateInPending:
			return true, EnvelopeResult{Code: protocol.EnvelopeOK}
		case chat.StateOutPending:
			_ = st.SetMutual(remote)
			d.enqueueChatHeal(local, remote)
			return true, EnvelopeResult{Code: protocol.EnvelopeOK}
		}
	}
	inv, err := chat.DecodeInvite(body)
	if err != nil || !chat.VerifyInvite(remote, local, inv, time.Now().Unix()) {
		return true, EnvelopeResult{Code: protocol.EnvelopePowRequired, Extra: []byte{uint8(pow.DefaultBits)}}
	}
	before := st.InPendingCount()
	if err := st.PutInPending(remote, inv.Note); err != nil {
		if err == chat.ErrPendingFull {
			return true, EnvelopeResult{Code: protocol.EnvelopeRetryLater}
		}
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	if before == 0 {
		d.noteChatInvites(local)
	}
	return true, EnvelopeResult{Code: protocol.EnvelopePending}
}

func (d *Daemon) onChatAccept(local, remote a2al.Address, _ string, _ []byte) (bool, EnvelopeResult) {
	st, err := d.chatStore(local)
	if err != nil {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	e, ok := st.Get(remote)
	if !ok {
		return true, EnvelopeResult{Code: protocol.EnvelopeOK}
	}
	if e.State == chat.StateBlocked {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	switch e.State {
	case chat.StateOutPending, chat.StateInPending:
		_ = st.SetMutual(remote)
		d.enqueueChatWake(local, remote, false)
	case chat.StateMutual:
		d.enqueueChatWake(local, remote, false)
	}
	return true, EnvelopeResult{Code: protocol.EnvelopeOK}
}

func (d *Daemon) onChatRefuse(local, remote a2al.Address, _ string, _ []byte) (bool, EnvelopeResult) {
	st, err := d.chatStore(local)
	if err != nil {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	e, ok := st.Get(remote)
	if ok && e.State == chat.StateBlocked {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	_ = st.Delete(remote)
	return true, EnvelopeResult{Code: protocol.EnvelopeOK}
}

func (d *Daemon) onChatDing(local, remote a2al.Address, _ string, _ []byte) (bool, EnvelopeResult) {
	if !d.chatMutual(local, remote) {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	d.enqueueChatWake(local, remote, true)
	return true, EnvelopeResult{Code: protocol.EnvelopeOK}
}

func (d *Daemon) onChatPull(local, remote a2al.Address, _ string, body []byte) (bool, EnvelopeResult) {
	if !d.chatMutual(local, remote) {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	d.enqueueChatWake(local, remote, false)
	_ = body
	return true, EnvelopeResult{Code: protocol.EnvelopeOK}
}

func (d *Daemon) onChatMsg(local, remote a2al.Address, _ string, body []byte) (bool, EnvelopeResult) {
	if !d.chatMutual(local, remote) {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	st, err := d.chatStore(local)
	if err != nil {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	m, err := chat.DecodeMsg(body)
	if err != nil {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	rec, err := chat.RecFromMsg(m, remote)
	if err != nil {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	dup, unreadEdge, err := st.AppendIn(remote, rec)
	if err != nil {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	}
	if !dup {
		d.publishChat(local, "chat.received", map[string]any{"peer": remote.String(), "seq": rec.Seq})
		if unreadEdge {
			d.publishChat(local, "chat.unread", map[string]any{"peer": remote.String(), "unread_count": st.UnreadCount(remote)})
		}
	}
	return true, EnvelopeResult{Code: protocol.EnvelopeOK}
}

func (d *Daemon) chatMutual(local, remote a2al.Address) bool {
	st, err := d.chatStore(local)
	if err != nil {
		return false
	}
	e, ok := st.Get(remote)
	if !ok {
		return false
	}
	if e.State == chat.StateBlocked {
		return false
	}
	return e.State == chat.StateMutual
}

func (d *Daemon) publishChat(aid a2al.Address, typ string, data map[string]any) {
	if d.bus == nil {
		return
	}
	d.bus.Publish(Event{Type: typ, AID: aid, Data: data, At: time.Now()})
}

var chatInviteBackoff = []time.Duration{
	15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute,
}

func (d *Daemon) noteChatInvites(aid a2al.Address) {
	if d.chats == nil {
		return
	}
	st, err := d.chats.store(aid)
	if err != nil {
		return
	}
	n := st.InPendingCount()
	if n == 0 {
		d.chats.inviteMu.Lock()
		if t := d.chats.inviteTimer[aid]; t != nil {
			t.Stop()
			delete(d.chats.inviteTimer, aid)
		}
		delete(d.chats.inviteStep, aid)
		d.chats.inviteMu.Unlock()
		return
	}
	d.publishChat(aid, "chat.invites", map[string]any{"count": n})
	d.chats.inviteMu.Lock()
	defer d.chats.inviteMu.Unlock()
	if d.chats.inviteTimer[aid] != nil {
		return
	}
	step := d.chats.inviteStep[aid]
	if step >= len(chatInviteBackoff) {
		step = len(chatInviteBackoff) - 1
	}
	delay := chatInviteBackoff[step]
	d.chats.inviteStep[aid] = step + 1
	d.chats.inviteTimer[aid] = time.AfterFunc(delay, func() {
		d.chats.inviteMu.Lock()
		delete(d.chats.inviteTimer, aid)
		d.chats.inviteMu.Unlock()
		d.noteChatInvites(aid)
	})
}
