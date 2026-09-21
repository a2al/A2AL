// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/chat"
	"github.com/a2al/a2al/group"
	"github.com/a2al/a2al/internal/pow"
	"github.com/a2al/a2al/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (d *Daemon) registerChatMCPTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "chat_request",
		Description: `Invite a peer AID to chat. First call lists them as waiting-to-accept. Calling again (including when already friends) resends the invite so a stale peer roster can catch up. If they already invited you, this accepts. Do not use a2al_mailbox_send for this.`,
	}, d.mcpChatRequest)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "chat_accept",
		Description: `Accept a pending chat invite from peer. If already friends, resends accept so a peer still stuck in out_pending can catch up.`,
	}, d.mcpChatAccept)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "chat_refuse",
		Description: `Refuse a pending inbound invite, or withdraw an outbound invite still waiting. The peer drops this identity and local history with them. Does not apply to friends — use chat_remove or chat_block.`,
	}, d.mcpChatRefuse)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "chat_remove",
		Description: `Remove a friend. Deletes local roster and history, and tells them so they drop this identity too. Either side may chat_request again. Not a block.`,
	}, d.mcpChatRemove)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "chat_block",
		Description: `Block a peer AID. Further chat envelopes are dropped. Does not tell them they were blocked.`,
	}, d.mcpChatBlock)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "chat_send",
		Description: `Send text or a file reference to a peer on this identity's chat list. Returns not_friends if they are not listed — call chat_request first. Pass text and/or path or object_id (not both path and object_id).`,
	}, d.mcpChatSend)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "chat_read",
		Description: `Read the local chat log with peer. after_seq is a local index cursor (0 = from the start), exclusive; page with scanned_to. Entries still status=local have not been delivered. Reading does not mark read: call chat_mark_read after you have dealt with inbound entries.`,
	}, d.mcpChatRead)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "chat_mark_read",
		Description: `Advance this identity's read cursor for peer to scanned_to (from chat_read). Omit scanned_to or pass 0 to mark everything currently in the local log. Drives chat.unread: it fires once when unread goes 0 to positive and stays silent until you bring it back to 0.`,
	}, d.mcpChatMarkRead)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "chat_contacts",
		Description: `List this identity's chat roster: friends, out_pending (waiting for them to accept), in_pending (waiting for you). invites is the in_pending count; unread is inbound messages past the read cursor.`,
	}, d.mcpChatContacts)
}

type mcpChatPeerArgs struct {
	AID  string `json:"aid"`
	Peer string `json:"peer"`
	Note string `json:"note,omitempty"`
}

type mcpChatSendArgs struct {
	AID      string `json:"aid"`
	Peer     string `json:"peer"`
	Text     string `json:"text,omitempty"`
	Path     string `json:"path,omitempty"`
	ObjectID string `json:"object_id,omitempty"`
}

type mcpChatReadArgs struct {
	AID      string `json:"aid"`
	Peer     string `json:"peer"`
	AfterSeq uint64 `json:"after_seq"`
	Limit    int    `json:"limit,omitempty"`
}

type mcpChatMarkReadArgs struct {
	AID       string `json:"aid"`
	Peer      string `json:"peer"`
	ScannedTo uint64 `json:"scanned_to"`
}

type mcpChatAIDArgs struct {
	AID string `json:"aid"`
}

func (d *Daemon) mcpChatRequest(ctx context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpChatPeerArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	out, err := d.execChatRequest(ctx, p.Arguments.AID, p.Arguments.Peer, p.Arguments.Note)
	if err != nil {
		return nil, err
	}
	return mcpOK(out), nil
}

func (d *Daemon) mcpChatAccept(ctx context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpChatPeerArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	out, err := d.execChatAccept(ctx, p.Arguments.AID, p.Arguments.Peer)
	if err != nil {
		return nil, err
	}
	return mcpOK(out), nil
}

func (d *Daemon) mcpChatRefuse(ctx context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpChatPeerArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	out, err := d.execChatRefuse(ctx, p.Arguments.AID, p.Arguments.Peer)
	if err != nil {
		return nil, err
	}
	return mcpOK(out), nil
}

func (d *Daemon) mcpChatRemove(ctx context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpChatPeerArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	out, err := d.execChatRemove(ctx, p.Arguments.AID, p.Arguments.Peer)
	if err != nil {
		return nil, err
	}
	return mcpOK(out), nil
}

func (d *Daemon) mcpChatBlock(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpChatPeerArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	out, err := d.execChatBlock(p.Arguments.AID, p.Arguments.Peer)
	if err != nil {
		return nil, err
	}
	return mcpOK(out), nil
}

func (d *Daemon) mcpChatSend(ctx context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpChatSendArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	a := p.Arguments
	out, err := d.execChatSend(ctx, a.AID, a.Peer, a.Text, a.Path, a.ObjectID)
	if err != nil {
		return nil, err
	}
	return mcpOK(out), nil
}

func (d *Daemon) mcpChatRead(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpChatReadArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	out, err := d.execChatRead(p.Arguments.AID, p.Arguments.Peer, p.Arguments.AfterSeq, p.Arguments.Limit)
	if err != nil {
		return nil, err
	}
	return mcpOK(out), nil
}

func (d *Daemon) mcpChatMarkRead(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpChatMarkReadArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	out, err := d.execChatMarkRead(p.Arguments.AID, p.Arguments.Peer, p.Arguments.ScannedTo)
	if err != nil {
		return nil, err
	}
	return mcpOK(out), nil
}

func (d *Daemon) mcpChatContacts(_ context.Context, _ *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpChatAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	out, err := d.execChatContacts(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	return mcpOK(out), nil
}

func (d *Daemon) parseChatPair(aidStr, peerStr string) (local, peer a2al.Address, err error) {
	local, err = d.resolveAgentAID(aidStr)
	if err != nil {
		return local, peer, err
	}
	peer, err = parseAID(peerStr)
	if err != nil {
		return local, peer, err
	}
	if local == peer {
		return local, peer, chat.ErrSelf
	}
	return local, peer, nil
}

func (d *Daemon) execChatRequest(ctx context.Context, aidStr, peerStr, note string) (map[string]any, error) {
	local, peer, err := d.parseChatPair(aidStr, peerStr)
	if err != nil {
		return nil, err
	}
	st, err := d.chatStore(local)
	if err != nil {
		return nil, err
	}
	prev, had := st.Get(peer)
	if had && prev.State == chat.StateBlocked {
		return nil, chat.ErrBlocked
	}
	if had && prev.State == chat.StateInPending {
		if err := st.SetMutual(peer); err != nil {
			return nil, err
		}
		res, err := d.chatDeliver(ctx, local, peer, chat.KindAccept, chat.EncodeEmpty(), true)
		if err := signalingErr(res, err); err != nil {
			return nil, err
		}
		d.enqueueChatWake(local, peer, false)
		d.noteChatInvites(local)
		return map[string]any{"state": chat.StateMutual}, nil
	}
	created := false
	if !had || prev.State == chat.StateOutPending {
		if err := st.PutOutPending(peer); err != nil {
			return nil, err
		}
		created = !had
	}
	body, err := d.chatInviteBody(ctx, local, peer, note)
	if err != nil {
		if created {
			_ = st.Delete(peer)
		}
		return nil, err
	}
	res, err := d.chatDeliver(ctx, local, peer, chat.KindInvite, body, true)
	if err := signalingErr(res, err); err != nil {
		if created {
			_ = st.Delete(peer)
		}
		return nil, err
	}
	e, _ := st.Get(peer)
	return map[string]any{"state": e.State}, nil
}

func (d *Daemon) chatInviteBody(ctx context.Context, local, peer a2al.Address, note string) ([]byte, error) {
	ts := time.Now().Unix()
	nonce, err := pow.Solve(ctx, chat.PurposeInvite, local, peer, ts, pow.DefaultBits)
	if err != nil {
		return nil, err
	}
	return chat.EncodeInvite(chat.Invite{TS: ts, Nonce: chat.NonceB64(nonce), Bits: pow.DefaultBits, Note: note})
}

func (d *Daemon) execChatAccept(ctx context.Context, aidStr, peerStr string) (map[string]any, error) {
	local, peer, err := d.parseChatPair(aidStr, peerStr)
	if err != nil {
		return nil, err
	}
	st, err := d.chatStore(local)
	if err != nil {
		return nil, err
	}
	e, ok := st.Get(peer)
	if !ok {
		return nil, chat.ErrNotPending
	}
	switch e.State {
	case chat.StateMutual:
		// resend accept if the first signal did not land
	case chat.StateInPending:
		if err := st.SetMutual(peer); err != nil {
			return nil, err
		}
	default:
		return nil, chat.ErrNotPending
	}
	res, err := d.chatDeliver(ctx, local, peer, chat.KindAccept, chat.EncodeEmpty(), true)
	if err := signalingErr(res, err); err != nil {
		return nil, err
	}
	d.enqueueChatWake(local, peer, false)
	d.noteChatInvites(local)
	return map[string]any{"state": chat.StateMutual}, nil
}

func (d *Daemon) execChatRefuse(ctx context.Context, aidStr, peerStr string) (map[string]any, error) {
	local, peer, err := d.parseChatPair(aidStr, peerStr)
	if err != nil {
		return nil, err
	}
	st, err := d.chatStore(local)
	if err != nil {
		return nil, err
	}
	e, ok := st.Get(peer)
	if !ok || (e.State != chat.StateInPending && e.State != chat.StateOutPending) {
		return nil, chat.ErrNotPending
	}
	if err := d.chatDropPeer(ctx, st, local, peer); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (d *Daemon) execChatRemove(ctx context.Context, aidStr, peerStr string) (map[string]any, error) {
	local, peer, err := d.parseChatPair(aidStr, peerStr)
	if err != nil {
		return nil, err
	}
	st, err := d.chatStore(local)
	if err != nil {
		return nil, err
	}
	e, ok := st.Get(peer)
	if !ok {
		return nil, chat.ErrNotFriends
	}
	switch e.State {
	case chat.StateMutual:
	case chat.StateBlocked:
		return nil, chat.ErrBlocked
	default:
		return nil, chat.ErrNotPending
	}
	if err := d.chatDropPeer(ctx, st, local, peer); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (d *Daemon) chatDropPeer(ctx context.Context, st *chat.Store, local, peer a2al.Address) error {
	if err := st.Delete(peer); err != nil {
		return err
	}
	res, err := d.chatDeliver(ctx, local, peer, chat.KindRefuse, chat.EncodeEmpty(), true)
	if err := signalingErr(res, err); err != nil {
		d.noteChatInvites(local)
		return err
	}
	d.noteChatInvites(local)
	return nil
}

func (d *Daemon) execChatBlock(aidStr, peerStr string) (map[string]any, error) {
	local, peer, err := d.parseChatPair(aidStr, peerStr)
	if err != nil {
		return nil, err
	}
	st, err := d.chatStore(local)
	if err != nil {
		return nil, err
	}
	if err := st.Block(peer); err != nil {
		return nil, err
	}
	d.noteChatInvites(local)
	return map[string]any{"state": chat.StateBlocked}, nil
}

func (d *Daemon) execChatSend(ctx context.Context, aidStr, peerStr, text, path, objectID string) (map[string]any, error) {
	local, peer, err := d.parseChatPair(aidStr, peerStr)
	if err != nil {
		return nil, err
	}
	text = strings.TrimSpace(text)
	path = strings.TrimSpace(path)
	objectID = strings.TrimSpace(objectID)
	if path != "" && objectID != "" {
		return nil, errors.New("chat_send: pass path or object_id, not both")
	}
	if text == "" && path == "" && objectID == "" {
		return nil, errors.New("chat_send: pass text and/or a file (path or object_id)")
	}
	st, err := d.chatStore(local)
	if err != nil {
		return nil, err
	}
	if !st.CanSend(peer) {
		return nil, chat.ErrNotFriends
	}
	rec := chat.Rec{Kind: chat.KindText, Body: text, TS: time.Now().UnixMilli()}
	if path != "" {
		id, size, name, err := d.registerLocalObject(local, path)
		if err != nil {
			return nil, err
		}
		rec.Kind = chat.KindFile
		rec.Ref = id
		rec.Name = name
		rec.Size = size
	} else if objectID != "" {
		id, err := parseHex32(objectID)
		if err != nil {
			return nil, err
		}
		p, size, ok := d.lookupLocalObject(local, id)
		if !ok {
			return nil, errors.New("chat_send: object_id is not mapped for this identity")
		}
		rec.Kind = chat.KindFile
		rec.Ref = id
		rec.Name = filepath.Base(p)
		rec.Size = size
	}
	seq, err := st.AppendOut(peer, rec)
	if err != nil {
		return nil, err
	}
	status := chat.StatusLocal
	e, _ := st.Get(peer)
	if e.State == chat.StateMutual {
		rec.Seq = seq
		body, err := chat.EncodeMsg(chat.MsgFromRec(rec))
		if err != nil {
			return nil, err
		}
		res, err := d.chatDeliver(ctx, local, peer, chat.KindMsg, body, false)
		if err == nil && res.Code == protocol.EnvelopeOK {
			_ = st.MarkSent(peer, seq)
			status = chat.StatusSent
		} else {
			d.chatDing(ctx, local, peer)
		}
	}
	return map[string]any{"seq": seq, "status": status}, nil
}

func (d *Daemon) execChatRead(aidStr, peerStr string, after uint64, limit int) (map[string]any, error) {
	local, peer, err := d.parseChatPair(aidStr, peerStr)
	if err != nil {
		return nil, err
	}
	st, err := d.chatStore(local)
	if err != nil {
		return nil, err
	}
	entries, scanned, more := st.Read(peer, after, limit)
	items := make([]map[string]any, 0, len(entries))
	for _, r := range entries {
		items = append(items, recToMap(local, peer, r))
	}
	return map[string]any{
		"entries":      items,
		"scanned_to":   scanned,
		"has_more":     more,
		"read_cursor":  st.ReadCursor(peer),
		"unread_count": st.UnreadCount(peer),
	}, nil
}

func (d *Daemon) execChatMarkRead(aidStr, peerStr string, scannedTo uint64) (map[string]any, error) {
	local, peer, err := d.parseChatPair(aidStr, peerStr)
	if err != nil {
		return nil, err
	}
	st, err := d.chatStore(local)
	if err != nil {
		return nil, err
	}
	if err := st.MarkRead(peer, scannedTo); err != nil {
		return nil, err
	}
	return map[string]any{"read_cursor": st.ReadCursor(peer), "unread_count": st.UnreadCount(peer)}, nil
}

func (d *Daemon) execChatContacts(aidStr string) (map[string]any, error) {
	local, err := d.resolveAgentAID(aidStr)
	if err != nil {
		return nil, err
	}
	st, err := d.chatStore(local)
	if err != nil {
		return nil, err
	}
	var friends, outP, inP []map[string]any
	for _, e := range st.Contacts() {
		item := map[string]any{"peer": e.Peer.String(), "since": e.Since}
		switch e.State {
		case chat.StateMutual:
			item["unread_count"] = st.UnreadCount(e.Peer)
			friends = append(friends, item)
		case chat.StateOutPending:
			outP = append(outP, item)
		case chat.StateInPending:
			item["note"] = e.Note
			inP = append(inP, item)
		}
	}
	if friends == nil {
		friends = []map[string]any{}
	}
	if outP == nil {
		outP = []map[string]any{}
	}
	if inP == nil {
		inP = []map[string]any{}
	}
	return map[string]any{
		"friends":     friends,
		"out_pending": outP,
		"in_pending":  inP,
		"invites":     st.InPendingCount(),
		"unread":      st.TotalUnread(),
	}, nil
}

func recToMap(local, peer a2al.Address, r chat.Rec) map[string]any {
	author := local
	if r.Dir == chat.DirIn {
		author = peer
		if r.Author != (a2al.Address{}) {
			author = r.Author
		}
	}
	m := map[string]any{
		"idx":    r.Idx,
		"seq":    r.Seq,
		"dir":    r.Dir,
		"ts":     r.TS,
		"kind":   r.Kind,
		"body":   r.Body,
		"status": r.Status,
		"author": author.String(),
	}
	if r.Ref != ([32]byte{}) {
		m["ref"] = hex.EncodeToString(r.Ref[:])
		m["name"] = r.Name
		m["size"] = r.Size
		holder := local
		if r.Dir == chat.DirIn {
			holder = peer
		}
		m["url"] = group.CASURL(holder, r.Ref)
	}
	return m
}
