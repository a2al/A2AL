// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/chat"
	"github.com/a2al/a2al/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/quic-go/quic-go"
)

func TestChat_sameDaemonInviteSend(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)

	out, err := d.execChatRequest(context.Background(), a.String(), b.String(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if out["state"] != chat.StateOutPending {
		t.Fatalf("%v", out)
	}
	cst, err := d.execChatContacts(b.String())
	if err != nil {
		t.Fatal(err)
	}
	in := cst["in_pending"].([]map[string]any)
	if len(in) != 1 || in[0]["note"] != "hi" {
		t.Fatalf("%v", cst)
	}

	if _, err := d.execChatAccept(context.Background(), b.String(), a.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatSend(context.Background(), a.String(), b.String(), "hello", "", "", ""); err != nil {
		t.Fatal(err)
	}
	got, err := d.execChatRead(b.String(), a.String(), 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	entries := got["entries"].([]map[string]any)
	if len(entries) != 1 || entries[0]["body"] != "hello" || entries[0]["status"] != chat.StatusIn {
		t.Fatalf("%v", entries)
	}
	sent, err := d.execChatRead(a.String(), b.String(), 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	se := sent["entries"].([]map[string]any)
	if len(se) != 1 || se[0]["status"] != chat.StatusSent {
		t.Fatalf("%v", se)
	}
}

func TestChat_sendStaysLocalWhenAcquireFails(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	peer := newTestAddr(t)
	st, err := d.chatStore(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetMutual(peer); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := d.execChatSend(ctx, a.String(), peer.String(), "hello", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if out["status"] != chat.StatusLocal {
		t.Fatalf("%v", out)
	}
	got, err := d.execChatRead(a.String(), peer.String(), 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	entries := got["entries"].([]map[string]any)
	if len(entries) != 1 || entries[0]["status"] != chat.StatusLocal {
		t.Fatalf("%v", entries)
	}
}

func TestChat_notFriendsAndSelf(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatSend(context.Background(), a.String(), b.String(), "x", "", "", ""); !errors.Is(err, chat.ErrNotFriends) {
		t.Fatalf("err=%v", err)
	}
	if _, err := d.execChatRequest(context.Background(), a.String(), a.String(), ""); !errors.Is(err, chat.ErrSelf) {
		t.Fatalf("err=%v", err)
	}
}

func TestChat_mutualRequest(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatRequest(context.Background(), b.String(), a.String(), ""); err != nil {
		t.Fatal(err)
	}
	ca, _ := d.chatStore(a)
	e, ok := ca.Get(b)
	if !ok || e.State != chat.StateMutual {
		t.Fatalf("a %+v", e)
	}
	cb, _ := d.chatStore(b)
	e, ok = cb.Get(a)
	if !ok || e.State != chat.StateMutual {
		t.Fatalf("b %+v", e)
	}
}

func TestChat_blockKeepsRow(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), b.String(), a.String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatAccept(context.Background(), a.String(), b.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatBlock(a.String(), b.String()); err != nil {
		t.Fatal(err)
	}
	st, _ := d.chatStore(a)
	e, ok := st.Get(b)
	if !ok || e.State != chat.StateBlocked {
		t.Fatal("blocked row")
	}
	if _, err := d.execChatSend(context.Background(), b.String(), a.String(), "no", "", "", ""); err != nil {
		t.Fatal(err)
	}
	got, _ := d.execChatRead(a.String(), b.String(), 0, 10)
	if n := len(got["entries"].([]map[string]any)); n != 0 {
		t.Fatalf("blocked must drop msg, n=%d", n)
	}
}

func TestChat_inspectDoesNotHeartbeat(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/agents/" + a.String() + "/chat/contacts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if d.aidHasHeartbeat(a) {
		t.Fatal("inspect GET must not record liveness")
	}
}

func TestChat_mcpTools(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	cs := newMCPClientSession(t, d.mcpInstance())
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "chat_request",
		Arguments: map[string]any{"aid": a.String(), "peer": b.String(), "note": "n"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !d.aidHasHeartbeat(a) {
		t.Fatal("chat_request must record liveness")
	}
}

func TestChat_mailboxClaimNoDoorbell(t *testing.T) {
	d := newTestDaemon(t)
	b := newTestAgent(t, d)
	e := d.reg.Get(b)
	if err := d.h.RegisterDelegatedAgent(b, e.OpPriv, e.DelegationCBOR); err != nil {
		t.Fatal(err)
	}
	ch, cancel := d.bus.Subscribe(Filter{Types: []string{"mailbox.received"}})
	defer cancel()
	a := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), "z"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
		t.Fatal("claimed invite must not doorbell mailbox.received")
	default:
	}
}

func TestChat_sendPendingStaysLocal(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	out, err := d.execChatSend(context.Background(), a.String(), b.String(), "soon", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if out["status"] != chat.StatusLocal {
		t.Fatalf("%v", out)
	}
	got, _ := d.execChatRead(b.String(), a.String(), 0, 10)
	if n := len(got["entries"].([]map[string]any)); n != 0 {
		t.Fatalf("pending must not deliver, n=%d", n)
	}
}

func TestChat_httpSendJSON(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatAccept(context.Background(), b.String(), a.String()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/agents/"+a.String()+"/chat/send", "application/json", strings.NewReader(`{"peer":"`+b.String()+`","text":"web"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != chat.StatusSent {
		t.Fatalf("%v", body)
	}
}

func TestChat_requestDeniedRollsBack(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatBlock(b.String(), a.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); !errors.Is(err, chat.ErrSignaling) {
		t.Fatalf("err=%v", err)
	}
	st, err := d.chatStore(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Get(b); ok {
		t.Fatal("failed invite must not leave out_pending")
	}
}

func TestChat_acceptResendAfterDenied(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	failAccept := true
	d.chatDeliverHook = func(ctx context.Context, local, remote a2al.Address, kind string, body []byte, persist bool) (EnvelopeResult, error) {
		if kind == chat.KindAccept && failAccept {
			failAccept = false
			return EnvelopeResult{Code: protocol.EnvelopeDenied}, nil
		}
		return d.chatDeliverReal(ctx, local, remote, kind, body, persist)
	}
	if _, err := d.execChatAccept(context.Background(), b.String(), a.String()); !errors.Is(err, chat.ErrSignaling) {
		t.Fatalf("err=%v", err)
	}
	bst, _ := d.chatStore(b)
	e, ok := bst.Get(a)
	if !ok || e.State != chat.StateMutual {
		t.Fatal("accept must stay mutual locally")
	}
	ast, _ := d.chatStore(a)
	e, ok = ast.Get(b)
	if !ok || e.State != chat.StateOutPending {
		t.Fatal("inviter still out_pending until accept lands")
	}
	if _, err := d.execChatAccept(context.Background(), b.String(), a.String()); err != nil {
		t.Fatal(err)
	}
	e, ok = ast.Get(b)
	if !ok || e.State != chat.StateMutual {
		t.Fatalf("resend accept: %+v", e)
	}
}

func TestChat_unreadMarkRead(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	ch, cancel := d.bus.Subscribe(Filter{AID: b, Types: []string{"chat.unread"}})
	defer cancel()
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatAccept(context.Background(), b.String(), a.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatSend(context.Background(), a.String(), b.String(), "ping", "", "", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ch:
		if ev.Type != "chat.unread" {
			t.Fatalf("%+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("missing chat.unread")
	}
	got, err := d.execChatRead(b.String(), a.String(), 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	if got["unread_count"] != 1 {
		t.Fatalf("%v", got)
	}
	if _, err := d.execChatMarkRead(b.String(), a.String(), 0); err != nil {
		t.Fatal(err)
	}
	got, _ = d.execChatRead(b.String(), a.String(), 0, 20)
	if got["unread_count"] != 0 {
		t.Fatalf("after mark %v", got)
	}
	if _, err := d.execChatSend(context.Background(), a.String(), b.String(), "pong", "", "", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("second chat.unread")
	}
}

func TestChat_pendingHitchInvitesAndUnread(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	c := newTestAgent(t, d)

	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), "hi"); err != nil {
		t.Fatal(err)
	}
	per, _ := d.pendingFor(b)[b.String()].(map[string]any)
	if per["chat_invites"] != 1 {
		t.Fatalf("invites %v", d.pendingFor(b))
	}
	if _, has := per["mailbox"]; has {
		t.Fatalf("claimed invite must not count as mailbox: %v", per)
	}
	if got := d.pendingFor(c); got != nil {
		t.Fatalf("unused aid %v", got)
	}

	cs := newMCPClientSession(t, d.mcpInstance())
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "a2al_agents_list",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	sc := res.StructuredContent.(map[string]any)
	hitch := sc["pending"].(map[string]any)[b.String()].(map[string]any)
	if got := hitch["chat_invites"]; got != float64(1) && got != 1 {
		t.Fatalf("mcp hitch %v", hitch)
	}

	if _, err := d.execChatAccept(context.Background(), b.String(), a.String()); err != nil {
		t.Fatal(err)
	}
	if got := d.pendingFor(b); got != nil {
		t.Fatalf("after accept %v", got)
	}
	if _, err := d.execChatSend(context.Background(), a.String(), b.String(), "hello", "", "", ""); err != nil {
		t.Fatal(err)
	}
	per, _ = d.pendingFor(b)[b.String()].(map[string]any)
	if per["chat_unread"] != 1 {
		t.Fatalf("unread %v", d.pendingFor(b))
	}
	if _, err := d.execChatMarkRead(b.String(), a.String(), 0); err != nil {
		t.Fatal(err)
	}
	if got := d.pendingFor(b); got != nil {
		t.Fatalf("after mark_read %v", got)
	}
}

func TestChat_initChatIdempotent(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	st1, err := d.chatStore(a)
	if err != nil {
		t.Fatal(err)
	}
	mgr := d.chats
	d.initChat()
	if d.chats != mgr {
		t.Fatal("second initChat replaced manager")
	}
	st2, err := d.chatStore(a)
	if err != nil {
		t.Fatal(err)
	}
	if st1 != st2 {
		t.Fatal("open store lost")
	}
}

func waitChatState(t *testing.T, d *Daemon, local, peer a2al.Address, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		st, err := d.chatStore(local)
		if err == nil {
			if e, ok := st.Get(peer); ok && e.State == want {
				return
			}
		}
		if time.Now().After(deadline) {
			st, _ := d.chatStore(local)
			e, _ := st.Get(peer)
			t.Fatalf("state=%q want %s", e.State, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestChat_requestResendHealsPeerOutPending(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatAccept(context.Background(), b.String(), a.String()); err != nil {
		t.Fatal(err)
	}
	stb, err := d.chatStore(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := stb.Delete(a); err != nil {
		t.Fatal(err)
	}
	if err := stb.PutOutPending(a); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	waitChatState(t, d, b, a, chat.StateMutual)
	waitChatState(t, d, a, b, chat.StateMutual)
}

func TestChat_peerRequestHealsWhenWeAreMutual(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatAccept(context.Background(), b.String(), a.String()); err != nil {
		t.Fatal(err)
	}
	stb, _ := d.chatStore(b)
	if err := stb.Delete(a); err != nil {
		t.Fatal(err)
	}
	if err := stb.PutOutPending(a); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatRequest(context.Background(), b.String(), a.String(), ""); err != nil {
		t.Fatal(err)
	}
	waitChatState(t, d, b, a, chat.StateMutual)
	waitChatState(t, d, a, b, chat.StateMutual)
}

func TestChat_acceptPromotesInPending(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	consumed, res := d.consumeEnvelope(b, a, chat.KindAccept, chat.EncodeEmpty())
	if !consumed || res.Code != protocol.EnvelopeOK {
		t.Fatalf("consumed=%v res=%+v", consumed, res)
	}
	waitChatState(t, d, b, a, chat.StateMutual)
}

func TestChat_refuseWithdrawsOutbound(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatRefuse(context.Background(), a.String(), b.String()); err != nil {
		t.Fatal(err)
	}
	sta, _ := d.chatStore(a)
	if _, ok := sta.Get(b); ok {
		t.Fatal("inviter still has row")
	}
	stb, _ := d.chatStore(b)
	if _, ok := stb.Get(a); ok {
		t.Fatal("invitee still has row")
	}
}

func TestChat_removeFriend(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatAccept(context.Background(), b.String(), a.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatSend(context.Background(), a.String(), b.String(), "hi", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatRemove(context.Background(), a.String(), b.String()); err != nil {
		t.Fatal(err)
	}
	sta, _ := d.chatStore(a)
	if _, ok := sta.Get(b); ok {
		t.Fatal("remover still has row")
	}
	stb, _ := d.chatStore(b)
	if _, ok := stb.Get(a); ok {
		t.Fatal("peer still has row")
	}
	if _, err := d.execChatSend(context.Background(), a.String(), b.String(), "x", "", "", ""); !errors.Is(err, chat.ErrNotFriends) {
		t.Fatalf("err=%v", err)
	}
	out, err := d.execChatRequest(context.Background(), a.String(), b.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	if out["state"] != chat.StateOutPending {
		t.Fatalf("%v", out)
	}
	cst, err := d.execChatContacts(b.String())
	if err != nil {
		t.Fatal(err)
	}
	in := cst["in_pending"].([]map[string]any)
	if len(in) != 1 {
		t.Fatalf("%v", cst)
	}
}

func TestChat_removeNotFriend(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRemove(context.Background(), a.String(), b.String()); !errors.Is(err, chat.ErrNotFriends) {
		t.Fatalf("err=%v", err)
	}
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatRemove(context.Background(), a.String(), b.String()); !errors.Is(err, chat.ErrNotPending) {
		t.Fatalf("err=%v", err)
	}
}

func TestChat_invitesFrameListsPeers(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	ch, cancel := d.bus.Subscribe(Filter{AID: b, Types: []string{"chat.invites"}})
	defer cancel()
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), "hi"); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ch:
		data, _ := ev.Data.(map[string]any)
		if data["count"] != 1 && data["count"] != float64(1) {
			t.Fatalf("count %v", data)
		}
		peers, _ := data["peers"].([]string)
		if len(peers) != 1 || peers[0] != a.String() {
			t.Fatalf("peers %v want %s", data["peers"], a)
		}
	case <-time.After(time.Second):
		t.Fatal("no chat.invites")
	}
}

func waitChatStatus(t *testing.T, d *Daemon, local, peer a2al.Address, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, err := d.execChatRead(local.String(), peer.String(), 0, 20)
		if err != nil {
			t.Fatal(err)
		}
		entries := got["entries"].([]map[string]any)
		if len(entries) == 1 && entries[0]["status"] == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("status still %v want %s", entries, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestChat_pathLiveFlushesUnsent(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	peer := newTestAddr(t)
	st, err := d.chatStore(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetMutual(peer); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := d.execChatSend(ctx, a.String(), peer.String(), "hello", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if out["status"] != chat.StatusLocal {
		t.Fatalf("%v", out)
	}

	var dials int
	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		dials++
		return newStubConn(), false, nil
	}, d.log)
	d.connPool = p
	p.setOnLive(d.notePathLive)
	d.chatDeliverHook = func(ctx context.Context, local, remote a2al.Address, kind string, body []byte, persist bool) (EnvelopeResult, error) {
		if kind == chat.KindMsg && !persist {
			return EnvelopeResult{Code: protocol.EnvelopeOK}, nil
		}
		return EnvelopeResult{}, errEnvelopeUnavailable
	}
	if _, _, err := p.acquire(ctx, a, peer, nil, false, true); err != nil {
		t.Fatal(err)
	}
	waitChatStatus(t, d, a, peer, chat.StatusSent)
	if dials != 1 {
		t.Fatalf("settler must not acquire dials=%d", dials)
	}
}

func TestChat_pathLiveSkipsWithoutHeartbeat(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	peer := newTestAddr(t)
	st, err := d.chatStore(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetMutual(peer); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := d.execChatSend(ctx, a.String(), peer.String(), "hello", "", "", ""); err != nil {
		t.Fatal(err)
	}
	d.heartbeatMu.Lock()
	delete(d.heartbeatAt, a)
	d.heartbeatMu.Unlock()

	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		return newStubConn(), false, nil
	}, d.log)
	d.connPool = p
	p.setOnLive(d.notePathLive)
	sent := make(chan struct{}, 1)
	d.chatDeliverHook = func(ctx context.Context, local, remote a2al.Address, kind string, body []byte, persist bool) (EnvelopeResult, error) {
		select {
		case sent <- struct{}{}:
		default:
		}
		return EnvelopeResult{Code: protocol.EnvelopeOK}, nil
	}
	if _, _, err := p.acquire(ctx, a, peer, nil, false, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sent:
		t.Fatal("settler must not send without heartbeat")
	case <-time.After(80 * time.Millisecond):
	}
	got, err := d.execChatRead(a.String(), peer.String(), 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	entries := got["entries"].([]map[string]any)
	if len(entries) != 1 || entries[0]["status"] != chat.StatusLocal {
		t.Fatalf("%v", entries)
	}
}

func TestChatAttachName(t *testing.T) {
	if got := chatAttachName("dir/notes.txt", "x.bin"); got != "notes.txt" {
		t.Fatalf("%q", got)
	}
	if got := chatAttachName("  ", "x.bin"); got != "x.bin" {
		t.Fatalf("%q", got)
	}
	if got := chatAttachName("..", "x.bin"); got != "x.bin" {
		t.Fatalf("%q", got)
	}
}

func TestChat_sendObjectIDUsesDisplayName(t *testing.T) {
	d := newTestDaemon(t)
	d.cfg.FilesRoot = t.TempDir()
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	if _, err := d.execChatRequest(context.Background(), a.String(), b.String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.execChatAccept(context.Background(), b.String(), a.String()); err != nil {
		t.Fatal(err)
	}

	id, _, ingestName, err := d.ingestCASObject(a, strings.NewReader("hello-file"), "notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	if ingestName != "notes.txt" {
		t.Fatalf("ingest name %q", ingestName)
	}
	oid := hex.EncodeToString(id[:])
	if _, err := d.execChatSend(context.Background(), a.String(), b.String(), "", "", oid, "notes.txt"); err != nil {
		t.Fatal(err)
	}
	got, err := d.execChatRead(b.String(), a.String(), 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	entries := got["entries"].([]map[string]any)
	if len(entries) != 1 || entries[0]["kind"] != chat.KindFile || entries[0]["name"] != "notes.txt" {
		t.Fatalf("%v", entries)
	}
	if g, _ := entries[0]["grant"].(string); g == "" {
		t.Fatalf("grant missing %v", entries[0])
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, _, ok := d.lookupLocalObject(b, id); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inbound file was not prefetched onto the receiver")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var rec casRec
	for {
		var ok bool
		rec, ok = d.casRec(a, id)
		if ok && fetchedHas(rec.Served, b.String()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sender Served %v", rec.Served)
		}
		time.Sleep(10 * time.Millisecond)
	}
	sent, err := d.execChatRead(a.String(), b.String(), 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	se := sent["entries"].([]map[string]any)
	if !fetchedHas(se[0]["fetched"], b.String()) {
		t.Fatalf("sender fetched %v", se[0]["fetched"])
	}

	id2, _, _, err := d.ingestCASObject(a, strings.NewReader("other"), "")
	if err != nil {
		t.Fatal(err)
	}
	oid2 := hex.EncodeToString(id2[:])
	if _, err := d.execChatSend(context.Background(), a.String(), b.String(), "", "", oid2, ""); err != nil {
		t.Fatal(err)
	}
	got, err = d.execChatRead(b.String(), a.String(), 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	entries = got["entries"].([]map[string]any)
	if len(entries) != 2 || entries[1]["name"] != oid2+".bin" {
		t.Fatalf("%v", entries)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		if _, _, ok := d.lookupLocalObject(b, id2); ok {
			rec, _ := d.casRec(a, id2)
			if fetchedHas(rec.Served, b.String()) {
				break
			}
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func fetchedHas(v any, aid string) bool {
	switch xs := v.(type) {
	case []string:
		for _, s := range xs {
			if s == aid {
				return true
			}
		}
	case []any:
		for _, x := range xs {
			if s, ok := x.(string); ok && s == aid {
				return true
			}
		}
	}
	return false
}
