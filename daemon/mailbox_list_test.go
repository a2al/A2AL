// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMailboxListDoesNotConsumeThenPollDoes(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	body := []byte("hello-list")
	msgID := putTestMailboxNote(t, d, aid, body)

	ctx := context.Background()
	first, err := d.execMailboxList(ctx, aid.String())
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.execMailboxList(ctx, aid.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("list first=%v second=%v, want 1 each", first, second)
	}
	idHex := hex.EncodeToString(msgID[:])
	if first[0]["message_id"] != idHex || second[0]["message_id"] != idHex {
		t.Fatalf("message_id first=%v second=%v want %s", first[0]["message_id"], second[0]["message_id"], idHex)
	}
	if mailboxPending(t, d, aid) != 1 {
		t.Fatal("list must not drop pending.mailbox")
	}

	taken, err := d.execMailboxPoll(ctx, aid.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(taken) != 1 || taken[0]["message_id"] != idHex {
		t.Fatalf("poll %v", taken)
	}
	if mailboxPending(t, d, aid) != 0 {
		t.Fatal("poll must consume")
	}
	empty, err := d.execMailboxList(ctx, aid.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("list after poll %v", empty)
	}
}

func TestMailboxListHTTPDoesNotHeartbeat(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	putTestMailboxNote(t, d, aid, []byte("web"))

	srv := httptest.NewServer(d.routes())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/agents/" + aid.String() + "/mailbox")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	msgs, _ := out["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("messages %v", out["messages"])
	}
	if d.aidHasHeartbeat(aid) {
		t.Fatal("GET /mailbox must not record liveness")
	}
	if mailboxPending(t, d, aid) != 1 {
		t.Fatal("GET must not consume")
	}
}

func TestMailboxListMCPRecordsHeartbeatAndKeepsPending(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	putTestMailboxNote(t, d, aid, []byte("mcp"))
	cs := newMCPClientSession(t, buildMCPServer(d))

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "a2al_mailbox_list",
		Arguments: map[string]any{"aid": aid.String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error %v", res.Content)
	}
	if !d.aidHasHeartbeat(aid) {
		t.Fatal("MCP list must record liveness via resolveAgentAID")
	}
	sc, _ := res.StructuredContent.(map[string]any)
	raw, _ := json.Marshal(sc["messages"])
	var msgs []map[string]any
	if err := json.Unmarshal(raw, &msgs); err != nil || len(msgs) != 1 {
		t.Fatalf("messages %v", sc["messages"])
	}
	pending, _ := sc["pending"].(map[string]any)
	per, _ := pending[aid.String()].(map[string]any)
	if got := per["mailbox"]; got != float64(1) && got != 1 {
		t.Fatalf("pending after list %v", sc["pending"])
	}
}

func TestMailboxListLeavesUndecryptableForPoll(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	goodID := putTestMailboxNote(t, d, aid, []byte("ok"))
	badRec := protocol.SignedRecord{Payload: []byte("not-mail")}
	badID := MsgIDFromRecord(badRec)
	now := time.Now().Unix()
	if !d.mboxStore.Put(badID, MailboxStoreEntry{
		RecipientAID: aid,
		Record:       badRec,
		ReceivedAt:   now,
		TTLExpires:   now + 3600,
	}) {
		t.Fatal("put bad")
	}

	ctx := context.Background()
	listed, err := d.execMailboxList(ctx, aid.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0]["message_id"] != hex.EncodeToString(goodID[:]) {
		t.Fatalf("list %v", listed)
	}
	if mailboxPending(t, d, aid) != 2 {
		t.Fatalf("pending after list %d want 2", mailboxPending(t, d, aid))
	}

	taken, err := d.execMailboxPoll(ctx, aid.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(taken) != 1 {
		t.Fatalf("poll %v", taken)
	}
	if mailboxPending(t, d, aid) != 0 {
		t.Fatal("poll must consume the undecryptable record")
	}
}

func mailboxPending(t *testing.T, d *Daemon, aid a2al.Address) int {
	t.Helper()
	got := d.pendingSnapshot(context.Background(), nil)
	if got == nil {
		return 0
	}
	per, _ := got[aid.String()].(map[string]any)
	n, _ := per["mailbox"].(int)
	return n
}

func putTestMailboxNote(t *testing.T, d *Daemon, recipient a2al.Address, body []byte) [32]byte {
	t.Helper()
	e := d.reg.Get(recipient)
	if err := d.h.RegisterDelegatedAgent(recipient, e.OpPriv, e.DelegationCBOR); err != nil {
		t.Fatal(err)
	}
	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderAID, err := crypto.AddressFromPublicKey(senderPub)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeMailboxPayload(senderAID, recipient, e.OpPriv.Public().(ed25519.PublicKey), protocol.MailboxMsgText, body)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rec, err := protocol.SignRecord(senderPriv, senderAID, protocol.RecTypeMailbox, payload, uint64(now.UnixNano()), uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	msgID := MsgIDFromRecord(rec)
	if !d.mboxStore.Put(msgID, MailboxStoreEntry{
		RecipientAID: recipient,
		Record:       rec,
		ReceivedAt:   now.Unix(),
		TTLExpires:   now.Unix() + 3600,
	}) {
		t.Fatal("put note")
	}
	return msgID
}
