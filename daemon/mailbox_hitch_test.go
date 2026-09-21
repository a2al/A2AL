// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"crypto/ed25519"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/protocol"
)

func TestReceivePoolNeedsRefresh(t *testing.T) {
	store := newMailboxStore("", slog.New(slog.NewTextHandler(io.Discard, nil)))
	var known [32]byte
	known[0] = 9
	store.Put(known, MailboxStoreEntry{TTLExpires: 1 << 40})

	var missing [32]byte
	missing[0] = 8

	if receivePoolNeedsRefresh(store, nil) {
		t.Fatal("empty pool")
	}
	if receivePoolNeedsRefresh(store, []protocol.ReceivePoolHint{{
		RecType: protocol.RecTypeMailbox, Count: 3, IDs: [][]byte{known[:]},
	}}) {
		t.Fatal("truncated IDs that are all Has must not refresh")
	}
	if !receivePoolNeedsRefresh(store, []protocol.ReceivePoolHint{{
		RecType: protocol.RecTypeMailbox, Count: 1, IDs: [][]byte{missing[:]},
	}}) {
		t.Fatal("missing ID must refresh")
	}
	if !receivePoolNeedsRefresh(store, []protocol.ReceivePoolHint{{
		RecType: protocol.RecTypeMailbox, Count: 2,
	}}) {
		t.Fatal("count without IDs must refresh")
	}
	if receivePoolNeedsRefresh(store, []protocol.ReceivePoolHint{{
		RecType: protocol.RecTypeMailbox, Count: 2, IDs: [][]byte{{1, 2, 3}},
	}}) {
		t.Fatal("malformed ID must be dropped, not treated as a miss")
	}
	if receivePoolNeedsRefresh(store, []protocol.ReceivePoolHint{{
		RecType: protocol.RecTypeMailbox, Count: 2, IDs: [][]byte{missing[:], {1, 2}},
	}}) {
		t.Fatal("one malformed ID must invalidate the whole slice")
	}
	if receivePoolNeedsRefresh(store, []protocol.ReceivePoolHint{{
		RecType: protocol.RecTypeEndpoint, Count: 5,
	}}) {
		t.Fatal("publish-pool type must be ignored")
	}
}

// Coincidence ingest hands the record to the same handler as DHT_PUSH, so this
// covers both: an inbound mailbox record for a locally registered agent must end
// up unconsumed in mailbox_store, and a replay of it must not.
func TestHandleMailboxPush_landsInStore(t *testing.T) {
	d := newTestDaemon(t)
	recipientAID, recipientPub := newTestMailboxAgent(t, d)

	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderAID, err := crypto.AddressFromPublicKey(senderPub)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeMailboxPayload(senderAID, recipientAID, recipientPub, protocol.MailboxMsgText, []byte("ding"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rec, err := protocol.SignRecord(senderPriv, senderAID, protocol.RecTypeMailbox, payload, uint64(now.UnixNano()), uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}

	key := a2al.NodeIDFromAddress(recipientAID)
	if !d.handleMailboxPush(key, rec) {
		t.Fatal("first delivery must be new")
	}
	if !d.mboxStore.Has(MsgIDFromRecord(rec)) {
		t.Fatal("record not in mailbox_store")
	}
	if got, _ := d.mboxStore.GetUnconsumed(recipientAID); len(got) != 1 {
		t.Fatalf("unconsumed %d want 1", len(got))
	}
	if d.handleMailboxPush(key, rec) {
		t.Fatal("replay must not be reported as new")
	}
}

// The node identity can neither send nor poll mail, so it must not be treated as
// a mailbox home: an inbound record keyed to it is dropped rather than stored.
func TestHandleMailboxPush_nodeIdentityIsNotAMailboxHome(t *testing.T) {
	d := newTestDaemon(t)
	if _, ok := d.findAgentByNodeID(a2al.NodeIDFromAddress(d.nodeAddr)); ok {
		t.Fatal("node identity must not resolve as a mailbox recipient")
	}
	if d.isLocalAID(d.nodeAddr) {
		t.Fatal("node identity must not count as a local mailbox AID")
	}
}

func TestSyncLocalReceiveKeys_registeredAgentsOnly(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	keys := d.localReceiveKeysLocked()
	if len(keys) != 1 || keys[0] != a2al.NodeIDFromAddress(aid) {
		t.Fatalf("keys %v want only the registered agent", keys)
	}
	// allAgentKeys still includes the node identity; the receive-key set must not.
	if len(d.allAgentKeys()) != 2 {
		t.Fatal("allAgentKeys should still cover node identity + agent")
	}
}

// newTestMailboxAgent registers a fresh agent on d and returns its AID together
// with the master pubkey, which mailbox payload encryption needs.
func newTestMailboxAgent(t *testing.T, d *Daemon) (a2al.Address, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := crypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, opPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.reg.Put(&registry.Entry{AID: aid, ServiceTCP: "127.0.0.1:9", OpPriv: opPriv}); err != nil {
		t.Fatal(err)
	}
	return aid, pub
}
