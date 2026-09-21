// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

func TestReceivePoolHints_ttlOnlyNoVerify(t *testing.T) {
	s := NewStore(nil, 0)
	id := newRecIdentity(t)
	now := time.Now().Truncate(time.Second)
	mail := mustMailbox(t, id, now, []byte("note-1"))
	if err := s.Put(id.key, mail, now); err != nil {
		t.Fatal(err)
	}
	hints := s.ReceivePoolHints(id.key, now, 8)
	if len(hints) != 1 || hints[0].Count != 1 || len(hints[0].IDs) != 1 {
		t.Fatalf("got %+v", hints)
	}
	want := protocol.RecordID(mail)
	if string(hints[0].IDs[0]) != string(want[:]) {
		t.Fatal("RecordID mismatch")
	}
}

func TestReceivePoolHints_capsIDsAndKeepsCount(t *testing.T) {
	s := NewStore(nil, 0)
	id := newRecIdentity(t)
	now := time.Now().Truncate(time.Second)
	// Spread across senders: a single pubkey may only leave maxMailboxPerPubkey.
	total := 0
	for sender := 0; sender < 3; sender++ {
		from := newRecIdentity(t)
		for i := 0; i < maxMailboxPerPubkey; i++ {
			mail := mustMailboxKeys(t, from.priv, from.addr, id.priv, id.addr,
				now.Add(time.Duration(i)*time.Second), []byte{byte(sender), byte(i)})
			if err := s.Put(id.key, mail, now); err != nil {
				t.Fatal(err)
			}
			total++
		}
	}
	if total <= protocol.MaxReceivePoolIDs {
		t.Fatalf("fixture must exceed the ID cap, got %d", total)
	}
	hints := s.ReceivePoolHints(id.key, now, protocol.MaxReceivePoolIDs)
	if len(hints) != 1 {
		t.Fatalf("hints %+v", hints)
	}
	if int(hints[0].Count) != total {
		t.Fatalf("count %d want %d", hints[0].Count, total)
	}
	if len(hints[0].IDs) != protocol.MaxReceivePoolIDs {
		t.Fatalf("ids %d want %d", len(hints[0].IDs), protocol.MaxReceivePoolIDs)
	}
}

// Even a pool wide enough to overflow a UDP response must leave STORE_RESP
// sendable: detail is shed, and the reply never exceeds maxResponsePayload.
func TestTrimStoreRespPool_fitsResponseBudget(t *testing.T) {
	resp := &protocol.BodyStoreResp{Stored: true}
	for slice := 0; slice < 16; slice++ {
		h := protocol.ReceivePoolHint{RecType: protocol.RecTypeMailbox, Count: 99}
		for i := 0; i < protocol.MaxReceivePoolIDs; i++ {
			h.IDs = append(h.IDs, make([]byte, 32))
		}
		resp.Pool = append(resp.Pool, h)
	}
	if sz, err := protocol.StoreRespWireSize(resp); err != nil || sz <= maxResponsePayload {
		t.Fatalf("fixture must overflow: size %d err %v", sz, err)
	}
	trimStoreRespPool(resp)
	sz, err := protocol.StoreRespWireSize(resp)
	if err != nil {
		t.Fatal(err)
	}
	if sz > maxResponsePayload {
		t.Fatalf("trimmed size %d over budget %d", sz, maxResponsePayload)
	}
}

func TestStoreAt_publisherGetsReceivePoolHint(t *testing.T) {
	netw := transport.NewMemNetwork()
	trN, _ := netw.NewTransport("neigh")
	trB, _ := netw.NewTransport("bob")
	defer trN.Close()
	defer trB.Close()

	ksN, ksB := newMemKS(t), newMemKS(t)
	nodeN, _ := NewNode(Config{Transport: trN, Keystore: ksN})
	nodeB, _ := NewNode(Config{Transport: trB, Keystore: ksB})
	defer nodeN.Close()
	defer nodeB.Close()

	nodeN.BindPeerAddr(a2al.NodeIDFromAddress(ksB.addr), trB.LocalAddr())
	nodeB.BindPeerAddr(a2al.NodeIDFromAddress(ksN.addr), trN.LocalAddr())
	nodeN.Start()
	nodeB.Start()

	now := time.Now().Truncate(time.Second)
	mail := mustMailboxFrom(t, ksN, ksB, now, []byte("hi-bob"))
	bKey := a2al.NodeIDFromAddress(ksB.addr)
	if err := nodeN.LocalStorePut(bKey, mail); err != nil {
		t.Fatal(err)
	}

	got := make(chan []protocol.ReceivePoolHint, 1)
	nodeB.SetReceivePoolHandler(func(visitor a2al.Address, _ a2al.NodeID, pool []protocol.ReceivePoolHint) {
		if visitor != ksB.addr {
			t.Errorf("visitor %s want Bob", visitor)
		}
		got <- pool
	})

	ep, err := protocol.SignEndpointRecord(ksB.priv, ksB.addr, protocol.EndpointPayload{
		Endpoints: []string{"quic://10.0.0.2:9"},
		NatType:   protocol.NATUnknown,
	}, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stored, _, _, _, err := nodeB.StoreAt(ctx, trN.LocalAddr(), a2al.NodeID{}, ep)
	if err != nil {
		t.Fatal(err)
	}
	if !stored {
		t.Fatal("StoreAt not stored")
	}
	select {
	case pool := <-got:
		if len(pool) != 1 || pool[0].RecType != protocol.RecTypeMailbox || pool[0].Count < 1 {
			t.Fatalf("hint %+v", pool)
		}
	case <-ctx.Done():
		t.Fatal("no receive-pool callback")
	}
}

func TestStoreAt_pathCacheNoReceivePoolHint(t *testing.T) {
	netw := transport.NewMemNetwork()
	trN, _ := netw.NewTransport("neigh")
	trQ, _ := netw.NewTransport("querier")
	defer trN.Close()
	defer trQ.Close()

	ksN, ksQ, ksB := newMemKS(t), newMemKS(t), newMemKS(t)
	nodeN, _ := NewNode(Config{Transport: trN, Keystore: ksN})
	nodeQ, _ := NewNode(Config{Transport: trQ, Keystore: ksQ})
	defer nodeN.Close()
	defer nodeQ.Close()

	nodeN.BindPeerAddr(a2al.NodeIDFromAddress(ksQ.addr), trQ.LocalAddr())
	nodeQ.BindPeerAddr(a2al.NodeIDFromAddress(ksN.addr), trN.LocalAddr())
	nodeN.Start()
	nodeQ.Start()

	now := time.Now().Truncate(time.Second)
	mail := mustMailboxFrom(t, ksN, ksB, now, []byte("for-b"))
	bKey := a2al.NodeIDFromAddress(ksB.addr)
	if err := nodeN.LocalStorePut(bKey, mail); err != nil {
		t.Fatal(err)
	}

	called := make(chan struct{}, 1)
	nodeQ.SetReceivePoolHandler(func(a2al.Address, a2al.NodeID, []protocol.ReceivePoolHint) {
		called <- struct{}{}
	})

	ep, err := protocol.SignEndpointRecord(ksB.priv, ksB.addr, protocol.EndpointPayload{
		Endpoints: []string{"quic://10.0.0.9:9"},
		NatType:   protocol.NATUnknown,
	}, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, _, _, err := nodeQ.StoreAt(ctx, trN.LocalAddr(), a2al.NodeID{}, ep); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
		t.Fatal("path-cache STORE must not hitch the record owner's receive pool")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestStoreAt_mailboxDepositDoesNotLeakRecipientPool(t *testing.T) {
	netw := transport.NewMemNetwork()
	trN, _ := netw.NewTransport("neigh")
	trC, _ := netw.NewTransport("carol")
	defer trN.Close()
	defer trC.Close()

	ksN, ksC, ksB := newMemKS(t), newMemKS(t), newMemKS(t)
	nodeN, _ := NewNode(Config{Transport: trN, Keystore: ksN})
	nodeC, _ := NewNode(Config{Transport: trC, Keystore: ksC})
	defer nodeN.Close()
	defer nodeC.Close()

	nodeN.BindPeerAddr(a2al.NodeIDFromAddress(ksC.addr), trC.LocalAddr())
	nodeC.BindPeerAddr(a2al.NodeIDFromAddress(ksN.addr), trN.LocalAddr())
	nodeN.Start()
	nodeC.Start()

	now := time.Now().Truncate(time.Second)
	existing := mustMailboxFrom(t, ksN, ksB, now, []byte("already-for-b"))
	bKey := a2al.NodeIDFromAddress(ksB.addr)
	if err := nodeN.LocalStorePut(bKey, existing); err != nil {
		t.Fatal(err)
	}

	got := make(chan []protocol.ReceivePoolHint, 1)
	nodeC.SetReceivePoolHandler(func(_ a2al.Address, _ a2al.NodeID, pool []protocol.ReceivePoolHint) {
		got <- pool
	})

	deposit := mustMailboxFrom(t, ksC, ksB, now, []byte("new-for-b"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, _, _, err := nodeC.StoreAt(ctx, trN.LocalAddr(), bKey, deposit); err != nil {
		t.Fatal(err)
	}
	select {
	case pool := <-got:
		t.Fatalf("sender must not receive recipient pool, got %+v", pool)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestCoincidenceIngest_asyncPushHandler(t *testing.T) {
	netw := transport.NewMemNetwork()
	trN, _ := netw.NewTransport("home")
	trC, _ := netw.NewTransport("carol")
	defer trN.Close()
	defer trC.Close()

	ksN, ksC := newMemKS(t), newMemKS(t)
	nodeN, _ := NewNode(Config{Transport: trN, Keystore: ksN})
	nodeC, _ := NewNode(Config{Transport: trC, Keystore: ksC})
	defer nodeN.Close()
	defer nodeC.Close()

	nKey := a2al.NodeIDFromAddress(ksN.addr)
	nodeN.SetLocalReceiveKeys([]a2al.NodeID{nKey})
	got := make(chan protocol.SignedRecord, 1)
	nodeN.SetPushHandler(func(key a2al.NodeID, rec protocol.SignedRecord) bool {
		if key != nKey {
			t.Errorf("key %x want home", key[:4])
		}
		got <- rec
		return true
	})

	nodeN.BindPeerAddr(a2al.NodeIDFromAddress(ksC.addr), trC.LocalAddr())
	nodeC.BindPeerAddr(nKey, trN.LocalAddr())
	nodeN.Start()
	nodeC.Start()

	now := time.Now().Truncate(time.Second)
	mail := mustMailboxFrom(t, ksC, ksN, now, []byte("home-mail"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, _, _, err := nodeC.StoreAt(ctx, trN.LocalAddr(), nKey, mail); err != nil {
		t.Fatal(err)
	}
	select {
	case rec := <-got:
		if rec.RecType != protocol.RecTypeMailbox {
			t.Fatalf("recType %d", rec.RecType)
		}
	case <-ctx.Done():
		t.Fatal("coincidence ingest did not fire")
	}
}

func mustMailbox(t *testing.T, id recIdentity, now time.Time, body []byte) protocol.SignedRecord {
	t.Helper()
	return mustMailboxKeys(t, id.priv, id.addr, id.priv, id.addr, now, body)
}

func mustMailboxFrom(t *testing.T, sender, recipient *memKS, now time.Time, body []byte) protocol.SignedRecord {
	t.Helper()
	return mustMailboxKeys(t, sender.priv, sender.addr, recipient.priv, recipient.addr, now, body)
}

func mustMailboxKeys(t *testing.T, senderPriv ed25519.PrivateKey, senderAddr a2al.Address, recipientPriv ed25519.PrivateKey, recipientAddr a2al.Address, now time.Time, body []byte) protocol.SignedRecord {
	t.Helper()
	pub := recipientPriv.Public().(ed25519.PublicKey)
	payload, err := protocol.EncodeMailboxPayload(senderAddr, recipientAddr, pub, protocol.MailboxMsgText, body)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := protocol.SignRecord(senderPriv, senderAddr, protocol.RecTypeMailbox, payload, uint64(now.UnixNano()), uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}
