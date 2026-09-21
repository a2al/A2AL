// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/nodeks"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

func putLive(d *Daemon, local, remote a2al.Address, conn quic.Connection) {
	d.connPool.mu.Lock()
	d.connPool.pool[connPoolKey{local: local, remote: remote}] = &connPoolEntry{conn: conn, lastUsed: time.Now()}
	d.connPool.mu.Unlock()
}

func TestLooksLikeA2Magic(t *testing.T) {
	var m [4]byte
	copy(m[:], protocol.MagicGroupJoin)
	if !looksLikeA2Magic(m, 4) {
		t.Fatal("a2gj")
	}
	copy(m[:], "GET ")
	if looksLikeA2Magic(m, 4) {
		t.Fatal("HTTP")
	}
	if looksLikeA2Magic(m, 2) {
		t.Fatal("short")
	}
}

func TestDecideAccess_envelopeIgnoresACLDeny(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	e := d.reg.Get(aid)
	e.ACL = &registry.ACLPolicy{Default: registry.ACLDefaultDeny}
	if err := d.reg.Put(e); err != nil {
		t.Fatal(err)
	}
	remote := newTestAddr(t)
	src := testUDP("10.9.0.1")
	if d.decideAccess(aid, remote, "", src, accessService) {
		t.Fatal("service must deny")
	}
	if !d.decideAccess(aid, remote, "", src, accessEnvelope) {
		t.Fatal("envelope must allow")
	}
}

func TestSendEnvelope_noLiveNoPersist(t *testing.T) {
	d := newTestDaemon(t)
	local := newTestAgent(t, d)
	var remote a2al.Address
	remote[0] = 9
	_, err := d.SendEnvelope(context.Background(), local, remote, "t.ping", nil, false)
	if !errors.Is(err, errEnvelopeUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestFileMailbox_claimSkipsDoorbell(t *testing.T) {
	d := newTestDaemon(t)
	recipient := newTestAgent(t, d)
	e := d.reg.Get(recipient)
	if err := d.h.RegisterDelegatedAgent(recipient, e.OpPriv, e.DelegationCBOR); err != nil {
		t.Fatal(err)
	}
	var claimed atomic.Bool
	d.RegisterEnvelopeConsumer("t.invite", func(local, remote a2al.Address, kind string, body []byte) (bool, EnvelopeResult) {
		claimed.Store(true)
		if kind != "t.invite" || string(body) != "hi" {
			t.Errorf("kind=%q body=%q", kind, body)
		}
		return true, EnvelopeResult{Code: protocol.EnvelopePending}
	})

	ch, cancel := d.bus.Subscribe(Filter{Types: []string{"mailbox.received"}})
	defer cancel()

	rec := mustMailboxEnvelope(t, recipient, e.OpPriv.Public().(ed25519.PublicKey), "t.invite", []byte("hi"))
	newRecord, doorbell := d.fileMailbox(recipient, rec)
	if !newRecord || doorbell {
		t.Fatalf("new=%v doorbell=%v", newRecord, doorbell)
	}
	if !claimed.Load() {
		t.Fatal("consumer not called")
	}
	left, _ := d.mboxStore.GetUnconsumed(recipient)
	if len(left) != 0 {
		t.Fatalf("unconsumed %d", len(left))
	}
	if n := d.mboxStore.PendingCounts()[recipient]; n != 0 {
		t.Fatalf("pending %d", n)
	}
	select {
	case ev := <-ch:
		t.Fatalf("doorbell: %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestFileMailbox_textStillDoorbell(t *testing.T) {
	d := newTestDaemon(t)
	recipient := newTestAgent(t, d)
	e := d.reg.Get(recipient)
	if err := d.h.RegisterDelegatedAgent(recipient, e.OpPriv, e.DelegationCBOR); err != nil {
		t.Fatal(err)
	}
	d.RegisterEnvelopeConsumer("t.invite", func(a2al.Address, a2al.Address, string, []byte) (bool, EnvelopeResult) {
		t.Fatal("must not claim text")
		return false, EnvelopeResult{}
	})
	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderAID, err := crypto.AddressFromPublicKey(senderPub)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeMailboxPayload(senderAID, recipient, e.OpPriv.Public().(ed25519.PublicKey), protocol.MailboxMsgText, []byte("note"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rec, err := protocol.SignRecord(senderPriv, senderAID, protocol.RecTypeMailbox, payload, uint64(now.UnixNano()), uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	newRecord, doorbell := d.fileMailbox(recipient, rec)
	if !newRecord || !doorbell {
		t.Fatalf("new=%v doorbell=%v", newRecord, doorbell)
	}
	left, _ := d.mboxStore.GetUnconsumed(recipient)
	if len(left) != 1 {
		t.Fatalf("unconsumed %d", len(left))
	}
}

func TestFileMailbox_unclaimedEnvelopeDoorbell(t *testing.T) {
	d := newTestDaemon(t)
	recipient := newTestAgent(t, d)
	e := d.reg.Get(recipient)
	if err := d.h.RegisterDelegatedAgent(recipient, e.OpPriv, e.DelegationCBOR); err != nil {
		t.Fatal(err)
	}
	rec := mustMailboxEnvelope(t, recipient, e.OpPriv.Public().(ed25519.PublicKey), "t.invite", []byte("hi"))
	newRecord, doorbell := d.fileMailbox(recipient, rec)
	if !newRecord || !doorbell {
		t.Fatalf("new=%v doorbell=%v", newRecord, doorbell)
	}
}

func TestGateway_unknownA2DoesNotBridge(t *testing.T) {
	a := newTestDaemon(t)
	aid := newTestAgent(t, a)
	e := a.reg.Get(aid)
	if err := a.h.RegisterDelegatedAgent(aid, e.OpPriv, e.DelegationCBOR); err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			_ = c.Close()
		}
	}()
	e.ServiceTCP = ln.Addr().String()
	e.ACL = &registry.ACLPolicy{Default: registry.ACLDefaultPublic}
	if err := a.reg.Put(e); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		ac, err := a.h.Accept(ctx)
		if err != nil {
			return
		}
		a.serveGatewayConn(ctx, ac)
	}()

	ksB, err := nodeks.LoadOrGenerate(filepath.Join(t.TempDir(), "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	hb, err := host.New(host.Config{
		KeyStore:         ksB,
		ListenAddr:       "127.0.0.1:0",
		QUICListenAddr:   "127.0.0.1:0",
		MinObservedPeers: 1,
		FallbackHost:     "127.0.0.1",
		DisableUPnP:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hb.Close()

	conn, err := hb.Connect(ctx, aid, a.h.QUICLocalAddr())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := str.Write([]byte(protocol.MagicGroupJoin + "xxxx")); err != nil {
		t.Fatal(err)
	}
	_ = str.Close()
	time.Sleep(200 * time.Millisecond)
	if n := dials.Load(); n != 0 {
		t.Fatalf("a2gj bridged to TCP %d times", n)
	}
}

func TestSendEnvelope_hotPathNoMailbox(t *testing.T) {
	a := newTestDaemon(t)
	b := newTestDaemon(t)
	alice := newTestAgent(t, a)
	ea := a.reg.Get(alice)
	ea.ACL = &registry.ACLPolicy{Default: registry.ACLDefaultDeny}
	if err := a.reg.Put(ea); err != nil {
		t.Fatal(err)
	}
	if err := a.h.RegisterDelegatedAgent(alice, ea.OpPriv, ea.DelegationCBOR); err != nil {
		t.Fatal(err)
	}
	var saw atomic.Bool
	a.RegisterEnvelopeConsumer("t.ping", func(local, remote a2al.Address, kind string, body []byte) (bool, EnvelopeResult) {
		saw.Store(true)
		if local != alice || string(body) != "x" {
			t.Errorf("local=%s body=%q", local, body)
		}
		return true, EnvelopeResult{Code: protocol.EnvelopeOK}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		ac, err := a.h.Accept(ctx)
		if err != nil {
			return
		}
		a.serveGatewayConn(ctx, ac)
	}()

	conn, err := b.h.Connect(ctx, alice, a.h.QUICLocalAddr())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.CloseWithError(0, "done")
	if !b.h.PeerEnvelopeStream(conn) {
		t.Fatal("want 0x08")
	}
	putLive(b, b.nodeAddr, alice, conn)

	res, err := b.SendEnvelope(ctx, b.nodeAddr, alice, "t.ping", []byte("x"), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != protocol.EnvelopeOK {
		t.Fatalf("code=%d", res.Code)
	}
	if !saw.Load() {
		t.Fatal("consumer not called")
	}
	left, _ := a.mboxStore.GetUnconsumed(alice)
	if len(left) != 0 {
		t.Fatalf("hot path must not persist mailbox, unconsumed=%d", len(left))
	}
}

func TestSendEnvelope_deniedDoesNotPersist(t *testing.T) {
	a := newTestDaemon(t)
	b := newTestDaemon(t)
	alice := newTestAgent(t, a)
	ea := a.reg.Get(alice)
	if err := a.h.RegisterDelegatedAgent(alice, ea.OpPriv, ea.DelegationCBOR); err != nil {
		t.Fatal(err)
	}
	a.RegisterEnvelopeConsumer("t.ping", func(a2al.Address, a2al.Address, string, []byte) (bool, EnvelopeResult) {
		return true, EnvelopeResult{Code: protocol.EnvelopeDenied}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		ac, err := a.h.Accept(ctx)
		if err != nil {
			return
		}
		a.serveGatewayConn(ctx, ac)
	}()

	conn, err := b.h.Connect(ctx, alice, a.h.QUICLocalAddr())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.CloseWithError(0, "done")
	putLive(b, b.nodeAddr, alice, conn)

	res, err := b.SendEnvelope(ctx, b.nodeAddr, alice, "t.ping", []byte("x"), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != protocol.EnvelopeDenied {
		t.Fatalf("code=%d want denied", res.Code)
	}
	left, _ := a.mboxStore.GetUnconsumed(alice)
	if len(left) != 0 {
		t.Fatalf("denied must not persist, unconsumed=%d", len(left))
	}
}

func mustMailboxEnvelope(t *testing.T, recipient a2al.Address, recipientPub ed25519.PublicKey, kind string, body []byte) protocol.SignedRecord {
	t.Helper()
	inner, err := protocol.EncodeEnvelopeInner(kind, body)
	if err != nil {
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
	payload, err := protocol.EncodeMailboxPayload(senderAID, recipient, recipientPub, protocol.MailboxMsgEnvelope, inner)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rec, err := protocol.SignRecord(senderPriv, senderAID, protocol.RecTypeMailbox, payload, uint64(now.UnixNano()), uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}
