// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dht

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

func TestMailboxPublishAggregate_mem(t *testing.T) {
	netw := transport.NewMemNetwork()
	trS, _ := netw.NewTransport("seed")
	trA, _ := netw.NewTransport("nodeA")
	trB, _ := netw.NewTransport("nodeB")
	defer trS.Close()
	defer trA.Close()
	defer trB.Close()

	ksS, ksA, ksB := newMemKS(t), newMemKS(t), newMemKS(t)
	nodeS, _ := NewNode(Config{Transport: trS, Keystore: ksS})
	nodeA, _ := NewNode(Config{Transport: trA, Keystore: ksA})
	nodeB, _ := NewNode(Config{Transport: trB, Keystore: ksB})
	defer nodeS.Close()
	defer nodeA.Close()
	defer nodeB.Close()

	type nm struct {
		n  *Node
		ks *memKS
		tr *transport.MemTransport
	}
	all := []nm{{nodeS, ksS, trS}, {nodeA, ksA, trA}, {nodeB, ksB, trB}}
	for i := range all {
		for j := range all {
			if i == j {
				continue
			}
			all[i].n.BindPeerAddr(a2al.NodeIDFromAddress(all[j].ks.addr), all[j].tr.LocalAddr())
		}
	}

	nodeS.Start()
	nodeA.Start()
	nodeB.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := nodeA.BootstrapAddrs(ctx, []net.Addr{trS.LocalAddr()}); err != nil {
		t.Fatal("bootstrapAddrs A:", err)
	}
	if err := nodeB.BootstrapAddrs(ctx, []net.Addr{trS.LocalAddr()}); err != nil {
		t.Fatal("bootstrapAddrs B:", err)
	}

	now := time.Now().Truncate(time.Second)
	epRec, err := protocol.SignEndpointRecord(ksB.priv, ksB.addr, protocol.EndpointPayload{
		Endpoints: []string{"quic://10.0.0.2:9"},
		NatType:   protocol.NATUnknown,
	}, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeB.PublishEndpointRecord(ctx, epRec); err != nil {
		t.Fatal("publish B endpoint:", err)
	}

	pubB := ksB.priv.Public().(ed25519.PublicKey)
	payload, err := protocol.EncodeMailboxPayload(ksA.addr, ksB.addr, pubB, protocol.MailboxMsgText, []byte("mailbox-hi"))
	if err != nil {
		t.Fatal(err)
	}
	ts := uint64(time.Now().Unix())
	mailRec, err := protocol.SignRecord(ksA.priv, ksA.addr, protocol.RecTypeMailbox, payload, uint64(time.Now().UnixNano()), ts, 3600)
	if err != nil {
		t.Fatal(err)
	}
	bKey := a2al.NodeIDFromAddress(ksB.addr)
	if err := nodeA.PublishMailboxRecord(ctx, bKey, mailRec); err != nil {
		t.Fatal("publish mailbox:", err)
	}

	q := NewQuery(nodeB)
	recs, err := q.AggregateRecords(ctx, bKey, protocol.RecTypeMailbox)
	if err != nil {
		t.Fatal("aggregate:", err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 mailbox rec, got %d", len(recs))
	}
	msg, err := protocol.OpenMailboxRecord(ksB.priv, ksB.addr, recs[0])
	if err != nil {
		t.Fatal("open:", err)
	}
	if msg.MsgType != protocol.MailboxMsgText || string(msg.Body) != "mailbox-hi" || msg.Sender != ksA.addr {
		t.Fatalf("got %+v", msg)
	}
}
