// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dht

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

func TestTopicPublishSearch_mem(t *testing.T) {
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
		t.Fatal(err)
	}
	if err := nodeB.BootstrapAddrs(ctx, []net.Addr{trS.LocalAddr()}); err != nil {
		t.Fatal(err)
	}

	tp := protocol.TopicPayload{
		Version:   1,
		Topic:     "ai/demo-topic",
		Name:      "Demo",
		Protocols: []string{"mcp"},
		Tags:      []string{"x"},
		Brief:     "brief",
	}
	payload, err := protocol.MarshalTopicPayload(tp)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rec, err := protocol.SignRecord(ksA.priv, ksA.addr, protocol.RecTypeTopic, payload, uint64(now.UnixNano()), uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	key := protocol.TopicNodeID("ai/demo-topic")
	if err := nodeA.PublishTopicRecord(ctx, key, rec); err != nil {
		t.Fatal(err)
	}

	q := NewQuery(nodeB)
	recs, err := q.AggregateRecords(ctx, key, protocol.RecTypeTopic)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 rec, got %d", len(recs))
	}
	e, err := protocol.TopicEntryFromSignedRecord(recs[0])
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "Demo" || e.Topic != "ai/demo-topic" || e.Address != ksA.addr {
		t.Fatalf("%+v", e)
	}
}
