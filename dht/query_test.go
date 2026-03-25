// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dht

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

func TestBootstrap_iterativeResolveMem(t *testing.T) {
	netw := transport.NewMemNetwork()
	names := []string{"s", "r", "a", "c"}
	type pack struct {
		n  *Node
		ks *memKS
		tr *transport.MemTransport
	}
	packs := make([]pack, len(names))
	for i, name := range names {
		tr, err := netw.NewTransport(name)
		if err != nil {
			t.Fatal(err)
		}
		ks := newMemKS(t)
		node, err := NewNode(Config{Transport: tr, Keystore: ks})
		if err != nil {
			t.Fatal(err)
		}
		packs[i] = pack{n: node, ks: ks, tr: tr}
	}
	defer func() {
		for _, p := range packs {
			_ = p.n.Close()
			_ = p.tr.Close()
		}
	}()

	for i := range packs {
		pi := &packs[i]
		for j := range packs {
			if i == j {
				continue
			}
			pj := &packs[j]
			pid := a2al.NodeIDFromAddress(pj.ks.addr)
			pi.n.BindPeerAddr(pid, pj.tr.LocalAddr())
		}
		pi.n.Start()
	}

	S := &packs[0]
	seed := BootstrapSeed{Addr: S.tr.LocalAddr(), Info: contactNI(S.ks.addr)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for i := range packs {
		if err := packs[i].n.Bootstrap(ctx, []BootstrapSeed{seed}); err != nil {
			t.Fatalf("bootstrap %d: %v", i, err)
		}
	}

	A := &packs[2]
	R := &packs[1]
	now := time.Now().Truncate(time.Second)
	rec, err := protocol.SignEndpointRecord(A.ks.priv, A.ks.addr, protocol.EndpointPayload{
		Endpoints: []string{"quic://10.0.0.1:4242"},
		NatType:   protocol.NATUnknown,
	}, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := A.n.StoreAt(ctx, R.tr.LocalAddr(), a2al.NodeID{}, rec)
	if err != nil || !ok {
		t.Fatalf("store at R: ok=%v err=%v", ok, err)
	}

	C := &packs[3]
	q := NewQuery(C.n)
	key := a2al.NodeIDFromAddress(A.ks.addr)
	er, err := q.Resolve(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(er.Endpoints) != 1 || er.Endpoints[0] != "quic://10.0.0.1:4242" {
		t.Fatalf("endpoint %+v", er.Endpoints)
	}
}

func TestPublishEndpointRecord_mem(t *testing.T) {
	netw := transport.NewMemNetwork()
	trS, _ := netw.NewTransport("s")
	trA, _ := netw.NewTransport("a")
	defer trS.Close()
	defer trA.Close()
	ksS, ksA := newMemKS(t), newMemKS(t)
	nodeS, _ := NewNode(Config{Transport: trS, Keystore: ksS})
	nodeA, _ := NewNode(Config{Transport: trA, Keystore: ksA})
	defer nodeS.Close()
	defer nodeA.Close()

	nodeA.BindPeerAddr(a2al.NodeIDFromAddress(ksS.addr), trS.LocalAddr())
	nodeS.BindPeerAddr(a2al.NodeIDFromAddress(ksA.addr), trA.LocalAddr())

	nodeS.Start()
	nodeA.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	seed := BootstrapSeed{Addr: trS.LocalAddr(), Info: contactNI(ksS.addr)}
	if err := nodeA.Bootstrap(ctx, []BootstrapSeed{seed}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().Truncate(time.Second)
	rec, err := protocol.SignEndpointRecord(ksA.priv, ksA.addr, protocol.EndpointPayload{
		Endpoints: []string{"quic://192.0.2.1:9999"},
		NatType:   protocol.NATUnknown,
	}, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeA.PublishEndpointRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}

	q := NewQuery(nodeS)
	key := a2al.NodeIDFromAddress(ksA.addr)
	er, err := q.Resolve(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(er.Endpoints) != 1 || er.Endpoints[0] != "quic://192.0.2.1:9999" {
		t.Fatal(er.Endpoints)
	}
}

func TestTenNodes_memMultiHop(t *testing.T) {
	const nPeer = 10
	netw := transport.NewMemNetwork()
	type pack struct {
		n  *Node
		ks *memKS
		tr *transport.MemTransport
	}
	packs := make([]pack, nPeer)
	for i := 0; i < nPeer; i++ {
		tr, err := netw.NewTransport(fmt.Sprintf("n%d", i))
		if err != nil {
			t.Fatal(err)
		}
		ks := newMemKS(t)
		node, err := NewNode(Config{Transport: tr, Keystore: ks})
		if err != nil {
			t.Fatal(err)
		}
		packs[i] = pack{n: node, ks: ks, tr: tr}
	}
	defer func() {
		for i := range packs {
			_ = packs[i].n.Close()
			_ = packs[i].tr.Close()
		}
	}()

	for i := range packs {
		for j := range packs {
			if i == j {
				continue
			}
			pid := a2al.NodeIDFromAddress(packs[j].ks.addr)
			packs[i].n.BindPeerAddr(pid, packs[j].tr.LocalAddr())
		}
		packs[i].n.Start()
	}

	seed := BootstrapSeed{Addr: packs[0].tr.LocalAddr(), Info: contactNI(packs[0].ks.addr)}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	for i := range packs {
		if err := packs[i].n.Bootstrap(ctx, []BootstrapSeed{seed}); err != nil {
			t.Fatalf("bootstrap %d: %v", i, err)
		}
	}

	pub := &packs[5]
	hub := &packs[8]
	resolver := &packs[9]
	now := time.Now().Truncate(time.Second)
	rec, err := protocol.SignEndpointRecord(pub.ks.priv, pub.ks.addr, protocol.EndpointPayload{
		Endpoints: []string{"quic://198.51.100.7:7777"},
		NatType:   protocol.NATUnknown,
	}, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := pub.n.StoreAt(ctx, hub.tr.LocalAddr(), a2al.NodeID{}, rec)
	if err != nil || !ok {
		t.Fatalf("store: ok=%v err=%v", ok, err)
	}

	q := NewQuery(resolver.n)
	key := a2al.NodeIDFromAddress(pub.ks.addr)
	er, err := q.Resolve(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(er.Endpoints) != 1 || er.Endpoints[0] != "quic://198.51.100.7:7777" {
		t.Fatalf("endpoints %+v", er.Endpoints)
	}
}

func TestBootstrapAddrs_mem(t *testing.T) {
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
	rec, err := protocol.SignEndpointRecord(ksA.priv, ksA.addr, protocol.EndpointPayload{
		Endpoints: []string{"quic://10.0.0.1:1234"},
		NatType:   protocol.NATUnknown,
	}, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeA.PublishEndpointRecord(ctx, rec); err != nil {
		t.Fatal("publish A:", err)
	}

	q := NewQuery(nodeB)
	key := a2al.NodeIDFromAddress(ksA.addr)
	er, err := q.Resolve(ctx, key)
	if err != nil {
		t.Fatal("resolve:", err)
	}
	if len(er.Endpoints) != 1 || er.Endpoints[0] != "quic://10.0.0.1:1234" {
		t.Fatalf("want [quic://10.0.0.1:1234], got %v", er.Endpoints)
	}
}
