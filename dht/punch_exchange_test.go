// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"net"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
	"github.com/a2al/a2al/transport"
)

// TestExchangeAfterPunch verifies that after a successful punch, nodeA can
// discover nodeC through nodeB via exchangeAfterPunch.
//
// Setup:
//   nodeA ──(punch)──► nodeB  (both on MemTransport)
//   nodeB already has nodeC in its routing table (direct-verified)
//
// Expected result:
//   After exchangeAfterPunch completes, nodeC appears in nodeA's routing
//   table (main bucket or pending list, as hearsay from nodeB).
func TestExchangeAfterPunch(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, err := netw.NewTransport("exchA")
	if err != nil {
		t.Fatal(err)
	}
	trB, err := netw.NewTransport("exchB")
	if err != nil {
		t.Fatal(err)
	}
	defer trA.Close()
	defer trB.Close()

	ksA, ksB := newMemKS(t), newMemKS(t)
	nodeA, err := NewNode(Config{Transport: trA, Keystore: ksA})
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := NewNode(Config{Transport: trB, Keystore: ksB})
	if err != nil {
		t.Fatal(err)
	}
	nodeA.Start()
	nodeB.Start()
	defer nodeA.Close()
	defer nodeB.Close()

	// Give nodeB a "third node" (nodeC) it directly knows.
	// Use a real keypair so Address/NodeID pass protocol.nodeInfoCheck.
	ksC := newMemKS(t)
	nodeCAddr := ksC.addr
	nodeCID := a2al.NodeIDFromAddress(nodeCAddr)
	nodeC_ni := protocol.NodeInfo{
		Address: append([]byte(nil), nodeCAddr[:]...),
		NodeID:  append([]byte(nil), nodeCID[:]...),
		IP:      []byte{10, 0, 0, 3},
		Port:    9003,
	}
	// Add nodeC to nodeB as a directly-verified contact.
	nodeB.tabAdd(nodeC_ni, routing.EntryMeta{VerifiedAt: time.Now()}, nil)

	// Wire nodeA → nodeB for lookup (simulates the punch result).
	nodeA.BindPeerAddr(a2al.NodeIDFromAddress(ksB.addr), trB.LocalAddr())
	nodeBID := a2al.NodeIDFromAddress(ksB.addr)

	// Run the exchange synchronously (it's normally in a goroutine).
	nodeA.exchangeAfterPunch(nodeBID, trB.LocalAddr())

	// nodeC should now be discoverable by nodeA (routing table or pending list).
	nodeA.tabMu.RLock()
	found := nodeA.table.Contains(nodeCID)
	nodeA.tabMu.RUnlock()

	if !found {
		// It might be in the pending list if the main bucket filled up —
		// check via NearestN which includes main bucket only, but for this
		// test nodeA's table is nearly empty so it should be in main.
		t.Errorf("nodeC not found in nodeA's routing table after exchangeAfterPunch")
	}
}

// TestExchangeAfterPunch_badNodeFiltered verifies that nodes in PeerHealthBad
// state are NOT absorbed during the exchange (§6.2 anti-poisoning rule).
func TestExchangeAfterPunch_badNodeFiltered(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, err := netw.NewTransport("exchA2")
	if err != nil {
		t.Fatal(err)
	}
	trB, err := netw.NewTransport("exchB2")
	if err != nil {
		t.Fatal(err)
	}
	defer trA.Close()
	defer trB.Close()

	ksA, ksB := newMemKS(t), newMemKS(t)
	nodeA, err := NewNode(Config{Transport: trA, Keystore: ksA})
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := NewNode(Config{Transport: trB, Keystore: ksB})
	if err != nil {
		t.Fatal(err)
	}
	nodeA.Start()
	nodeB.Start()
	defer nodeA.Close()
	defer nodeB.Close()

	// Give nodeB a third node (nodeD).
	ksD := newMemKS(t)
	nodeDAddr := ksD.addr
	nodeDID := a2al.NodeIDFromAddress(nodeDAddr)
	nodeD_ni := protocol.NodeInfo{
		Address: append([]byte(nil), nodeDAddr[:]...),
		NodeID:  append([]byte(nil), nodeDID[:]...),
		IP:      []byte{10, 0, 0, 4},
		Port:    9004,
	}
	nodeB.tabAdd(nodeD_ni, routing.EntryMeta{VerifiedAt: time.Now()}, nil)

	// Pre-mark nodeD as Bad on nodeA — it should be filtered during absorption.
	nodeDNetAddr := &net.UDPAddr{IP: []byte{10, 0, 0, 4}, Port: 9004}
	for i := 0; i < badHealthThreshold; i++ {
		nodeA.recordFailure(nodeDID, nodeDNetAddr)
	}
	if nodeA.PeerHealthOf(nodeDID) != PeerHealthBad {
		t.Fatal("pre-condition: nodeDID should be Bad on nodeA")
	}

	nodeBID := a2al.NodeIDFromAddress(ksB.addr)
	nodeA.BindPeerAddr(nodeBID, trB.LocalAddr())
	nodeA.exchangeAfterPunch(nodeBID, trB.LocalAddr())

	// nodeD must NOT appear in nodeA's routing table.
	nodeA.tabMu.RLock()
	found := nodeA.table.Contains(nodeDID)
	nodeA.tabMu.RUnlock()
	if found {
		t.Error("nodeD (PeerHealthBad) should NOT be absorbed during exchange")
	}
}
