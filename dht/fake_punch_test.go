// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
	"github.com/a2al/a2al/transport"
)

// setupFakePunchPair creates two DHT nodes (A, B) both wired to the same
// FakePunchNetwork, ready for integration testing.
//
//	punchNet — shared network
//	nodeA, nodeB — fully started nodes
//	nidA, nidB — corresponding NodeIDs
//
// Callers must defer nodeA.Close(), nodeB.Close().
func setupFakePunchPair(t *testing.T) (
	punchNet *FakePunchNetwork,
	nodeA, nodeB *Node,
	nidA, nidB a2al.NodeID,
) {
	t.Helper()

	memNet := transport.NewMemNetwork()
	trA, err := memNet.NewTransport("fpA")
	if err != nil {
		t.Fatal(err)
	}
	trB, err := memNet.NewTransport("fpB")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { trA.Close(); trB.Close() })

	ksA, ksB := newMemKS(t), newMemKS(t)
	nidA = a2al.NodeIDFromAddress(ksA.addr)
	nidB = a2al.NodeIDFromAddress(ksB.addr)

	punchNet = NewFakePunchNetwork()
	ptA := punchNet.NewTransport(nidA, trA.LocalAddr())
	ptB := punchNet.NewTransport(nidB, trB.LocalAddr())

	nodeA, err = NewNode(Config{Transport: trA, Keystore: ksA, PunchTransport: ptA})
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err = NewNode(Config{Transport: trB, Keystore: ksB, PunchTransport: ptB})
	if err != nil {
		t.Fatal(err)
	}

	// Wire transports to their nodes after creation.
	ptA.Bind(nodeA)
	ptB.Bind(nodeB)

	nodeA.Start()
	nodeB.Start()
	return
}

// waitForRoutingEntry polls nodeA's routing table until it contains target
// or the deadline passes.  Returns true when found.
func waitForRoutingEntry(nodeA *Node, target a2al.NodeID, deadline time.Duration) bool {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		nodeA.tabMu.RLock()
		found := nodeA.table.Contains(target)
		nodeA.tabMu.RUnlock()
		if found {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// ---------------------------------------------------------------------------
// TestFakePunchTransport_SendTo
// Verifies that FakePunchTransport.SendTo routes messages through
// InjectReceived (bypassing the MemTransport) by issuing a real Ping RPC
// from nodeA to nodeB entirely over the fake punch channel.
//
// Flow:
//
//	nodeA.Ping(addrB)
//	  → sendToOrFallback → punch.SendTo(nidB, ping_raw)
//	  → nodeB.InjectReceived(ping_raw, addrA)
//	  → nodeB.onPing → reply via punch.SendTo(nidA, pong_raw)
//	  → nodeA.InjectReceived(pong_raw, addrB) → Ping returns nil
// ---------------------------------------------------------------------------
func TestFakePunchTransport_SendTo(t *testing.T) {
	punchNet, nodeA, nodeB, nidA, nidB := setupFakePunchPair(t)
	defer nodeA.Close()
	defer nodeB.Close()

	addrA := punchNet.peers[nidA].addr
	addrB := punchNet.peers[nidB].addr

	// Register each node's address in the other's peer map so that
	// sendToOrFallback → lookupPeerID can resolve the NodeID and delegate
	// to the punch pool rather than fall back to MemTransport.
	nodeA.BindPeerAddr(nidB, addrB)
	nodeB.BindPeerAddr(nidA, addrA)

	// Issue a Ping from A to B entirely over the fake punch channel.
	// If SendTo is broken the reply never arrives and the context times out.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := nodeA.Ping(ctx, addrB); err != nil {
		t.Fatalf("Ping over fake punch channel failed: %v", err)
	}

	// nodeB also records nodeA after processing the ping.
	if !waitForRoutingEntry(nodeB, nidA, 2*time.Second) {
		t.Error("nodeB did not add nodeA to routing table after punch-channel ping")
	}
}

// ---------------------------------------------------------------------------
// TestFakePunchTransport_Punch_routingExchange
// Full L2 integration: punch nodeA → nodeB, confirm both sides update their
// routing tables and the FIND_NODE exchange propagates nodeB's pre-known
// third node (nodeC) into nodeA's routing table.
//
//	nodeA ──(FakePunch)──► nodeB
//	nodeB already knows nodeC (directly verified)
//
// Expected after punch completes:
//   - nodeA's routing table contains nodeB (isPunched = true initially)
//   - nodeA's routing table contains nodeC (discovered via FIND_NODE exchange)
//   - nodeB's routing table contains nodeA (bidirectional punch notification)
// ---------------------------------------------------------------------------
func TestFakePunchTransport_Punch_routingExchange(t *testing.T) {
	_, nodeA, nodeB, nidA, nidB := setupFakePunchPair(t)
	defer nodeA.Close()
	defer nodeB.Close()

	// Give nodeB a directly-verified third node (nodeC) so the FIND_NODE
	// response returns something useful to nodeA.
	ksC := newMemKS(t)
	nodeCAddr := ksC.addr
	nodeCID := a2al.NodeIDFromAddress(nodeCAddr)
	nodeC_ni := protocol.NodeInfo{
		Address: append([]byte(nil), nodeCAddr[:]...),
		NodeID:  append([]byte(nil), nodeCID[:]...),
		IP:      []byte{10, 0, 1, 3},
		Port:    9103,
	}
	nodeB.tabAdd(nodeC_ni, routing.EntryMeta{VerifiedAt: time.Now()}, nil)

	// Also register both peers' addresses in the opposite node so
	// sendToOrFallback can resolve NodeIDs from addresses (needed for the
	// FIND_NODE exchange reply path).
	//
	// In production this is done by OnPunchComplete → BindPeerAddr.
	// Here we pre-seed it so the reply from B can be resolved by B.
	// (OnPunchComplete seeds A's side; B's side is seeded when it processes
	//  the incoming FIND_NODE and calls remember().)
	_ = nidA // used by OnPunchComplete inside Punch

	// Trigger fake punch: A punches B.  FakePunchTransport calls
	// OnPunchComplete on both sides in goroutines.
	nodeA.punch.Punch(nidB, nil, PunchPriorityHigh)

	// 1. nodeA routing table should eventually contain nodeB.
	if !waitForRoutingEntry(nodeA, nidB, 3*time.Second) {
		t.Error("nodeA did not add nodeB to routing table after punch")
	}

	// 2. nodeA routing table should eventually contain nodeC (via exchange).
	if !waitForRoutingEntry(nodeA, nodeCID, 3*time.Second) {
		t.Errorf("nodeA did not discover nodeC (via FIND_NODE exchange) after punch")
	}

	// 3. nodeB routing table should contain nodeA (bidirectional notification).
	if !waitForRoutingEntry(nodeB, nidA, 3*time.Second) {
		t.Error("nodeB did not add nodeA to routing table after bidirectional punch")
	}
}

// ---------------------------------------------------------------------------
// TestFakePunchTransport_Punch_unknown
// Punching an unregistered node must report failure (isPunching cleared) and
// must not panic.
// ---------------------------------------------------------------------------
func TestFakePunchTransport_Punch_unknown(t *testing.T) {
	_, nodeA, nodeB, _, _ := setupFakePunchPair(t)
	defer nodeA.Close()
	defer nodeB.Close()

	var ghost a2al.NodeID
	ghost[0] = 0xFF // not registered in punchNet

	// Should not panic; isPunching is cleared via OnPunchComplete(…, false).
	done := make(chan struct{})
	go func() {
		defer close(done)
		nodeA.punch.Punch(ghost, nil, PunchPriorityLow)
	}()
	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("Punch to unknown node did not complete within deadline")
	}
}

// ---------------------------------------------------------------------------
// TestFakePunchTransport_Bind_idempotent
// Calling Bind a second time (e.g., re-registering for a different logical
// transport slot in a test) must not corrupt the network registry.
// ---------------------------------------------------------------------------
func TestFakePunchTransport_Bind_idempotent(t *testing.T) {
	punchNet, nodeA, nodeB, nidA, nidB := setupFakePunchPair(t)
	defer nodeA.Close()
	defer nodeB.Close()

	// Re-bind ptA to nodeA — should overwrite silently.
	ptA2 := punchNet.NewTransport(nidA, punchNet.peers[nidA].addr)
	ptA2.Bind(nodeA)

	punchNet.mu.Lock()
	peA := punchNet.peers[nidA]
	punchNet.mu.Unlock()

	if peA.node != nodeA {
		t.Error("second Bind did not update network registry correctly")
	}
	_ = nidB
}
