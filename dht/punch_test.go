// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

// mockPunch is a test-only PunchTransport that records calls and returns
// configurable responses.
type mockPunch struct {
	sendOK    bool  // what SendTo should return as ok
	sendCalls int32 // atomic counter
	punchCalls int32
}

func (m *mockPunch) SendTo(_ context.Context, _ a2al.NodeID, _ []byte) (bool, error) {
	atomic.AddInt32(&m.sendCalls, 1)
	return m.sendOK, nil
}

func (m *mockPunch) Punch(_ a2al.NodeID, _ *protocol.EndpointRecord, _ int) {
	atomic.AddInt32(&m.punchCalls, 1)
}

// newTestNode builds a minimal DHT node wired to the given MemTransport, with
// an optional PunchTransport.
func newTestNode(t *testing.T, tr transport.Transport, punch PunchTransport) *Node {
	t.Helper()
	ks := newMemKS(t)
	n, err := NewNode(Config{Transport: tr, Keystore: ks, PunchTransport: punch})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSendToOrFallback_noPunch verifies that when no punch pool is configured,
// sendToOrFallback delivers via the UDP transport.
func TestSendToOrFallback_noPunch(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, _ := netw.NewTransport("a")
	trB, _ := netw.NewTransport("b")
	defer trA.Close()
	defer trB.Close()

	nodeA := newTestNode(t, trA, nil) // no punch pool
	nodeA.Start()
	defer nodeA.Close()

	payload := []byte("hello-udp")
	if err := nodeA.sendToOrFallback(context.Background(), trB.LocalAddr(), payload); err != nil {
		t.Fatalf("sendToOrFallback returned error: %v", err)
	}

	pkt, _, err := trB.Receive()
	if err != nil {
		t.Fatalf("trB did not receive the packet: %v", err)
	}
	if string(pkt) != string(payload) {
		t.Errorf("got %q, want %q", pkt, payload)
	}
}

// TestSendToOrFallback_punchMiss verifies that when the punch pool does NOT
// have an active connection (ok=false), sendToOrFallback falls back to UDP.
func TestSendToOrFallback_punchMiss(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, _ := netw.NewTransport("a")
	trB, _ := netw.NewTransport("b")
	defer trA.Close()
	defer trB.Close()

	mock := &mockPunch{sendOK: false}
	nodeA := newTestNode(t, trA, mock)
	nodeA.Start()
	defer nodeA.Close()

	// Register the peer address so lookupPeerID can resolve it.
	bAddr := trB.LocalAddr()
	var bID a2al.NodeID
	bID[0] = 0xAB
	nodeA.BindPeerAddr(bID, bAddr)

	payload := []byte("hello-fallback")
	if err := nodeA.sendToOrFallback(context.Background(), bAddr, payload); err != nil {
		t.Fatalf("sendToOrFallback returned error: %v", err)
	}

	// punch.SendTo must have been called once.
	if atomic.LoadInt32(&mock.sendCalls) != 1 {
		t.Errorf("SendTo call count = %d, want 1", mock.sendCalls)
	}
	// Packet must arrive via UDP fallback.
	pkt, _, err := trB.Receive()
	if err != nil {
		t.Fatalf("trB did not receive the packet: %v", err)
	}
	if string(pkt) != string(payload) {
		t.Errorf("got %q, want %q", pkt, payload)
	}
}

// TestSendToOrFallback_punchHit verifies that when the punch pool has an
// active connection (ok=true), sendToOrFallback does NOT call the UDP
// transport.
func TestSendToOrFallback_punchHit(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, _ := netw.NewTransport("a")
	trB, _ := netw.NewTransport("b")
	defer trA.Close()
	defer trB.Close()

	mock := &mockPunch{sendOK: true} // pool reports delivery succeeded
	nodeA := newTestNode(t, trA, mock)
	nodeA.Start()
	defer nodeA.Close()

	bAddr := trB.LocalAddr()
	var bID a2al.NodeID
	bID[0] = 0xCD
	nodeA.BindPeerAddr(bID, bAddr)

	payload := []byte("via-punch")
	if err := nodeA.sendToOrFallback(context.Background(), bAddr, payload); err != nil {
		t.Fatalf("sendToOrFallback returned error: %v", err)
	}

	// punch.SendTo must have been called once.
	if atomic.LoadInt32(&mock.sendCalls) != 1 {
		t.Errorf("SendTo call count = %d, want 1", mock.sendCalls)
	}
	// The UDP transport must NOT have been used; trB receives nothing.
	trB.Close() // closing makes any pending Receive return immediately
	_, _, udpErr := trB.Receive()
	if udpErr == nil {
		t.Error("UDP transport should NOT have been used when punch pool returns ok=true")
	}
}
