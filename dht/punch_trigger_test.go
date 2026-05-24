// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2al/a2al"
	acrypto "github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

// makeSignedEndpointRecord creates a minimal signed endpoint record for testing.
// signalURL may be empty to produce a record without a signal URL.
func makeSignedEndpointRecord(t *testing.T, signalURL string) (a2al.Address, a2al.NodeID, protocol.SignedRecord) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := acrypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	nid := a2al.NodeIDFromAddress(addr)
	ep := protocol.EndpointPayload{
		Endpoints: []string{"quic://10.0.0.1:4242"},
		NatType:   protocol.NATRestricted,
		Signal:    signalURL,
	}
	now := time.Now()
	sr, err := protocol.SignEndpointRecord(priv, addr, ep, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	return addr, nid, sr
}

// TestLookupEndpointRecord_hit verifies that a record with a signal URL is returned.
func TestLookupEndpointRecord_hit(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("trig-hit")
	defer tr.Close()

	ks := newMemKS(t)
	node, err := NewNode(Config{Transport: tr, Keystore: ks})
	if err != nil {
		t.Fatal(err)
	}

	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := node.LocalStorePut(peerID, sr); err != nil {
		t.Fatalf("LocalStorePut: %v", err)
	}

	er := node.lookupEndpointRecord(peerID)
	if er == nil {
		t.Fatal("expected non-nil EndpointRecord for peer with signal URL")
	}
	if er.Signal == "" {
		t.Error("returned record has empty signal URL")
	}
}

// TestLookupEndpointRecord_miss verifies that nil is returned when no record is cached.
func TestLookupEndpointRecord_miss(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("trig-miss")
	defer tr.Close()

	ks := newMemKS(t)
	node, err := NewNode(Config{Transport: tr, Keystore: ks})
	if err != nil {
		t.Fatal(err)
	}

	var unknownID a2al.NodeID
	unknownID[0] = 0xDE
	er := node.lookupEndpointRecord(unknownID)
	if er != nil {
		t.Error("expected nil when no endpoint record is cached")
	}
}

// TestLookupEndpointRecord_noSignal verifies that nil is returned for a record
// without a signal URL (direct-only server node).
func TestLookupEndpointRecord_noSignal(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("trig-nosig")
	defer tr.Close()

	ks := newMemKS(t)
	node, err := NewNode(Config{Transport: tr, Keystore: ks})
	if err != nil {
		t.Fatal(err)
	}

	_, peerID, sr := makeSignedEndpointRecord(t, "") // no signal URL
	if err := node.LocalStorePut(peerID, sr); err != nil {
		t.Fatalf("LocalStorePut: %v", err)
	}

	er := node.lookupEndpointRecord(peerID)
	if er != nil {
		t.Error("expected nil for record without signal URL")
	}
}

// TestTriggerPunch_fromLookup verifies the full path:
//   - endpoint record with signal URL is in local store
//   - triggerPunch is called → punch pool receives the request
func TestTriggerPunch_fromLookup(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("trig-full")
	defer tr.Close()

	mock := &mockPunch{sendOK: false}
	ks := newMemKS(t)
	node, err := NewNode(Config{Transport: tr, Keystore: ks, PunchTransport: mock})
	if err != nil {
		t.Fatal(err)
	}

	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := node.LocalStorePut(peerID, sr); err != nil {
		t.Fatalf("LocalStorePut: %v", err)
	}

	er := node.lookupEndpointRecord(peerID)
	if er == nil {
		t.Fatal("pre-condition: lookupEndpointRecord should return non-nil")
	}
	node.triggerPunch(peerID, er, PunchPriorityHigh)

	if atomic.LoadInt32(&mock.punchCalls) != 1 {
		t.Errorf("Punch call count = %d, want 1", mock.punchCalls)
	}
}

// TestTriggerPunch_deduplication verifies that a second triggerPunch while
// isPunching=true is silently dropped.
func TestTriggerPunch_deduplication(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("trig-dedup")
	defer tr.Close()

	mock := &mockPunch{}
	ks := newMemKS(t)
	node, err := NewNode(Config{Transport: tr, Keystore: ks, PunchTransport: mock})
	if err != nil {
		t.Fatal(err)
	}

	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := node.LocalStorePut(peerID, sr); err != nil {
		t.Fatalf("LocalStorePut: %v", err)
	}
	er := node.lookupEndpointRecord(peerID)

	// First punch: accepted.
	node.triggerPunch(peerID, er, PunchPriorityHigh)
	// isPunching is now true (mock does not call OnPunchComplete).
	// Second punch: deduplicated.
	node.triggerPunch(peerID, er, PunchPriorityHigh)

	if atomic.LoadInt32(&mock.punchCalls) != 1 {
		t.Errorf("Punch call count = %d, want 1 (dedup should prevent second call)", mock.punchCalls)
	}
}

func TestTriggerPunchSkipsSelfNodeID(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("trig-self-nid")
	defer tr.Close()

	mock := &mockPunch{}
	ks := newMemKS(t)
	node, err := NewNode(Config{Transport: tr, Keystore: ks, PunchTransport: mock})
	if err != nil {
		t.Fatal(err)
	}

	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := node.LocalStorePut(peerID, sr); err != nil {
		t.Fatalf("LocalStorePut: %v", err)
	}
	er := node.lookupEndpointRecord(peerID)
	if er == nil {
		t.Fatal("pre-condition: lookupEndpointRecord should return non-nil")
	}

	node.triggerPunch(node.nid, er, PunchPriorityHigh)

	if atomic.LoadInt32(&mock.punchCalls) != 0 {
		t.Errorf("Punch call count = %d, want 0 for self nodeID", mock.punchCalls)
	}
}

func TestTriggerPunchSkipsSelfEndpoint(t *testing.T) {
	mock := &mockPunch{}
	node := newHealthTestNode(t)
	node.punch = mock

	var peerID a2al.NodeID
	peerID[0] = 0xAB
	er := &protocol.EndpointRecord{
		Address: node.addr,
		Signal:  "wss://signal.example.com",
	}
	node.triggerPunch(peerID, er, PunchPriorityHigh)

	if atomic.LoadInt32(&mock.punchCalls) != 0 {
		t.Errorf("Punch call count = %d, want 0 for self endpoint address", mock.punchCalls)
	}
}

func TestOnPunchCompleteRejectsHairpinSuccess(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetSelfExtIP(net.IPv4(47, 74, 189, 180))

	var peerID a2al.NodeID
	peerID[0] = 0xCC
	peerAddr, _, _ := makeSignedEndpointRecord(t, "wss://signal.example.com")
	hairpin := &net.UDPAddr{IP: net.IPv4(47, 74, 189, 180), Port: 65090}

	n.OnPunchComplete(peerID, peerAddr, hairpin, true, true, PunchFailNone)

	if _, ok := n.lookupPeer(peerID); ok {
		t.Fatal("hairpin punch success must not register peer address")
	}
}

func TestOnPunchCompleteRejectsSelfLogicalAddr(t *testing.T) {
	n := newHealthTestNode(t)

	var peerID a2al.NodeID
	peerID[0] = 0xDD
	peerUDP := addrV4(55106)

	n.OnPunchComplete(peerID, n.addr, peerUDP, true, true, PunchFailNone)

	if _, ok := n.lookupPeer(peerID); ok {
		t.Fatal("self logical address must not be admitted on punch complete")
	}
}

func TestIsControlPlaneSelfExcitation(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetSelfExtIP(net.IPv4(47, 74, 189, 180))

	var peerID a2al.NodeID
	peerID[0] = 0xEE
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4122}
	hairpin := &net.UDPAddr{IP: net.IPv4(47, 74, 189, 180), Port: 65090}

	if !n.isControlPlaneSelfExcitation(n.nid, loopback) {
		t.Fatal("self nodeID must be self excitation")
	}
	if !n.isControlPlaneSelfExcitation(peerID, hairpin) {
		t.Fatal("hairpin from must be self excitation")
	}
	if n.isControlPlaneSelfExcitation(peerID, loopback) {
		t.Fatal("loopback sibling from must not be self excitation")
	}
}
