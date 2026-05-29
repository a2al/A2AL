// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"net"
	"testing"
	"time"

	"github.com/a2al/a2al/transport"
)

// addrV4 is a helper for a v4 test UDP address.
func addrV4(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: port}
}

// addrV6 is a helper for a v6 test UDP address.
func addrV6(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: port}
}

// newHealthTestNode creates a minimal DHT node backed by a MemTransport for
// health/address-slot unit tests.
func newHealthTestNode(t *testing.T) *Node {
	t.Helper()
	netw := transport.NewMemNetwork()
	tr, err := netw.NewTransport("health-test")
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	ks := newMemKS(t)
	n, err := NewNode(Config{
		Transport: tr,
		Keystore:  ks,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	t.Cleanup(func() { n.Close(); tr.Close() })
	return n
}

// ---- peerAddrs dual-slot tests ----

func TestPeerAddrs_SetAndPrefer(t *testing.T) {
	pa := &peerAddrs{}
	if pa.preferred() != nil {
		t.Fatal("expected nil for empty peerAddrs")
	}

	v4 := addrV4(4000)
	pa.setStable(v4)
	if got := pa.preferred(); got.String() != v4.String() {
		t.Fatalf("preferred() = %v, want %v", got, v4)
	}

	v6 := addrV6(4000)
	pa.setStable(v6)
	// v4 live is still preferred (v4 priority).
	if got := pa.preferred(); got.String() != v4.String() {
		t.Fatalf("preferred() should be v4, got %v", got)
	}

	// Remove v4; v6 should surface.
	pa.v4 = familyAddrs{}
	if got := pa.preferred(); got != nil && got.String() != v6.String() {
		t.Fatalf("preferred() should be v6 live, got %v", got)
	}
}

func TestPeerAddrs_EphemeralExpiry(t *testing.T) {
	pa := &peerAddrs{}
	eph := addrV4(9999)
	pa.setEphemeral(eph)

	if got := pa.preferred(); got == nil || got.String() != eph.String() {
		t.Fatalf("expected ephemeral %v, got %v", eph, got)
	}

	// Simulate expiry by backdating ephemeralAt.
	pa.v4.ephemeralAt = time.Now().Add(-(peerAddrEphemeralTTL + time.Second))
	if pa.preferred() != nil {
		t.Fatal("expected nil after ephemeral expiry")
	}
}

func TestPeerAddrs_FallbackNonUDP(t *testing.T) {
	netw := transport.NewMemNetwork()
	fbTr, _ := netw.NewTransport("memtest")
	defer fbTr.Close()
	pa := &peerAddrs{}
	fb := fbTr.LocalAddr()
	pa.fallback = fb
	pa.setStable(addrV4(1234))
	// fallback takes priority over anchor/live slots.
	if got := pa.preferred(); got != fb {
		t.Fatalf("expected fallback addr, got %v", got)
	}
}

// ---- familyHealth / PeerHealthOf migration equivalence tests ----

// TestPeerHealthOf_V4Only asserts that for a v4-only peer the aggregate
// PeerHealthOf result is identical to the old single-family model.
func TestPeerHealthOf_V4Only(t *testing.T) {
	n := newHealthTestNode(t)
	var id [32]byte
	id[0] = 0xAA
	peerID := nodeIDFromBytes(id[:])

	// Initial state: Unknown (no contact yet).
	if s := n.PeerHealthOf(peerID); s != PeerHealthUnknown {
		t.Fatalf("initial state: want Unknown, got %v", s)
	}

	// One success on v4 -> Good.
	n.recordSuccess(peerID, addrV4(4000), 5*time.Millisecond)
	if s := n.PeerHealthOf(peerID); s != PeerHealthGood {
		t.Fatalf("after v4 success: want Good, got %v", s)
	}

	// badHealthThreshold failures on v4 -> Bad.
	for i := 0; i < badHealthThreshold; i++ {
		n.recordFailure(peerID, addrV4(4000))
	}
	if s := n.PeerHealthOf(peerID); s != PeerHealthBad {
		t.Fatalf("after v4 failures: want Bad, got %v", s)
	}
}

// TestPeerHealthOf_DualStack verifies the aggregation rules for dual-stack nodes.
func TestPeerHealthOf_DualStack(t *testing.T) {
	n := newHealthTestNode(t)
	var id [32]byte
	id[0] = 0xBB
	peerID := nodeIDFromBytes(id[:])

	// v4 succeeds ??Good even if v6 never tried.
	n.recordSuccess(peerID, addrV4(4000), 0)
	if s := n.PeerHealthOf(peerID); s != PeerHealthGood {
		t.Fatalf("v4 good, v6 inactive: want Good, got %v", s)
	}

	// Drive v4 into Bad but v6 has just succeeded ??overall Good.
	for i := 0; i < badHealthThreshold; i++ {
		n.recordFailure(peerID, addrV4(4000))
	}
	n.recordSuccess(peerID, addrV6(4000), 0)
	if s := n.PeerHealthOf(peerID); s != PeerHealthGood {
		t.Fatalf("v4 bad, v6 good: want Good, got %v", s)
	}

	// Drive v6 into Bad too ??Bad.
	for i := 0; i < badHealthThreshold; i++ {
		n.recordFailure(peerID, addrV6(4000))
	}
	if s := n.PeerHealthOf(peerID); s != PeerHealthBad {
		t.Fatalf("both v4 and v6 bad: want Bad, got %v", s)
	}

	// One v4 success ??Good again.
	n.recordSuccess(peerID, addrV4(4000), 0)
	if s := n.PeerHealthOf(peerID); s != PeerHealthGood {
		t.Fatalf("v4 recovered: want Good, got %v", s)
	}
}

// TestPeerHealthOf_V6OnlyActive checks a node only ever contacted via v6.
func TestPeerHealthOf_V6OnlyActive(t *testing.T) {
	n := newHealthTestNode(t)
	var id [32]byte
	id[0] = 0xCC
	peerID := nodeIDFromBytes(id[:])

	for i := 0; i < badHealthThreshold; i++ {
		n.recordFailure(peerID, addrV6(6000))
	}
	// v4 inactive, v6 bad ??Bad (all active families are bad).
	if s := n.PeerHealthOf(peerID); s != PeerHealthBad {
		t.Fatalf("v6 bad, v4 inactive: want Bad, got %v", s)
	}
}

// TestPeerAllowContact_DualFamily verifies that contact is allowed if at
// least one family's backoff has expired.
func TestPeerAllowContact_DualFamily(t *testing.T) {
	n := newHealthTestNode(t)
	var id [32]byte
	id[0] = 0xDD
	peerID := nodeIDFromBytes(id[:])

	// Start clean: allowed.
	if !n.PeerAllowContact(peerID) {
		t.Fatal("expected allow for unknown peer")
	}

	// Fail v4 to trigger backoff.
	n.recordFailure(peerID, addrV4(4000))
	// v6 has no backoff yet ??still allowed.
	if !n.PeerAllowContact(peerID) {
		t.Fatal("expected allow: v6 has no backoff")
	}
}

// TestLookupPeer_DualSlot verifies that BindPeerAddr stores family-matched
// slots and lookupPeer returns the preferred address.
func TestLookupPeer_DualSlot(t *testing.T) {
	n := newHealthTestNode(t)
	var id [32]byte
	id[0] = 0xEE
	peerID := nodeIDFromBytes(id[:])

	v4 := addrV4(5000)
	v6 := addrV6(5000)

	// Bind v4 first.
	n.BindPeerAddr(peerID, v4)
	got, ok := n.lookupPeer(peerID)
	if !ok || got.String() != v4.String() {
		t.Fatalf("after v4 bind: got %v, ok=%v", got, ok)
	}

	// Bind v6 ??v4 should still win (priority order).
	n.BindPeerAddr(peerID, v6)
	got, ok = n.lookupPeer(peerID)
	if !ok || got.String() != v4.String() {
		t.Fatalf("after v4+v6 bind: expected v4 preferred, got %v", got)
	}
}

// ---- helpers ----

func nodeIDFromBytes(b []byte) (id [32]byte) {
	copy(id[:], b)
	return id
}

// TestRecordFailure_ClearsLiveAtOnBad tests the full "peer-face cache
// lifecycle" when a peer migrates:
//
//  1. Set anchor + fresh verified live → preferred() returns live (observation wins).
//  2. recordFailure badHealthThreshold times → family turns Bad, liveAt is cleared.
//     preferred() should revert to anchor.
//  3. BindPeerAddr with a new live address → liveAt is refreshed.
//     preferred() should return the new live again.
func TestRecordFailure_ClearsLiveAtOnBad(t *testing.T) {
	n := newHealthTestNode(t)

	var peerID [32]byte
	peerID[0] = 0xFE
	id := nodeIDFromBytes(peerID[:])

	anchor := addrV4(4121)
	live1 := addrV4(55001)
	live2 := addrV4(55002)

	// Step 1: bind anchor and fresh verified live.
	n.BindPeerAnchor(id, anchor)
	n.BindPeerAddr(id, live1)

	got, ok := n.lookupPeer(id)
	if !ok || got.String() != live1.String() {
		t.Fatalf("step1: preferred = %v (ok=%v), want fresh live %v", got, ok, live1)
	}

	// Step 2: record enough failures to turn the family Bad.
	for i := 0; i < badHealthThreshold; i++ {
		n.recordFailure(id, live1)
	}
	got, ok = n.lookupPeer(id)
	if !ok || got.String() != anchor.String() {
		t.Fatalf("step2: after Bad, preferred = %v (ok=%v), want anchor %v", got, ok, anchor)
	}

	// Verify liveAt was actually zeroed.
	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(id)]
	n.peerMu.Unlock()
	if pa == nil {
		t.Fatal("step2: peerAddrs unexpectedly nil")
	}
	if !pa.v4.liveAt.IsZero() {
		t.Fatalf("step2: liveAt should be zero after Bad, got %v", pa.v4.liveAt)
	}

	// Step 3: new successful connection to updated address restores observation priority.
	n.BindPeerAddr(id, live2)
	got, ok = n.lookupPeer(id)
	if !ok || got.String() != live2.String() {
		t.Fatalf("step3: after rebind, preferred = %v (ok=%v), want new live %v", got, ok, live2)
	}
}

// TestSelfExtIPv6 verifies that SetSelfExtIPv6 / SelfExtIPv6 store and
// retrieve the IPv6 GUA independently of the v4 selfExtIP field.
func TestSelfExtIPv6(t *testing.T) {
	n := newHealthTestNode(t)

	// Initially nil.
	if got := n.SelfExtIPv6(); got != nil {
		t.Fatalf("expected nil SelfExtIPv6 before set, got %v", got)
	}

	// Set v6 GUA.
	v6 := net.ParseIP("2408:8207:18a0:2c60::56")
	n.SetSelfExtIPv6(v6)

	if got := n.SelfExtIPv6(); !got.Equal(v6) {
		t.Fatalf("SelfExtIPv6 = %v, want %v", got, v6)
	}

	// SelfExtIP (v4) must remain nil ? the two fields are independent.
	if got := n.SelfExtIP(); got != nil {
		t.Fatalf("SetSelfExtIPv6 should not affect SelfExtIP (v4), got %v", got)
	}

	// Setting v4 does not disturb v6.
	v4 := net.ParseIP("203.0.113.1")
	n.SetSelfExtIP(v4)
	if got := n.SelfExtIPv6(); !got.Equal(v6) {
		t.Fatalf("SelfExtIPv6 changed after SetSelfExtIP, got %v", got)
	}
}
