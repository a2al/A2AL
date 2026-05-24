// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package natsense

import (
	"net"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

func TestSense_singleReporterWithMin1(t *testing.T) {
	s := NewSense(1)
	var r1, r2 a2al.NodeID
	r1[0] = 1
	r2[0] = 2
	wire, _ := protocol.FormatObservedUDP(net.ParseIP("203.0.113.5"), 5001)
	s.Record(r1, wire)
	h, p, ok := s.TrustedUDP()
	if !ok || h != "203.0.113.5" || p != 5001 {
		t.Fatalf("TrustedUDP = %s %d %v", h, p, ok)
	}
	// different address from another reporter — with min=1 first key still wins (map iteration order not guaranteed for "first")
	s.Record(r2, wire)
	h2, p2, ok2 := s.TrustedUDP()
	if !ok2 {
		t.Fatal("lost consensus")
	}
	if h2 != h || p2 != p {
		t.Fatalf("inconsistent %s:%d vs %s:%d", h, p, h2, p2)
	}
}

func TestSense_requiresThreeByDefault(t *testing.T) {
	s := NewSense(0) // default 3
	var r1 a2al.NodeID
	r1[0] = 1
	wire, _ := protocol.FormatObservedUDP(net.ParseIP("10.0.0.1"), 1)
	s.Record(r1, wire)
	if _, _, ok := s.TrustedUDP(); ok {
		t.Fatal("expected no trusted with single reporter and min=3")
	}
}

func TestInferNATType_singlePortIsRestricted(t *testing.T) {
	s := NewSense(3)
	var r1, r2, r3 a2al.NodeID
	r1[0], r2[0], r3[0] = 1, 2, 3
	wire, _ := protocol.FormatObservedUDP(net.ParseIP("198.51.100.10"), 41000)
	s.Record(r1, wire)
	s.Record(r2, wire)
	s.Record(r3, wire)
	if got := s.InferNATType(); got != NATRestricted {
		t.Fatalf("InferNATType single port = %d, want %d", got, NATRestricted)
	}
}

func TestInferNATType_bindPublicIsFullCone(t *testing.T) {
	s := NewSense(3)
	s.RecordBindPublic(true)
	if got := s.InferNATType(); got != NATFullCone {
		t.Fatalf("bindPublic=true: InferNATType = %d, want NATFullCone(%d)", got, NATFullCone)
	}
	if !s.IsBindPublic() {
		t.Fatal("IsBindPublic() should return true")
	}
}

func TestInferNATType_probeReachableIsFullCone(t *testing.T) {
	s := NewSense(3)
	// Supply enough votes for stable single-port mapping.
	var r1, r2, r3 a2al.NodeID
	r1[0], r2[0], r3[0] = 1, 2, 3
	wire, _ := protocol.FormatObservedUDP(net.ParseIP("198.51.100.1"), 40000)
	s.Record(r1, wire)
	s.Record(r2, wire)
	s.Record(r3, wire)
	// Without probe result, default is Restricted.
	if got := s.InferNATType(); got != NATRestricted {
		t.Fatalf("before probe: InferNATType = %d, want NATRestricted(%d)", got, NATRestricted)
	}
	// Probe reports reachable → Full Cone.
	s.RecordProbeResult(true)
	if got := s.InferNATType(); got != NATFullCone {
		t.Fatalf("probe reachable: InferNATType = %d, want NATFullCone(%d)", got, NATFullCone)
	}
}

func TestInferNATType_probeUnreachableIsRestricted(t *testing.T) {
	s := NewSense(3)
	var r1, r2, r3 a2al.NodeID
	r1[0], r2[0], r3[0] = 1, 2, 3
	wire, _ := protocol.FormatObservedUDP(net.ParseIP("198.51.100.2"), 41000)
	s.Record(r1, wire)
	s.Record(r2, wire)
	s.Record(r3, wire)
	s.RecordProbeResult(false)
	if got := s.InferNATType(); got != NATRestricted {
		t.Fatalf("probe unreachable: InferNATType = %d, want NATRestricted(%d)", got, NATRestricted)
	}
}

func TestInferNATType_requiresSupportedMultiPortForSymmetric(t *testing.T) {
	s := NewSense(3)
	var r1, r2, r3, r4 a2al.NodeID
	r1[0], r2[0], r3[0], r4[0] = 1, 2, 3, 4
	p1, _ := protocol.FormatObservedUDP(net.ParseIP("203.0.113.9"), 51001)
	p2, _ := protocol.FormatObservedUDP(net.ParseIP("203.0.113.9"), 52002)

	// First port has 3 reporters, second port has only 1 reporter -> not enough
	// support for symmetric classification.
	s.Record(r1, p1)
	s.Record(r2, p1)
	s.Record(r3, p1)
	s.Record(r4, p2)
	if got := s.InferNATType(); got != NATRestricted {
		t.Fatalf("InferNATType sparse 2nd port = %d, want %d", got, NATRestricted)
	}

	// Add one more independent reporter on second port -> symmetric.
	s.Record(r1, p2)
	if got := s.InferNATType(); got != NATSymmetric {
		t.Fatalf("InferNATType supported 2 ports = %d, want %d", got, NATSymmetric)
	}
}

// TestInferNATType_v6VotesNotCountedAsSymmetric is the regression test for G3:
// a dual-stack node with a stable v6 GUA port must not be misclassified as
// Symmetric NAT because the GUA port and the v4 NAT port look like two
// "distinct well-supported ports" in the old aggregated count.
func TestInferNATType_v6VotesNotCountedAsSymmetric(t *testing.T) {
	s := NewSense(2)
	var r1, r2, r3 a2al.NodeID
	r1[0], r2[0], r3[0] = 1, 2, 3

	// v4 reporters see our NAT-mapped external port 61000.
	p1, _ := protocol.FormatObservedUDP(net.ParseIP("203.0.113.10"), 61000)
	s.Record(r1, p1)
	s.Record(r2, p1)

	// v6 reporters see our GUA at port 4121 (same as local bind, stable).
	p2, _ := protocol.FormatObservedUDP(net.ParseIP("2001:db8::1"), 4121)
	s.Record(r2, p2)
	s.Record(r3, p2)

	// Before fix, two well-supported ports (61000 from v4, 4121 from v6)
	// would trigger NATSymmetric. After fix, v6 votes are excluded.
	got := s.InferNATType()
	if got == NATSymmetric {
		t.Fatalf("dual-stack node with GUA should not be classified as Symmetric, got %d", got)
	}
}

// TestInferV6Reach covers the v6 reachability state machine.
func TestInferV6Reach(t *testing.T) {
	s := NewSense(1)

	// No information yet.
	if r := s.InferV6Reach(); r != V6Unknown {
		t.Fatalf("want V6Unknown initially, got %d", r)
	}

	// GUA bind → Direct immediately, no probe needed.
	s.RecordV6GUABind(true)
	if r := s.InferV6Reach(); r != V6Direct {
		t.Fatalf("want V6Direct with GUA bind, got %d", r)
	}
	if !s.IsV6GUABind() {
		t.Fatal("IsV6GUABind should return true")
	}

	// Firewalled (GUA absent, probe failed).
	s2 := NewSense(1)
	s2.RecordV6ProbeResult(false)
	if r := s2.InferV6Reach(); r != V6Firewalled {
		t.Fatalf("want V6Firewalled after failed probe, got %d", r)
	}

	// Probe success without GUA bind also gives Direct.
	s3 := NewSense(1)
	s3.RecordV6ProbeResult(true)
	if r := s3.InferV6Reach(); r != V6Direct {
		t.Fatalf("want V6Direct after successful probe, got %d", r)
	}
}

// TestTrustedWireV4V6 verifies that the family-specific wire helpers return
// only matching entries.
func TestTrustedWireV4V6(t *testing.T) {
	s := NewSense(1)
	var r1, r2 a2al.NodeID
	r1[0], r2[0] = 1, 2

	v4wire, _ := protocol.FormatObservedUDP(net.ParseIP("203.0.113.5"), 5001)
	v6wire, _ := protocol.FormatObservedUDP(net.ParseIP("2001:db8::1"), 6001)
	s.Record(r1, v4wire)
	s.Record(r2, v6wire)

	if _, ok := s.TrustedWireV4(); !ok {
		t.Fatal("TrustedWireV4 should return v4 entry")
	}
	if _, ok := s.TrustedWireV6(); !ok {
		t.Fatal("TrustedWireV6 should return v6 entry")
	}

	// v4-only sense: no v6 entry → TrustedWireV6 returns nothing.
	sv4 := NewSense(1)
	sv4.Record(r1, v4wire)
	if _, ok := sv4.TrustedWireV6(); ok {
		t.Fatal("TrustedWireV6 should return nothing when only v4 votes present")
	}
}

// TestV4BindPublicDeprecatedAPICompat ensures the old RecordBindPublic /
// IsBindPublic wrappers still work identically to the new per-family versions.
func TestV4BindPublicDeprecatedAPICompat(t *testing.T) {
	s := NewSense(1)
	s.RecordBindPublic(true)
	if !s.IsBindPublic() {
		t.Fatal("deprecated IsBindPublic should return true")
	}
	if !s.IsV4BindPublic() {
		t.Fatal("IsV4BindPublic should also return true via deprecated wrapper")
	}
	if s.InferNATType() != NATFullCone {
		t.Fatal("bindPublicV4=true should give NATFullCone")
	}
}

func TestTrustedUDPAll_returnsBothFamilies(t *testing.T) {
	s := NewSense(1)

	var r1, r2, r3 a2al.NodeID
	r1[0], r2[0], r3[0] = 1, 2, 3

	// IPv4 entry — one reporter (min=1, reaches consensus)
	v4wire, _ := protocol.FormatObservedUDP(net.ParseIP("203.0.113.5"), 5001)
	s.Record(r1, v4wire)

	// IPv6 entry — one reporter
	v6wire, _ := protocol.FormatObservedUDP(net.ParseIP("2001:db8::1"), 6001)
	s.Record(r2, v6wire)

	// Entry that does NOT reach consensus (need 2 reporters but only r3 reports it)
	s2 := NewSense(2)
	s2.Record(r3, v4wire) // only 1 reporter, below min=2 → not trusted

	all := s.TrustedUDPAll()
	if len(all) != 2 {
		t.Fatalf("TrustedUDPAll: got %d entries, want 2: %v", len(all), all)
	}
	hasV4, hasV6 := false, false
	for _, a := range all {
		switch a {
		case "203.0.113.5:5001":
			hasV4 = true
		case "[2001:db8::1]:6001":
			hasV6 = true
		}
	}
	if !hasV4 {
		t.Errorf("missing IPv4 entry in TrustedUDPAll: %v", all)
	}
	if !hasV6 {
		t.Errorf("missing IPv6 entry in TrustedUDPAll: %v", all)
	}

	// Below-threshold entry should not appear.
	none := s2.TrustedUDPAll()
	if len(none) != 0 {
		t.Errorf("expected no entries with single reporter and min=2, got %v", none)
	}
}

func TestTrustedUDPAll_emptyAfterInvalidate(t *testing.T) {
	s := NewSense(1)
	var r1 a2al.NodeID
	r1[0] = 1
	wire, _ := protocol.FormatObservedUDP(net.ParseIP("198.51.100.1"), 9000)
	s.Record(r1, wire)
	if got := s.TrustedUDPAll(); len(got) == 0 {
		t.Fatal("expected non-empty before invalidate")
	}
	s.InvalidateObservations()
	if got := s.TrustedUDPAll(); len(got) != 0 {
		t.Fatalf("expected empty after invalidate, got %v", got)
	}
}

func TestInvalidateObservationsClearsTrustedState(t *testing.T) {
	s := NewSense(1)
	var r1 a2al.NodeID
	r1[0] = 1
	wire, _ := protocol.FormatObservedUDP(net.ParseIP("198.51.100.8"), 42000)
	s.Record(r1, wire)
	if _, _, ok := s.TrustedUDP(); !ok {
		t.Fatal("expected trusted udp before invalidate")
	}
	s.InvalidateObservations()
	if _, _, ok := s.TrustedUDP(); ok {
		t.Fatal("expected no trusted udp after invalidate")
	}
}
