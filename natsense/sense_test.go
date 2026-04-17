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
