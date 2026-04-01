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
