// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"net"
	"testing"

	"github.com/a2al/a2al/protocol"
)

func TestShouldSkipDirect(t *testing.T) {
	signal := "wss://signal.example.com"

	tests := []struct {
		name     string
		er       *protocol.EndpointRecord
		wantSkip bool
	}{
		// nil record → never skip
		{name: "nil record", er: nil, wantSkip: false},

		// No signal URL → never skip regardless of NAT type
		{name: "unknown/no-signal", er: &protocol.EndpointRecord{NatType: protocol.NATUnknown}, wantSkip: false},
		{name: "fullcone/no-signal", er: &protocol.EndpointRecord{NatType: protocol.NATFullCone}, wantSkip: false},
		{name: "restricted/no-signal", er: &protocol.EndpointRecord{NatType: protocol.NATRestricted}, wantSkip: false},
		{name: "port-restricted/no-signal", er: &protocol.EndpointRecord{NatType: protocol.NATPortRestricted}, wantSkip: false},
		{name: "symmetric/no-signal", er: &protocol.EndpointRecord{NatType: protocol.NATSymmetric}, wantSkip: false},

		// NATUnknown + signal → try direct first (we don't know NAT topology)
		{name: "unknown/signal", er: &protocol.EndpointRecord{NatType: protocol.NATUnknown, Signal: signal}, wantSkip: false},

		// NATFullCone + signal → try direct first (inbound UDP likely works)
		{name: "fullcone/signal", er: &protocol.EndpointRecord{NatType: protocol.NATFullCone, Signal: signal}, wantSkip: false},

		// NATRestricted + signal → skip direct; cold UDP blocked by NAT filter
		{name: "restricted/signal", er: &protocol.EndpointRecord{NatType: protocol.NATRestricted, Signal: signal}, wantSkip: true},

		// NATPortRestricted + signal → skip direct; port must also match
		{name: "port-restricted/signal", er: &protocol.EndpointRecord{NatType: protocol.NATPortRestricted, Signal: signal}, wantSkip: true},

		// NATSymmetric + signal → skip direct; port prediction impossible
		{name: "symmetric/signal", er: &protocol.EndpointRecord{NatType: protocol.NATSymmetric, Signal: signal}, wantSkip: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSkipDirect(tc.er)
			if got != tc.wantSkip {
				t.Errorf("shouldSkipDirect(%+v) = %v, want %v", tc.er, got, tc.wantSkip)
			}
		})
	}
}

func mustUDPAddr(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		panic(err)
	}
	return a
}

// TestFilterDirectTargets verifies that per-candidate filtering preserves
// IPv6 GUA candidates even when the peer's v4 NAT type mandates ICE-only.
func TestFilterDirectTargets(t *testing.T) {
	signal := "wss://signal.example.com"
	v4addr := mustUDPAddr("1.2.3.4:4121")
	v6addr := mustUDPAddr("[2408:8207::1]:4121")
	both := []*net.UDPAddr{v4addr, v6addr}

	tests := []struct {
		name      string
		addrs     []*net.UDPAddr
		er        *protocol.EndpointRecord
		wantAddrs []*net.UDPAddr
	}{
		{
			name:      "nil record → all candidates pass",
			addrs:     both,
			er:        nil,
			wantAddrs: both,
		},
		{
			name:      "fullcone+signal → all candidates pass",
			addrs:     both,
			er:        &protocol.EndpointRecord{NatType: protocol.NATFullCone, Signal: signal},
			wantAddrs: both,
		},
		{
			name:  "symmetric+signal → v4 dropped, v6 kept",
			addrs: both,
			er:    &protocol.EndpointRecord{NatType: protocol.NATSymmetric, Signal: signal},
			// v6 GUA is directly reachable regardless of v4 NAT type.
			wantAddrs: []*net.UDPAddr{v6addr},
		},
		{
			name:  "restricted+signal → v4 dropped, v6 kept",
			addrs: both,
			er:    &protocol.EndpointRecord{NatType: protocol.NATRestricted, Signal: signal},
			wantAddrs: []*net.UDPAddr{v6addr},
		},
		{
			name:  "symmetric/no-signal → all candidates kept (no ICE fallback)",
			addrs: both,
			er:    &protocol.EndpointRecord{NatType: protocol.NATSymmetric},
			// Without a signal URL there is no ICE path; we must try direct.
			wantAddrs: both,
		},
		{
			name:      "v4-only symmetric+signal → all dropped (empty result)",
			addrs:     []*net.UDPAddr{v4addr},
			er:        &protocol.EndpointRecord{NatType: protocol.NATSymmetric, Signal: signal},
			wantAddrs: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := filterDirectTargets(tc.addrs, tc.er)
			if len(got) != len(tc.wantAddrs) {
				t.Fatalf("filterDirectTargets len=%d, want %d; got %v", len(got), len(tc.wantAddrs), got)
			}
			for i, a := range got {
				if a.String() != tc.wantAddrs[i].String() {
					t.Errorf("addr[%d] = %v, want %v", i, a, tc.wantAddrs[i])
				}
			}
		})
	}
}

// TestDialTargets verifies that dialTargets filters candidates by local IP-family
// capability, while falling back to the full list when no candidate matches.
func TestDialTargets(t *testing.T) {
	v4ep := "quic://1.2.3.4:4121"
	v6ep := "quic://[2408:8207::1]:4121"
	erBoth := &protocol.EndpointRecord{Endpoints: []string{v4ep, v6ep}}
	erV4Only := &protocol.EndpointRecord{Endpoints: []string{v4ep}}
	erV6Only := &protocol.EndpointRecord{Endpoints: []string{v6ep}}

	tests := []struct {
		name    string
		hasV4   bool
		hasV6   bool
		er      *protocol.EndpointRecord
		wantLen int
		wantV4  bool // result contains v4
		wantV6  bool // result contains v6
	}{
		{
			name:    "dual-stack host → both candidates",
			hasV4:   true,
			hasV6:   true,
			er:      erBoth,
			wantLen: 2,
		},
		{
			name:    "v4-only host → only v4 candidate",
			hasV4:   true,
			hasV6:   false,
			er:      erBoth,
			wantLen: 1,
			wantV4:  true,
		},
		{
			name:    "v6-only host → only v6 candidate",
			hasV4:   false,
			hasV6:   true,
			er:      erBoth,
			wantLen: 1,
			wantV6:  true,
		},
		{
			// No candidate matches capability → fallback to full list.
			name:    "v4-only host, record has only v6 → fallback to full list",
			hasV4:   true,
			hasV6:   false,
			er:      erV6Only,
			wantLen: 1,
			wantV6:  true,
		},
		{
			name:    "v6-only host, record has only v4 → fallback to full list",
			hasV4:   false,
			hasV6:   true,
			er:      erV4Only,
			wantLen: 1,
			wantV4:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &Host{hasV4: tc.hasV4, hasV6: tc.hasV6}
			got, err := h.dialTargets(tc.er)
			if err != nil {
				t.Fatalf("dialTargets error: %v", err)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("want %d addrs, got %d: %v", tc.wantLen, len(got), got)
			}
			if tc.wantLen == 1 {
				isV6 := got[0].IP.To4() == nil
				if tc.wantV4 && isV6 {
					t.Errorf("expected v4 addr, got v6: %v", got[0])
				}
				if tc.wantV6 && !isV6 {
					t.Errorf("expected v6 addr, got v4: %v", got[0])
				}
			}
		})
	}
}

// TestFirstV4SrflxAddr verifies that firstV4SrflxAddr correctly identifies
// the first IPv4 address from a mixed v4/v6 list regardless of order.
func TestFirstV4SrflxAddr(t *testing.T) {
	tests := []struct {
		name  string
		addrs []string
		want  string
	}{
		{name: "empty", addrs: nil, want: ""},
		{name: "v4 only", addrs: []string{"1.2.3.4:4121"}, want: "1.2.3.4:4121"},
		{name: "v6 only", addrs: []string{"[2408:8207::1]:4121"}, want: ""},
		{name: "v4 first", addrs: []string{"1.2.3.4:4121", "[2408:8207::1]:4121"}, want: "1.2.3.4:4121"},
		{name: "v6 first", addrs: []string{"[2408:8207::1]:4121", "1.2.3.4:4121"}, want: "1.2.3.4:4121"},
		{name: "multiple v4", addrs: []string{"1.2.3.4:4121", "5.6.7.8:4121"}, want: "1.2.3.4:4121"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := firstV4SrflxAddr(tc.addrs)
			if got != tc.want {
				t.Errorf("firstV4SrflxAddr(%v) = %q, want %q", tc.addrs, got, tc.want)
			}
		})
	}
}

// TestExpandSymmetricPunch_DualStack is a regression for P2 hazard 1:
// when the remote srflx list contains both v4 and v6 (from TrustedUDPAll),
// map iteration may put v6 first. expandSymmetricPunch must receive v4 base.
func TestExpandSymmetricPunch_DualStack(t *testing.T) {
	v4 := "1.2.3.4:4121"
	v6 := "[2408:8207::1]:4121"

	// v6 appears first (worst case map order). firstV4SrflxAddr must still find v4.
	base := firstV4SrflxAddr([]string{v6, v4})
	if base != v4 {
		t.Fatalf("expected v4 base %q, got %q", v4, base)
	}

	// expandSymmetricPunch with v4 base must produce sprayed ports.
	sprayed := expandSymmetricPunch(base, 2)
	if len(sprayed) <= 1 {
		t.Fatalf("expected spray > 1 entry, got %d: %v", len(sprayed), sprayed)
	}
	if sprayed[0] != v4 {
		t.Errorf("sprayed[0] = %q, want %q", sprayed[0], v4)
	}

	// expandSymmetricPunch with v6 primary must degrade gracefully to [v6].
	fallback := expandSymmetricPunch(v6, 2)
	if len(fallback) != 1 || fallback[0] != v6 {
		t.Errorf("v6 fallback: want [%q], got %v", v6, fallback)
	}
}
