// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
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
