// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"testing"

	"github.com/a2al/a2al/protocol"
)

func TestIsPublicHubCapable(t *testing.T) {
	tests := []struct {
		name      string
		natType   uint8
		endpoints []string
		want      bool
	}{
		// NATFullCone passes regardless of endpoints.
		{
			name:    "NATFullCone no endpoints",
			natType: protocol.NATFullCone,
			want:    true,
		},
		{
			name:      "NATFullCone with private v4 endpoint",
			natType:   protocol.NATFullCone,
			endpoints: []string{"quic://192.168.1.1:4121"},
			want:      true,
		},
		// Other NAT types with no endpoints.
		{
			name:    "NATRestricted no endpoints",
			natType: protocol.NATRestricted,
			want:    false,
		},
		{
			name:    "NATSymmetric no endpoints",
			natType: protocol.NATSymmetric,
			want:    false,
		},
		{
			name:    "NATUnknown no endpoints",
			natType: protocol.NATUnknown,
			want:    false,
		},
		// v6 GUA endpoint upgrades any NATType to capable.
		{
			name:      "NATRestricted with v6 GUA",
			natType:   protocol.NATRestricted,
			endpoints: []string{"quic://[2001:db8::1]:4121"},
			want:      true,
		},
		{
			name:      "NATUnknown with real v6 GUA",
			natType:   protocol.NATUnknown,
			endpoints: []string{"quic://[2408:8207:18a0:2c60::56]:4121"},
			want:      true,
		},
		// v6 non-GUA addresses do not qualify.
		{
			name:      "v6 ULA (fc00::/7)",
			natType:   protocol.NATRestricted,
			endpoints: []string{"quic://[fc00::1]:4121"},
			want:      false,
		},
		{
			name:      "v6 ULA (fd00::/8)",
			natType:   protocol.NATRestricted,
			endpoints: []string{"quic://[fd12:3456::1]:4121"},
			want:      false,
		},
		{
			name:      "v6 link-local",
			natType:   protocol.NATRestricted,
			endpoints: []string{"quic://[fe80::1]:4121"},
			want:      false,
		},
		{
			name:      "v6 loopback",
			natType:   protocol.NATRestricted,
			endpoints: []string{"quic://[::1]:4121"},
			want:      false,
		},
		// v4 public addresses alone do not qualify (no NATFullCone).
		{
			name:      "v4 public NATRestricted",
			natType:   protocol.NATRestricted,
			endpoints: []string{"quic://8.8.8.8:4121"},
			want:      false,
		},
		// Mixed endpoints: one v6 GUA among others is enough.
		{
			name:    "mixed endpoints one v6 GUA",
			natType: protocol.NATRestricted,
			endpoints: []string{
				"quic://192.168.1.1:4121",
				"quic://[fc00::1]:4121",
				"quic://[2001:db8::1]:4121",
			},
			want: true,
		},
		// Scheme-less host:port form still parses.
		{
			name:      "no scheme v6 GUA",
			natType:   protocol.NATRestricted,
			endpoints: []string{"[2001:db8::1]:4121"},
			want:      true,
		},
		// Malformed or empty entries are skipped.
		{
			name:      "malformed endpoint",
			natType:   protocol.NATRestricted,
			endpoints: []string{"not-a-url"},
			want:      false,
		},
		{
			name:      "empty endpoint string",
			natType:   protocol.NATRestricted,
			endpoints: []string{""},
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			er := &protocol.EndpointRecord{
				NatType:   tc.natType,
				Endpoints: tc.endpoints,
			}
			got := isPublicHubCapable(er)
			if got != tc.want {
				t.Errorf("isPublicHubCapable(%+v) = %v, want %v", er, got, tc.want)
			}
		})
	}
}
