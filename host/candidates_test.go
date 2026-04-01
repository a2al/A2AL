// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"net"
	"testing"
)

func TestIsPlausibleWANIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"100.64.0.1", false},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"224.0.0.1", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := isPlausibleWANIP(ip); got != tt.want {
			t.Errorf("isPlausibleWANIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestAppendCandidateUnique_dedupes(t *testing.T) {
	seen := make(map[string]struct{})
	var out []string
	appendCandidateUnique(seen, &out, "quic://1.2.3.4:5000")
	appendCandidateUnique(seen, &out, "quic://1.2.3.4:5000")
	if len(out) != 1 {
		t.Fatalf("len out = %d, want 1", len(out))
	}
}
