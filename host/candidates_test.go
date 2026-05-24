// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"net"
	"strconv"
	"testing"
)

func TestIsPlausibleWANIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
		desc string
	}{
		// IPv4
		{"8.8.8.8", true, "public v4"},
		{"192.168.1.1", false, "RFC 1918 private"},
		{"10.0.0.1", false, "RFC 1918 private"},
		{"172.16.0.1", false, "RFC 1918 private"},
		{"100.64.0.1", false, "RFC 6598 CGNAT"},
		{"127.0.0.1", false, "loopback"},
		{"169.254.1.1", false, "link-local"},
		{"224.0.0.1", false, "multicast"},
		// IPv6 — allowed
		{"2001:db8::1", true, "GUA (2001:db8 doc prefix, passes as GUA)"},
		{"2606:4700::1", true, "Cloudflare GUA"},
		// IPv6 — rejected
		{"fe80::1", false, "link-local"},
		{"fc00::1", false, "ULA"},
		{"fd00::1", false, "ULA"},
		{"::1", false, "loopback"},
		{"2001:0000::1", false, "Teredo 2001::/32"},
		{"2001:0000:1234::1", false, "Teredo 2001::/32"},
		{"2002::1", false, "6to4 2002::/16"},
		{"2002:c000:0204::1", false, "6to4 2002::/16 with embedded v4"},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tt.ip)
		}
		if got := isPlausibleWANIP(ip); got != tt.want {
			t.Errorf("isPlausibleWANIP(%s) [%s] = %v, want %v", tt.ip, tt.desc, got, tt.want)
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

// TestOrderedQUICEndpointStrings_v6Paths verifies that the v6-specific paths in
// orderedQUICEndpointStrings produce correct quic:// candidates without touching
// the network (all v6 inputs are injected as snapshots).
func TestOrderedQUICEndpointStrings_v6Paths(t *testing.T) {
	ks := newMemKS(t)
	h, err := New(Config{
		KeyStore: ks, ListenAddr: "127.0.0.1:0", QUICListenAddr: "127.0.0.1:0",
		PrivateKey: ks.priv, MinObservedPeers: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })

	port := strconv.Itoa(h.QUICLocalAddr().Port)

	t.Run("v6_stun_snapshot_only", func(t *testing.T) {
		// ② v6 STUN snapshot should appear as a quic:// candidate.
		eps, err := h.orderedQUICEndpointStrings("", "[2001:db8::1]:54321", "")
		if err != nil {
			t.Fatal(err)
		}
		want := "quic://[2001:db8::1]:" + port
		for _, ep := range eps {
			if ep == want {
				return
			}
		}
		t.Errorf("v6 STUN snapshot %q not found in %v", want, eps)
	})

	t.Run("v4_and_v6_stun_both_included", func(t *testing.T) {
		// Both IPv4 and IPv6 STUN snapshots should appear in output.
		eps, err := h.orderedQUICEndpointStrings("1.2.3.4:11111", "[2001:db8::2]:22222", "")
		if err != nil {
			t.Fatal(err)
		}
		wantV4 := "quic://1.2.3.4:" + port
		wantV6 := "quic://[2001:db8::2]:" + port
		hasV4, hasV6 := false, false
		for _, ep := range eps {
			switch ep {
			case wantV4:
				hasV4 = true
			case wantV6:
				hasV6 = true
			}
		}
		if !hasV4 {
			t.Errorf("IPv4 STUN candidate %q missing from %v", wantV4, eps)
		}
		if !hasV6 {
			t.Errorf("IPv6 STUN candidate %q missing from %v", wantV6, eps)
		}
	})

	t.Run("v6_stun_deduped_against_itself", func(t *testing.T) {
		// appendCandidateUnique must prevent the same v6 address appearing twice
		// even if multiple sources (e.g. STUN ② and natsense ①) agree on it.
		eps, err := h.orderedQUICEndpointStrings("", "[2001:db8::3]:99", "")
		if err != nil {
			t.Fatal(err)
		}
		wantV6 := "quic://[2001:db8::3]:" + port
		count := 0
		for _, ep := range eps {
			if ep == wantV6 {
				count++
			}
		}
		if count != 1 {
			t.Errorf("v6 candidate %q appears %d times (want 1) in %v", wantV6, count, eps)
		}
	})

	t.Run("empty_v6_snapshot_does_not_produce_candidate", func(t *testing.T) {
		// With no FallbackHost and empty v6 snapshot, must either succeed via v4
		// or return an error — never produce a v6 candidate from nothing.
		eps, _ := h.orderedQUICEndpointStrings("203.0.113.1:1234", "", "")
		for _, ep := range eps {
			if ep == "quic://[::]:"+port || ep == "quic://:"+port {
				t.Errorf("unexpected zero-IP v6 candidate in %v", eps)
			}
		}
	})
}
