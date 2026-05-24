// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package transport

import (
	"net"
	"testing"
)

func TestResolveListenAddr(t *testing.T) {
	cases := []struct {
		in      string
		network string
		out     string
	}{
		// Wildcard binds → dual-stack on [::]
		{":5001", "udp", "[::]:5001"},
		{"0.0.0.0:5001", "udp", "[::]:5001"},
		{"[::]:5001", "udp", "[::]:5001"},

		// Specific IPv4 → IPv4-only socket (preserves explicit-bind semantics)
		{"1.2.3.4:5001", "udp4", "1.2.3.4:5001"},
		{"127.0.0.1:0", "udp4", "127.0.0.1:0"},

		// Specific IPv6 → IPv6-only socket
		{"[2001:db8::1]:5001", "udp6", "[2001:db8::1]:5001"},
		{"[::1]:5001", "udp6", "[::1]:5001"},

		// Hostname (unresolvable here) → safe fallback to udp4
		{"localhost:5001", "udp4", "localhost:5001"},

		// Malformed (no port) → safe fallback to udp4
		{"not-an-addr", "udp4", "not-an-addr"},
	}
	for _, tc := range cases {
		gotNet, gotAddr := resolveListenAddr(tc.in)
		if gotNet != tc.network || gotAddr != tc.out {
			t.Errorf("resolveListenAddr(%q): got (%q, %q), want (%q, %q)",
				tc.in, gotNet, gotAddr, tc.network, tc.out)
		}
	}
}

func TestNormalizeUDPAddr(t *testing.T) {
	// IPv4-mapped IPv6 → unwrapped to 4-byte IPv4
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:1.2.3.4"), Port: 9}
	if len(mapped.IP) != net.IPv6len {
		t.Fatalf("test setup: expected 16-byte ::ffff: form, got %d", len(mapped.IP))
	}
	got := normalizeUDPAddr(mapped).(*net.UDPAddr)
	if len(got.IP) != net.IPv4len {
		t.Errorf("normalize did not unwrap v4-mapped: len=%d", len(got.IP))
	}
	if !got.IP.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("normalize wrong IP: %v", got.IP)
	}
	if got.Port != 9 {
		t.Errorf("normalize changed port: %d", got.Port)
	}

	// Plain IPv4 → unchanged
	v4 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9}
	if normalizeUDPAddr(v4) == nil {
		t.Errorf("normalize returned nil for plain v4")
	}

	// Pure IPv6 GUA → unchanged (To4() returns nil)
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9}
	gotV6 := normalizeUDPAddr(v6).(*net.UDPAddr)
	if !gotV6.IP.Equal(v6.IP) || len(gotV6.IP) != net.IPv6len {
		t.Errorf("normalize changed pure v6: got %v len=%d", gotV6.IP, len(gotV6.IP))
	}

	// Non-UDPAddr → returned as-is
	tcp := &net.TCPAddr{}
	if normalizeUDPAddr(tcp) != net.Addr(tcp) {
		t.Errorf("normalize altered non-UDP addr")
	}
}

func TestListenDualUDP_wildcard(t *testing.T) {
	c, err := ListenDualUDP(":0")
	if err != nil {
		t.Fatalf("ListenDualUDP wildcard: %v", err)
	}
	defer c.Close()
	// LocalAddr must be a *net.UDPAddr (so UDPMux can assert it freely)
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr is %T, want *net.UDPAddr", c.LocalAddr())
	}
	if la.Port == 0 {
		t.Errorf("expected OS-assigned port, got 0")
	}
}

func TestListenDualUDP_specificV4(t *testing.T) {
	c, err := ListenDualUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenDualUDP v4: %v", err)
	}
	defer c.Close()
	la := c.LocalAddr().(*net.UDPAddr)
	if la.IP.To4() == nil {
		t.Errorf("expected IPv4 bind, got %v", la.IP)
	}
}
