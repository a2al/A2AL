// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"io"
	"net"
	"testing"

	"log/slog"
)

func TestAddrToHostPort(t *testing.T) {
	if s := addrToHostPort(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5001}); s != "1.2.3.4:5001" {
		t.Fatalf("got %q", s)
	}
	if s := addrToHostPort(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 0}); s != "" {
		t.Fatalf("port 0: got %q", s)
	}
}

func TestResolveBootstrapAddrs(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	addrs := resolveBootstrapAddrs([]string{" 127.0.0.1:9 ", "", "not-a-hostname-that-will-never-resolve-xyz:1"}, log)
	if len(addrs) != 1 {
		t.Fatalf("want 1 valid addr, got %d", len(addrs))
	}
	ua, ok := addrs[0].(*net.UDPAddr)
	if !ok || ua.Port != 9 {
		t.Fatalf("addr: %#v", addrs[0])
	}
}
