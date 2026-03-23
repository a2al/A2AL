// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"net"
	"testing"
)

func TestFormatParseObservedUDPv4(t *testing.T) {
	ip := net.ParseIP("192.168.1.2")
	b, err := FormatObservedUDP(ip, 5001)
	if err != nil {
		t.Fatal(err)
	}
	h, p, ok := ParseObservedUDP(b)
	if !ok || h != "192.168.1.2" || p != 5001 {
		t.Fatalf("got %s %d %v", h, p, ok)
	}
}
