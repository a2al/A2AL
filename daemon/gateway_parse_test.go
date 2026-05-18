// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import "testing"

func TestParseServiceTCP(t *testing.T) {
	tests := []struct {
		raw        string
		wantScheme string
		wantAddr   string
	}{
		{"https://example.com:8443/path", "https", "example.com:8443/path"},
		{"http://127.0.0.1:8080", "http", "127.0.0.1:8080"},
		{"127.0.0.1:9999", "tcp", "127.0.0.1:9999"},
		{"localhost", "tcp", "localhost"},
	}
	for _, tc := range tests {
		scheme, addr := parseServiceTCP(tc.raw)
		if scheme != tc.wantScheme || addr != tc.wantAddr {
			t.Fatalf("parseServiceTCP(%q) = (%q,%q) want (%q,%q)",
				tc.raw, scheme, addr, tc.wantScheme, tc.wantAddr)
		}
	}
}
