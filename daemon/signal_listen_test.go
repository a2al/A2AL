// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"runtime"
	"testing"

	"github.com/a2al/a2al/config"
)

func TestResolveSignalListenAddr(t *testing.T) {
	// portOnlyWant reflects the platform-specific expansion of a port-only
	// address form (":port"). On Windows the result is "0.0.0.0:port" to
	// preserve IPv4 baseline; on other platforms it is "[::]:port" for
	// dual-stack listening (G8 fix).
	portOnlyWant4121 := "[::]:4121"
	portOnlyWant0 := "[::]:0"
	if runtime.GOOS == "windows" {
		portOnlyWant4121 = "0.0.0.0:4121"
		portOnlyWant0 = "0.0.0.0:0"
	}

	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{name: "nil config", cfg: nil, want: ""},
		// "off" and case variants → disabled.
		{name: "off", cfg: &config.Config{SignalListenAddr: "off"}, want: ""},
		{name: "OFF uppercase", cfg: &config.Config{SignalListenAddr: "OFF"}, want: ""},

		// Empty SignalListenAddr → derive port from ListenAddr.
		{name: "empty derives from ListenAddr", cfg: &config.Config{SignalListenAddr: "", ListenAddr: ":4121"}, want: portOnlyWant4121},
		{name: "whitespace derives from ListenAddr", cfg: &config.Config{SignalListenAddr: "  ", ListenAddr: ":4121"}, want: portOnlyWant4121},
		// Empty ListenAddr (or port 0) → cannot derive → disabled.
		{name: "empty addr no ListenAddr", cfg: &config.Config{SignalListenAddr: ""}, want: ""},
		{name: "empty addr port 0", cfg: &config.Config{SignalListenAddr: "", ListenAddr: ":0"}, want: ""},

		// Port-only form: platform-dependent expansion (see portOnlyWant above).
		{name: "port only :4121", cfg: &config.Config{SignalListenAddr: ":4121"}, want: portOnlyWant4121},
		{name: "port only :0", cfg: &config.Config{SignalListenAddr: ":0"}, want: portOnlyWant0},

		// Explicit addresses are returned as-is regardless of platform.
		{name: "explicit v4", cfg: &config.Config{SignalListenAddr: "0.0.0.0:4121"}, want: "0.0.0.0:4121"},
		{name: "explicit v4 ip", cfg: &config.Config{SignalListenAddr: "1.2.3.4:9000"}, want: "1.2.3.4:9000"},
		{name: "explicit v6", cfg: &config.Config{SignalListenAddr: "[::]:4121"}, want: "[::]:4121"},
		{name: "explicit v6 gua", cfg: &config.Config{SignalListenAddr: "[2001:db8::1]:4121"}, want: "[2001:db8::1]:4121"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveSignalListenAddr(tc.cfg)
			if got != tc.want {
				addr := "<nil>"
				if tc.cfg != nil {
					addr = tc.cfg.SignalListenAddr
				}
				t.Errorf("resolveSignalListenAddr(%q) = %q, want %q", addr, got, tc.want)
			}
		})
	}
}
