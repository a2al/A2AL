// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"net"
	"runtime"
	"strings"

	"github.com/a2al/a2al/config"
)

// resolveSignalListenAddr returns the TCP listen address for the embedded ICE hub,
// or empty string if disabled.
//
//   - Empty SignalListenAddr (default): derive port from cfg.ListenAddr.
//   - "off": explicitly disable the hub.
//   - ":port" form: expanded to platform wildcard (see below).
//   - Explicit address ("0.0.0.0:4121", "[::]:4121", etc.): returned as-is.
//
// Port-only expansion:
//   - Linux / macOS: "[::]:port" — dual-stack TCP socket.
//   - Windows: "0.0.0.0:port" — IPv4-only wildcard. Windows IPV6_V6ONLY=1 would
//     make "[::]:port" v6-only, silently breaking IPv4 clients (G8 fix).
func resolveSignalListenAddr(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	s := strings.TrimSpace(cfg.SignalListenAddr)
	if strings.EqualFold(s, "off") {
		return ""
	}
	if s == "" {
		// Derive port from ListenAddr (same port as DHT UDP).
		_, port, err := net.SplitHostPort(strings.TrimSpace(cfg.ListenAddr))
		if err != nil || port == "" || port == "0" {
			return ""
		}
		s = ":" + port
	}
	if strings.HasPrefix(s, ":") {
		if runtime.GOOS == "windows" {
			return "0.0.0.0" + s
		}
		return "[::]" + s
	}
	return s
}
