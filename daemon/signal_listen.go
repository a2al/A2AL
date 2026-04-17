// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"strings"

	"github.com/a2al/a2al/config"
)

// resolveSignalListenAddr returns the TCP listen address for the embedded ICE hub,
// or empty string if disabled. Empty config or "off" both disable the hub.
func resolveSignalListenAddr(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	s := strings.TrimSpace(cfg.SignalListenAddr)
	if s == "" || strings.EqualFold(s, "off") {
		return ""
	}
	if strings.HasPrefix(s, ":") {
		return "0.0.0.0" + s
	}
	return s
}
