// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import "errors"

// DialOptions carries per-call dialing preferences for outbound connections.
// The zero value represents the default behaviour (relay allowed).
type DialOptions struct {
	// DisableRelay prevents relay (TURN) candidates from being used for this
	// connection attempt. When true and direct connectivity fails,
	// ErrRelayRequired is returned so the caller can decide whether to retry
	// with relay enabled.
	DisableRelay bool
}

// ErrRelayRequired is returned when a direct connection could not be
// established and relay was either explicitly disabled (DisableRelay=true) or
// not available (no TURN servers configured). The application layer may use
// this to prompt the user or retry with relay enabled.
var ErrRelayRequired = errors.New("a2al/host: relay required but not available")
