// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package crypto

// Wipe overwrites b with zeros. Use in defer to clear sensitive key material.
// In practice the Go compiler does not eliminate these stores because callers
// pass slices that remain reachable via defer. If a future Go version proves
// more aggressive, replace with a runtime.KeepAlive(b) tail call or use
// golang.org/x/sys/unix.Mlock / crypto/subtle equivalents.
// TODO: revisit when Go provides an official "secure zero" intrinsic.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
