// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package updater

import "os"

// IsPersistentService reports whether a2ald is running under a service manager
// that will automatically restart it on failure.
//
// Linux: systemd sets INVOCATION_ID (v232+) and JOURNAL_STREAM (v231+).
// macOS:  launchd is PID 1 and does not set TERM for background agents.
// Other:  always returns false.
func IsPersistentService() bool {
	// Linux / systemd
	if os.Getenv("INVOCATION_ID") != "" || os.Getenv("JOURNAL_STREAM") != "" {
		return true
	}
	// macOS / launchd: parent is PID 1 and no terminal session
	if os.Getppid() == 1 && os.Getenv("TERM") == "" {
		return true
	}
	return false
}
