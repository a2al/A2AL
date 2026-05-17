// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package updater

import (
	"os"
	"syscall"
)

// restartProcess replaces the current process image with the binary at exe
// using execve. The new binary starts fresh from main() with the same
// arguments and environment, preserving the same PID.
//
// This works correctly in both service and non-service modes:
//   - Service mode (systemd/launchd): new binary calls CheckAndRollback and
//     the watchdog, just as after a normal service restart. If the new binary
//     exits (watchdog timeout or os.Exit(2)), the service manager restarts it.
//   - Non-service mode: the daemon continues running in-place; no interruption
//     visible to users or callers. The terminal session and stdio are preserved.
//
// defer functions in the calling goroutine do NOT run after Exec — callers
// must clean up any temp files before calling restartProcess.
func restartProcess(exe string) {
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		// execve failed (very rare: permission, exec format error, etc.)
		// Fall back to a clean exit so the caller can react.
		os.Exit(0)
	}
	// syscall.Exec never returns on success.
}
