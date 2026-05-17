// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package updater

import (
	"os"
	"os/exec"
)

// restartProcess restarts the daemon with the new binary at exe.
//
// Windows does not support Unix-style execve (in-place process image
// replacement). The strategy differs by run mode:
//
//   - Service mode (SCM): os.Exit(0) — SCM detects process termination and
//     restarts with the updated binary. This is the standard Windows service
//     update pattern.
//
//   - Non-service mode: spawn the new binary with the same arguments and
//     inherit stdin/stdout/stderr, then exit the current process. In an
//     interactive terminal the new process continues in the same window.
//
// defer functions in the calling goroutine do NOT run after this call —
// callers must clean up any temp files before calling restartProcess.
func restartProcess(exe string) {
	if IsPersistentService() {
		// SCM service: let the service manager restart using its configured
		// restart policy. Do not spawn a child — SCM tracks the original PID.
		os.Exit(0)
	}

	// Non-service: spawn the updated binary before exiting so the daemon
	// resumes without user intervention.
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Start() // best-effort; if it fails, os.Exit(0) still cleans up
	os.Exit(0)
}
