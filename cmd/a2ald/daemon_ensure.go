// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// ensureDaemon guarantees a daemon is serving the REST API at apiAddr, starting
// a detached one if needed.
//
// Why a plain background process rather than registering a service: the entry we
// just wrote is useless without a daemon, but registering with the system is a
// change the user did not ask for. A detached process is enough to make the
// current session work and costs nothing to undo; surviving logout is a separate
// decision, so it is only suggested (see persistenceHint).
//
// Not started here: anything that needs the caller's data directory to be free.
// If a daemon is already holding it, the probe finds it and we leave it alone.
func ensureDaemon(dataDir, apiAddr string) (started bool, err error) {
	apiURL := "http://" + apiAddr
	if probeHTTPDaemon(apiURL) {
		return false, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("cannot locate the a2ald binary: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return false, err
	}
	logPath := filepath.Join(dataDir, "a2ald-autostart.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return false, err
	}
	defer logFile.Close()

	cmd := exec.Command(exe, "-data-dir", dataDir, "-api-addr", apiAddr, "-no-open-browser") //nolint:gosec
	cmd.Stdout, cmd.Stderr = logFile, logFile
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return false, err
	}
	_ = cmd.Process.Release()

	// The API listener comes up long before the DHT does; waiting for the socket
	// is enough. Callers must not wait for a peer count.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if probeHTTPDaemon(apiURL) {
			return true, nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false, fmt.Errorf("daemon did not answer at %s within 15s (see %s)", apiAddr, logPath)
}

// persistenceHint names the one step that keeps the AID reachable across logins.
func persistenceHint() string {
	switch runtime.GOOS {
	case "windows", "darwin":
		return "this daemon stops when you log out; to keep the AID reachable: a2ald service install -user"
	default:
		return "this daemon stops when you log out; for a systemd unit see https://github.com/a2al/a2al/tree/main/deploy/linux"
	}
}
