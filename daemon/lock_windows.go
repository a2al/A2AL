// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

// acquireDataDirLock creates an exclusive OS-level lock on <dataDir>/daemon.lock
// using LockFileEx. The lock is automatically released when the file is closed
// or the process exits. It also writes the current PID for diagnostics.
func acquireDataDirLock(dataDir string) (*os.File, error) {
	lockPath := filepath.Join(dataDir, "daemon.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("daemon: open lock file: %w", err)
	}

	ol := new(windows.Overlapped)
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol,
	)
	if err != nil {
		pid := readLockPID(lockPath)
		f.Close()
		if err == windows.ERROR_LOCK_VIOLATION {
			return nil, buildLockError(dataDir, pid)
		}
		return nil, fmt.Errorf("daemon: LockFileEx %s: %w", lockPath, err)
	}

	// Write PID so a failing second instance can show a helpful message.
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	return f, nil
}

func readLockPID(lockPath string) string {
	b, err := os.ReadFile(lockPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func buildLockError(dataDir, pid string) error {
	pidInfo := ""
	if pid != "" {
		pidInfo = " (PID " + pid + ")"
	}
	return fmt.Errorf(
		"data directory %q is already in use by another a2ald process%s.\n"+
			"  To stop it:\n"+
			"    a2ald service stop            (if installed as a service)\n"+
			"    taskkill /PID %s /F            (manual, Task Manager also works)\n"+
			"  Or use a separate data directory: -data-dir <path>",
		dataDir, pidInfo, pidOrPlaceholder(pid),
	)
}

func pidOrPlaceholder(pid string) string {
	if pid != "" {
		return pid
	}
	return "<PID>"
}
