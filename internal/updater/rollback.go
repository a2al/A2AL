// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/internal/version"
)

// CheckAndRollback must be called at the very start of main(), before
// daemon.New() acquires the data-dir lock. It implements the startup-counter
// rollback described in the design doc.
//
// Guard chain (any failure → return, normal startup):
//  1. No state file or unreadable
//  2. Unknown schema
//  3. Dev build (version.Version == "dev")
//  4. state.NewVersion != version.Version  ← prevents false triggers
//  5. status != "pending"
//
// If attempts reaches 3 and .old is valid, the rollback is executed and
// os.Exit(0) is called so the service manager restarts with the old binary.
func CheckAndRollback(dataDir string) {
	state, err := ReadState(dataDir)
	if err != nil || state == nil {
		return
	}
	if state.Schema != stateSchema {
		return
	}
	if version.Version == "dev" {
		return
	}
	if state.NewVersion != version.Version {
		return
	}
	if state.Status != StatusPending {
		return
	}

	// Increment attempt counter first — before any other init.
	// If the binary crashes before reaching this point, the counter was never
	// incremented for this attempt. That is acceptable: the crash is caught
	// by the service manager restart, and on the next restart the counter
	// is incremented.
	state.Attempts++
	state.LastAttemptAt = time.Now()
	if err := WriteState(dataDir, state); err != nil {
		// Cannot reliably track state; proceed normally (fail-safe).
		return
	}

	if state.Attempts < 3 {
		return // give new binary more chances
	}

	// Three failed attempts — initiate rollback.
	exe, err := resolveExe()
	if err != nil {
		slog.Error("update rollback: cannot resolve executable path", "err", err)
		markRollbackFailed(dataDir, state)
		return
	}

	oldPath := oldBinaryPath(exe)
	if _, statErr := os.Stat(oldPath); statErr != nil {
		slog.Error("update rollback: .old binary not found, cannot rollback", "path", oldPath)
		markRollbackFailed(dataDir, state)
		return
	}

	// Verify .old checksum before restoring it.
	if state.OldChecksumSHA256 != "" {
		sum, hashErr := sha256File(oldPath)
		if hashErr != nil || sum != state.OldChecksumSHA256 {
			slog.Error("update rollback: .old binary checksum mismatch, refusing rollback",
				"expected", state.OldChecksumSHA256)
			markRollbackFailed(dataDir, state)
			return
		}
	}

	// Rename current → .failed (kept for diagnostics), .old → current.
	failedPath := exe + ".failed"
	if err := os.Rename(exe, failedPath); err != nil {
		slog.Error("update rollback: cannot rename current binary", "err", err)
		markRollbackFailed(dataDir, state)
		return
	}
	if err := os.Rename(oldPath, exe); err != nil {
		// Try to restore so the process can still run.
		_ = os.Rename(failedPath, exe)
		slog.Error("update rollback: cannot rename .old binary, attempted restore", "err", err)
		markRollbackFailed(dataDir, state)
		return
	}

	state.Status = StatusRolledBack
	state.RolledBackAt = time.Now()
	_ = WriteState(dataDir, state)

	slog.Info("update rollback: restored previous version",
		"from", state.NewVersion, "to", state.OldVersion)
	os.Exit(0) // service manager will restart with the old binary
}

// RunSmokeTest validates config parsing, keys, and data-dir writeability
// without starting the daemon or acquiring the data-dir lock. Called when
// a2ald is invoked as "__smoke-test --data-dir <path>" by the updater.
func RunSmokeTest(dataDir string) error {
	// 1. Verify data-dir is writable.
	probe := filepath.Join(dataDir, ".smoke-probe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		return err
	}
	_ = os.Remove(probe)

	// 2. Parse config.toml if it exists. This catches toml format regressions
	// and field-level validation errors introduced by the new binary.
	// Missing config.toml is fine — daemon.New() generates a default on first run.
	cfgPath := filepath.Join(dataDir, "config.toml")
	if _, err := os.Stat(cfgPath); err == nil {
		if _, err := config.LoadFile(cfgPath); err != nil {
			return err
		}
	}

	// 3. Key files, if present, must be readable (not corrupt/permission-locked).
	for _, name := range []string{"node.key", "node.pub"} {
		p := filepath.Join(dataDir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		f.Close()
	}

	return nil
}

// markRollbackFailed sets status to rollback_failed (terminal state) and logs.
func markRollbackFailed(dataDir string, state *UpdateState) {
	state.Status = StatusRollbackFailed
	_ = WriteState(dataDir, state)
	slog.Error("update: rollback failed — manual intervention required",
		"old_version", state.OldVersion, "new_version", state.NewVersion)
}

// resolveExe returns the real path of the current executable (follows symlinks).
func resolveExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// sha256File returns the hex-encoded SHA256 of a file.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
