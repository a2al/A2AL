// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package updater

import "os"

// oldBinaryPath returns the path where the pre-update binary is saved.
// On Windows the running .exe can be renamed (but not deleted/overwritten).
func oldBinaryPath(exe string) string { return exe + ".old" }

// atomicReplace on Windows:
//  1. Remove any pre-existing .old (it is not running, so deletion is allowed).
//  2. Rename current.exe → current.exe.old  (rename of running exe is allowed).
//  3. Rename new.exe    → current.exe       (creates a fresh file at the original path).
//
// On the next startup, CheckAndRollback checks for .old and rolls back if needed.
func atomicReplace(currentExe, newExe string) error {
	oldExe := oldBinaryPath(currentExe)
	_ = os.Remove(oldExe) // remove previous update's .old if present (not running, safe)
	if err := os.Rename(currentExe, oldExe); err != nil {
		return err
	}
	if err := os.Rename(newExe, currentExe); err != nil {
		_ = os.Rename(oldExe, currentExe) // restore
		return err
	}
	return nil
}
