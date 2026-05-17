// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package updater

import "os"

// oldBinaryPath returns the path where the pre-update binary is saved.
func oldBinaryPath(exe string) string { return exe + ".old" }

// atomicReplace renames current → current.old, then new → current.
// On Linux/macOS, os.Rename is atomic within the same filesystem.
func atomicReplace(currentExe, newExe string) error {
	oldExe := oldBinaryPath(currentExe)
	// Overwrite any existing .old (previous update's old binary).
	if err := os.Rename(currentExe, oldExe); err != nil {
		return err
	}
	if err := os.Rename(newExe, currentExe); err != nil {
		_ = os.Rename(oldExe, currentExe) // restore
		return err
	}
	return nil
}
