// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package updater

import "golang.org/x/sys/windows/svc"

// IsPersistentService reports whether a2ald is running as a Windows SCM service
// (which has automatic restart on failure configured at install time).
// Task Scheduler tasks are NOT treated as persistent (no crash restart).
func IsPersistentService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}
