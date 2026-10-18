// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package daemon

import "os/exec"

func hideWakeWindow(cmd *exec.Cmd) {}
