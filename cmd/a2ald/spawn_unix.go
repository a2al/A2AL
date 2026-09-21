// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detach makes the spawned daemon outlive the process that started it: a new
// session means the caller's terminal hangup or the MCP client exiting does not
// signal the daemon.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
