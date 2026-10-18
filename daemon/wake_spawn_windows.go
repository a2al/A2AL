// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package daemon

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func hideWakeWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// CREATE_NO_WINDOW: windowless console session for a console PE
	// started from a daemon. SW_HIDE still allocates a console and can
	// trip the Windows 11 default-terminal picker. Do not wrap .cmd/.bat
	// in cmd.exe; bind the underlying PE instead.
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NO_WINDOW
}
