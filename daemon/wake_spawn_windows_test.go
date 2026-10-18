// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package daemon

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHideWakeWindow_createNoWindow(t *testing.T) {
	cmd := exec.Command("node.exe")
	hideWakeWindow(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("flags %#x", cmd.SysProcAttr.CreationFlags)
	}
}
