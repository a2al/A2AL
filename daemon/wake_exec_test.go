// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/a2al/a2al/config"
)

func TestRejectWakeShell(t *testing.T) {
	for _, cmd := range []string{"bash", "/bin/sh", `C:\Windows\System32\cmd.exe`, "powershell.exe", "pwsh"} {
		if err := rejectWakeShell(cmd); err != errWakeShell {
			t.Fatalf("%s: %v", cmd, err)
		}
	}
	if err := rejectWakeShell(filepath.Join("tools", "a2al-wake-helper")); err != nil {
		t.Fatal(err)
	}
}

func TestResolveWakeCmd(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wake-helper")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveWakeCmd(p)
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("empty resolved")
	}
	if _, err := resolveWakeCmd(filepath.Join(dir, "missing")); err != errWakeCmdMissing {
		t.Fatalf("missing: %v", err)
	}
	if _, err := resolveWakeCmd(""); err != errWakeCmdEmpty {
		t.Fatalf("empty: %v", err)
	}
	if _, err := resolveWakeCmd(dir); err != errWakeCmdDir {
		t.Fatalf("dir: %v", err)
	}
}

func TestAuthorizeWakeCmd_allowList(t *testing.T) {
	dir := t.TempDir()
	okPath := filepath.Join(dir, "ok-helper")
	other := filepath.Join(dir, "other-helper")
	for _, p := range []string{okPath, other} {
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	d := &Daemon{cfg: &config.Config{}}
	if err := d.authorizeWakeCmd(okPath); err != nil {
		t.Fatalf("empty list: %v", err)
	}
	d.cfg.Wake.AllowedCmds = []string{okPath}
	if err := d.authorizeWakeCmd(okPath); err != nil {
		t.Fatal(err)
	}
	if err := d.authorizeWakeCmd(other); err != errWakeNotAllowed {
		t.Fatalf("other: %v", err)
	}
}

func TestNormalizeWakeVia(t *testing.T) {
	v, err := normalizeWakeVia("")
	if err != nil || v != "exec" {
		t.Fatalf("%q %v", v, err)
	}
	v, err = normalizeWakeVia("acp")
	if err != nil || v != "acp" {
		t.Fatalf("acp: %q %v", v, err)
	}
	if _, err := normalizeWakeVia("ssh"); err != errWakeVia {
		t.Fatalf("ssh: %v", err)
	}
}
