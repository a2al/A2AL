// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build !windows && !darwin

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/a2al/a2al/daemon"
)

func isRunningAsService() bool          { return false }
func runServiceMain(_ *daemon.Daemon) error { return nil }

func svcInstall(_ string, _ string, _ bool) error {
	fmt.Fprintln(os.Stderr, "a2ald: automatic service installation is not available on this platform.")
	fmt.Fprintln(os.Stderr, "  Linux: see https://github.com/a2al/a2al/tree/main/deploy/linux")
	return errors.New("not supported on this platform")
}

func svcUninstall(_ string) error {
	fmt.Println("a2ald: use your system's service manager to uninstall (e.g. systemctl disable --now a2ald).")
	return nil
}

func svcStart() error {
	fmt.Println("a2ald: use your system's service manager (e.g. systemctl start a2ald).")
	return nil
}

func svcStop() error {
	fmt.Println("a2ald: use your system's service manager (e.g. systemctl stop a2ald).")
	return nil
}

func svcEmitScript(_ string) error {
	return fmt.Errorf("emit-script is only available on Windows")
}

func svcStatus() error {
	fmt.Println("a2ald: use your system's service manager (e.g. systemctl status a2ald).")
	return nil
}
