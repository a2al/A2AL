// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	svcName        = "a2ald"
	svcLabel       = "org.a2al.a2ald" // macOS launchd label
	svcDisplayName = "A2AL Daemon"
	svcDescription = "A2AL peer-to-peer networking daemon for AI agents."
	svcTaskName    = "A2AL Daemon" // Windows Task Scheduler task name
)

func defaultDataDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "a2al")
}

// handleServiceCmd processes "a2ald service <subcmd> [flags]".
func handleServiceCmd(args []string) {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printServiceUsage()
		return
	}

	subcmd := args[0]

	fs := flag.NewFlagSet("a2ald service "+subcmd, flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory (embedded in service config at install time)")
	userMode := fs.Bool("user", false, "no-admin install (Windows: Task Scheduler; service stops on logout)")
	_ = fs.Parse(args[1:])

	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "a2ald service: cannot determine executable path:", err)
		os.Exit(1)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}

	switch subcmd {
	case "install":
		if err := svcInstall(exePath, *dataDir, *userMode); err != nil {
			fmt.Fprintln(os.Stderr, "a2ald service install:", err)
			os.Exit(1)
		}
	case "uninstall":
		if err := svcUninstall(exePath); err != nil {
			fmt.Fprintln(os.Stderr, "a2ald service uninstall:", err)
			os.Exit(1)
		}
	case "start":
		if err := svcStart(); err != nil {
			fmt.Fprintln(os.Stderr, "a2ald service start:", err)
			os.Exit(1)
		}
	case "stop":
		if err := svcStop(); err != nil {
			fmt.Fprintln(os.Stderr, "a2ald service stop:", err)
			os.Exit(1)
		}
	case "status":
		if err := svcStatus(); err != nil {
			fmt.Fprintln(os.Stderr, "a2ald service status:", err)
			os.Exit(1)
		}
	case "emit-script":
		if err := svcEmitScript(fs.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "a2ald service emit-script:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "a2ald: unknown service subcommand %q\n\n", subcmd)
		printServiceUsage()
		os.Exit(1)
	}
}

func printServiceUsage() {
	fmt.Fprintf(os.Stderr, `Usage: a2ald service <command> [flags]

Commands:
  install      Register and start a2ald as a persistent background service
  uninstall    Stop and remove the service registration
  start        Start an installed service
  stop         Stop a running service
  status       Show service status
  emit-script  Write install-service.ps1 to disk (Windows only)

Flags (install only):
  -data-dir <path>   Data directory (default: %s)
  -user              No-admin install (Windows only: uses Task Scheduler;
                     note: service stops when you log out)

Platform: %s
`, defaultDataDir(), runtime.GOOS)
}
