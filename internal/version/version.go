// Copyright 2026 The A2AL Authors, XG.Shi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package version

import "runtime/debug"

// Injected at build time via -ldflags (e.g. GoReleaser).
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

const Copyright = "Copyright 2026 The A2AL Authors. Licensed under MPL-2.0. https://a2al.org"

// vcsInfo reads VCS metadata embedded by the Go toolchain (requires -buildvcs=true, the default).
func vcsInfo() (revision, date string, modified bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", "", false
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			date = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	return
}

func commitDisplay() string {
	if Commit != "" && Commit != "unknown" {
		return Commit
	}
	rev, _, dirty := vcsInfo()
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		rev = rev[:7]
	}
	if dirty {
		rev += "+dirty"
	}
	return rev
}

func buildDateDisplay() string {
	if BuildDate != "" && BuildDate != "unknown" {
		return BuildDate
	}
	_, t, _ := vcsInfo()
	if t == "" {
		return "unknown"
	}
	return t
}

// String returns a single-line version string suitable for --version output.
func String(name string) string {
	return name + " " + Version + " (commit: " + commitDisplay() + ", built: " + buildDateDisplay() + ")\n" + Copyright
}

// Banner returns a compact startup banner for daemon use.
func Banner(name, description string) string {
	return name + " " + Version + " (" + commitDisplay() + ") - " + description + "\n" + Copyright
}
