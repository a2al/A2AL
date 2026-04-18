// Copyright 2026 The A2AL Authors, XG.Shi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"runtime/debug"
	"strings"
)

// Injected at build time via -ldflags (e.g. GoReleaser).
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

const Copyright = "Copyright 2026 The A2AL Authors, XG.Shi. Licensed under MPL-2.0."

// commitDisplay returns ldflags Commit, or VCS revision from the binary (local go build).
func commitDisplay() string {
	if Commit != "" && Commit != "unknown" {
		return Commit
	}
	rev, _ := vcsFromBuildInfo()
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		return rev[:7]
	}
	return rev
}

// buildDateDisplay returns ldflags BuildDate, or vcs.time from the binary.
func buildDateDisplay() string {
	if BuildDate != "" && BuildDate != "unknown" {
		return BuildDate
	}
	_, t := vcsFromBuildInfo()
	if t == "" {
		return "unknown"
	}
	return t
}

func vcsFromBuildInfo() (revision, time string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", ""
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			time = s.Value
		}
	}
	return revision, time
}

// String returns a single-line version string suitable for --version output.
func String(name string) string {
	return name + " " + Version + " (commit: " + commitDisplay() + ", built: " + buildDateDisplay() + ")\n" + Copyright
}

// Banner returns a compact startup banner for daemon use.
func Banner(name, description string) string {
	return name + " " + Version + " (" + commitDisplay() + ") - " + description + "\n" + Copyright
}

// Dirty returns whether the working tree had uncommitted changes at build time (when embedded).
func Dirty() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.modified" && strings.EqualFold(s.Value, "true") {
			return true
		}
	}
	return false
}
