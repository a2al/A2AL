// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build darwin

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/a2al/a2al/daemon"
)

const plistTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Label}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.ExePath}}</string>
        <string>-data-dir</string>
        <string>{{.DataDir}}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{{.LogPath}}</string>
    <key>StandardErrorPath</key>
    <string>{{.LogPath}}</string>
</dict>
</plist>
`

type plistData struct {
	Label, ExePath, DataDir, LogPath string
}

func agentPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", svcLabel+".plist"), nil
}

func agentLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Logs", "a2ald.log"), nil
}

// isRunningAsService is always false on macOS (no SCM equivalent).
func isRunningAsService() bool { return false }

// runServiceMain is never called on macOS.
func runServiceMain(_ *daemon.Daemon) error { return nil }

func svcInstall(exePath, dataDir string, _ bool) error {
	pp, err := agentPlistPath()
	if err != nil {
		return err
	}
	lp, err := agentLogPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(pp), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(lp), 0o755); err != nil {
		return err
	}

	t := template.Must(template.New("plist").Parse(plistTmpl))
	var buf bytes.Buffer
	if err := t.Execute(&buf, plistData{svcLabel, exePath, dataDir, lp}); err != nil {
		return err
	}
	if err := os.WriteFile(pp, buf.Bytes(), 0o644); err != nil {
		return err
	}

	// Unload first in case already registered (tolerate error).
	_ = exec.Command("launchctl", "unload", pp).Run()

	out, err := exec.Command("launchctl", "load", pp).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl load: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("a2ald: installed and started as LaunchAgent.")
	fmt.Println("  Plist:", pp)
	fmt.Println("  Logs: ", lp)
	fmt.Println("  MCP:   http://127.0.0.1:2121/mcp/")
	return nil
}

func svcUninstall(_ bool) error {
	pp, err := agentPlistPath()
	if err != nil {
		return err
	}
	if out, err := exec.Command("launchctl", "unload", pp).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "launchctl unload: %v: %s\n", err, strings.TrimSpace(string(out)))
	}
	if err := os.Remove(pp); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Println("a2ald: LaunchAgent removed.")
	return nil
}

// svcStart reloads the plist (equivalent to start for a KeepAlive agent).
func svcStart() error {
	pp, err := agentPlistPath()
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(pp); os.IsNotExist(statErr) {
		return fmt.Errorf("not installed; run 'a2ald service install' first")
	}
	out, err := exec.Command("launchctl", "load", pp).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl load: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("a2ald: started.")
	return nil
}

// svcStop unloads the plist (stops without deleting it).
func svcStop() error {
	pp, err := agentPlistPath()
	if err != nil {
		return err
	}
	out, err := exec.Command("launchctl", "unload", pp).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl unload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("a2ald: stopped. (run 'a2ald service start' to restart)")
	return nil
}

func svcStatus() error {
	out, err := exec.Command("launchctl", "list", svcLabel).CombinedOutput()
	if err != nil {
		fmt.Println("a2ald: not loaded.")
		pp, _ := agentPlistPath()
		if _, statErr := os.Stat(pp); os.IsNotExist(statErr) {
			fmt.Println("  Run 'a2ald service install' to install.")
		} else {
			fmt.Println("  Plist exists but agent is not loaded. Run 'a2ald service start'.")
		}
		return nil
	}
	fmt.Printf("LaunchAgent (%s):\n%s\n", svcLabel, strings.TrimSpace(string(out)))
	return nil
}
