// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build darwin

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
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

// agentInstallDir returns the stable binary location: ~/Library/Application Support/A2AL.
// The plist always points here so the LaunchAgent survives moving or deleting the
// original download.
func agentInstallDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "A2AL"), nil
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

// isRunningAsService reports whether a2ald should run the Windows SCM event loop.
// Always false on macOS; launchd manages process lifecycle directly.
// Persistent-service detection for status/update is in updater.IsPersistentService.
func isRunningAsService() bool { return false }

// runServiceMain is never called on macOS (launchd starts the process directly).
func runServiceMain(_ *daemon.Daemon) error { return nil }

func svcInstall(exePath, dataDir string, _ bool) error {
	installDir, err := agentInstallDir()
	if err != nil {
		return err
	}
	destExe := filepath.Join(installDir, "a2ald")

	pp, err := agentPlistPath()
	if err != nil {
		return err
	}
	lp, err := agentLogPath()
	if err != nil {
		return err
	}

	// 1. Idempotency: already installed from the stable location.
	if darwinSameFile(exePath, destExe) && darwinFileExists(pp) {
		fmt.Println("a2ald: already installed as LaunchAgent.")
		fmt.Println("  Use 'a2ald service status/stop/start' to manage.")
		return nil
	}

	// 2. Confirm if replacing an existing registration.
	if darwinFileExists(pp) {
		if darwinIsTerminal() {
			fmt.Printf("a2ald is already installed as LaunchAgent. Reinstall? [y/N]: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.ToLower(strings.TrimSpace(line)) != "y" {
				return fmt.Errorf("cancelled")
			}
		} else {
			return fmt.Errorf("already-installed: LaunchAgent is already registered; to upgrade use 'a2ald update'")
		}
	}

	// 3. Copy binary to stable location (atomic: write to .tmp, then rename).
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return fmt.Errorf("create install dir: %w", err)
	}
	if err := darwinCopyExe(exePath, destExe); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}

	// 4. Write plist (points to stable destExe).
	if err := os.MkdirAll(filepath.Dir(pp), 0o755); err != nil {
		os.Remove(destExe)
		os.Remove(installDir)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(lp), 0o755); err != nil {
		os.Remove(destExe)
		os.Remove(installDir)
		return err
	}
	t := template.Must(template.New("plist").Parse(plistTmpl))
	var buf bytes.Buffer
	if err := t.Execute(&buf, plistData{svcLabel, destExe, dataDir, lp}); err != nil {
		os.Remove(destExe)
		os.Remove(installDir)
		return err
	}
	if err := os.WriteFile(pp, buf.Bytes(), 0o644); err != nil {
		os.Remove(destExe)
		os.Remove(installDir)
		return err
	}

	// 5. Load agent (unload any previous registration first).
	_ = exec.Command("launchctl", "unload", pp).Run()
	if out, err := exec.Command("launchctl", "load", pp).CombinedOutput(); err != nil {
		// Rollback: remove plist and copied binary.
		os.Remove(pp)
		os.Remove(destExe)
		os.Remove(installDir)
		return fmt.Errorf("launchctl load: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	fmt.Println("a2ald: installed and started as LaunchAgent.")
	fmt.Printf("  Installed at: %s\n", installDir)
	fmt.Printf("  Data:         %s\n", dataDir)
	fmt.Printf("  Logs:         %s\n", lp)
	fmt.Println("  Web UI:       http://127.0.0.1:2121/")
	fmt.Println("  MCP:          http://127.0.0.1:2121/mcp/")
	if !darwinSameFile(exePath, destExe) {
		fmt.Printf("  Source binary (%s) can now be deleted.\n", exePath)
	}
	return nil
}

func svcUninstall(_ string) error {
	pp, err := agentPlistPath()
	if err != nil {
		return err
	}
	if !darwinFileExists(pp) {
		return fmt.Errorf("not-installed: LaunchAgent is not registered")
	}

	// Stop and unregister (tolerate unload errors — agent may already be stopped).
	_ = exec.Command("launchctl", "unload", pp).Run()
	if err := os.Remove(pp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}

	// Remove installed binary and directory (no-op if already gone or non-empty).
	if installDir, err := agentInstallDir(); err == nil {
		os.Remove(filepath.Join(installDir, "a2ald"))
		os.Remove(installDir)
	}

	fmt.Println("a2ald: LaunchAgent removed.")
	return nil
}

// svcStart reloads the plist — equivalent to start for a KeepAlive LaunchAgent.
func svcStart() error {
	pp, err := agentPlistPath()
	if err != nil {
		return err
	}
	if !darwinFileExists(pp) {
		return fmt.Errorf("not-installed: run 'a2ald service install' first")
	}
	out, err := exec.Command("launchctl", "load", pp).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "already loaded") {
			fmt.Println("a2ald: service is already running.")
			return nil
		}
		return fmt.Errorf("launchctl load: %w: %s", err, msg)
	}
	fmt.Println("a2ald: started.")
	return nil
}

// svcStop unloads the plist without deleting it (stopped until manual start or reboot).
func svcStop() error {
	pp, err := agentPlistPath()
	if err != nil {
		return err
	}
	if !darwinFileExists(pp) {
		return fmt.Errorf("not-installed: run 'a2ald service install' first")
	}
	if out, err := exec.Command("launchctl", "unload", pp).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl unload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("a2ald: stopped.")
	return nil
}

func svcEmitScript(_ string) error {
	return fmt.Errorf("emit-script is only available on Windows")
}

func svcStatus() error {
	pp, err := agentPlistPath()
	if err != nil {
		return err
	}
	out, err := exec.Command("launchctl", "list", svcLabel).CombinedOutput()
	if err != nil {
		if !darwinFileExists(pp) {
			fmt.Println("a2ald: not installed — run 'a2ald service install'")
		} else {
			fmt.Println("a2ald: LaunchAgent registered but not loaded — run 'a2ald service start'")
		}
		return nil
	}
	fmt.Printf("LaunchAgent (%s):\n%s\n", svcLabel, strings.TrimSpace(string(out)))
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func darwinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func darwinFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// darwinSameFile returns true if a and b point to the same file after symlink resolution.
func darwinSameFile(a, b string) bool {
	ra, ea := filepath.EvalSymlinks(a)
	rb, eb := filepath.EvalSymlinks(b)
	if ea != nil || eb != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return filepath.Clean(ra) == filepath.Clean(rb)
}

// darwinCopyExe copies src to dst atomically (via .tmp rename) with executable permissions.
func darwinCopyExe(src, dst string) error {
	if darwinSameFile(src, dst) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
