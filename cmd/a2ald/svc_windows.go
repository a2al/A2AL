// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/a2al/a2al/daemon"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

// installServicePS1 is the content written by "a2ald service emit-script".
// It is a thin adapter that locates a2ald.exe and calls it to do the actual work.
const installServicePS1 = `#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs a2ald as a persistent Windows Service.
.PARAMETER DataDir
    Data directory for a2ald. Defaults to %APPDATA%\a2al.
.PARAMETER Uninstall
    Remove the service instead of installing it.
#>
param(
    [string]$DataDir = "",
    [switch]$Uninstall
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Find a2ald.exe: check next to this script first, then PATH.
$exe = Join-Path $PSScriptRoot "a2ald.exe"
if (-not (Test-Path $exe)) {
    $found = Get-Command a2ald.exe -ErrorAction SilentlyContinue
    if ($found) { $exe = $found.Source }
    else {
        Write-Error "a2ald.exe not found next to this script or in PATH."
        exit 1
    }
}

$installArgs = @("service")
if ($Uninstall) {
    $installArgs += "uninstall"
} else {
    $installArgs += "install"
    if ($DataDir) { $installArgs += @("-data-dir", $DataDir) }
}
& $exe @installArgs
exit $LASTEXITCODE
`

// isRunningAsService reports whether the binary was started by the Windows SCM.
func isRunningAsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// a2alSvc wraps a Daemon to satisfy the svc.Handler interface.
type a2alSvc struct{ d *daemon.Daemon }

func (s *a2alSvc) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.d.Run(ctx, false) }()

	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case <-done:
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		}
	}
}

// runServiceMain runs d as a Windows SCM service; blocks until stopped.
func runServiceMain(d *daemon.Daemon) error {
	return svc.Run(svcName, &a2alSvc{d: d})
}

// ── Install ───────────────────────────────────────────────────────────────────

// errNeedElevation is returned when SCM operations require administrator rights.
// It is the only condition that triggers an interactive elevation prompt or
// the requires-admin message. Other errors propagate as-is.
var errNeedElevation = errors.New("administrator access required")

// svcInstall is the entry point for "a2ald service install".
func svcInstall(exePath, dataDir string, userMode bool) error {
	if userMode {
		return svcInstallTask(exePath, dataDir)
	}
	err := svcInstallSCM(exePath, dataDir)
	if err == nil {
		return nil
	}
	if !errors.Is(err, errNeedElevation) {
		return err
	}
	if !isStdinTerminal() {
		fmt.Fprintln(os.Stderr, "a2ald: requires-admin — administrator access required to install as Windows Service.")
		fmt.Fprintln(os.Stderr, "  Open an Administrator terminal and run: a2ald service install")
		fmt.Fprintln(os.Stderr, "  Or right-click install-service.ps1 → Run as Administrator")
		fmt.Fprintln(os.Stderr, "  No-admin fallback (stops on logout): a2ald service install --user")
		return errNeedElevation
	}
	return promptInstallChoice(exePath, dataDir)
}

// promptInstallChoice shows the interactive 1/2 menu when admin is unavailable.
func promptInstallChoice(exePath, dataDir string) error {
	fmt.Println("Administrator access required. Choose an install option:")
	fmt.Println()
	fmt.Println("  [1] System Service — fully persistent, survives reboot (recommended)")
	fmt.Println("        A new window will open requesting administrator access.")
	fmt.Println()
	fmt.Println("  [2] Task Scheduler — no admin required, runs while logged in")
	fmt.Println("        Note: agents go offline if you log out or restart.")
	fmt.Println()
	fmt.Print("Choice [1/2, q to quit]: ")

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr)
		return fmt.Errorf("cancelled")
	}
	switch strings.TrimSpace(line) {
	case "1":
		fmt.Println("a2ald: launching elevated installer — a UAC prompt will appear...")
		if err := elevateAndRun(exePath, []string{"install", "-data-dir", dataDir}); err != nil {
			return err
		}
		fmt.Println("a2ald: installed successfully as Windows Service.")
		fmt.Println("  Run 'a2ald service status' to verify, or open services.msc.")
		fmt.Println("  Web UI:  http://127.0.0.1:2121/")
		fmt.Println("  MCP:     http://127.0.0.1:2121/mcp/")
		return nil
	case "2":
		return svcInstallTask(exePath, dataDir)
	default:
		return fmt.Errorf("cancelled")
	}
}

// elevateAndRun re-runs "a2ald service <subcmdArgs>" in an elevated PowerShell
// window via UAC. The window stays open on failure so the user can read the error.
func elevateAndRun(exePath string, subcmdArgs []string) error {
	psArgs := "service"
	for _, a := range subcmdArgs {
		psArgs += " '" + psEscape(a) + "'"
	}
	script := fmt.Sprintf(
		"& '%s' %s\r\nif ($LASTEXITCODE -ne 0) { Read-Host 'Operation failed. Press Enter to close'; exit 1 }\r\n",
		psEscape(exePath), psArgs)

	tmp, err := os.CreateTemp("", "a2ald-op-*.ps1")
	if err != nil {
		return fmt.Errorf("create temp script: %w", err)
	}
	_, werr := tmp.WriteString(script)
	tmp.Close()
	if werr != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("write temp script: %w", werr)
	}
	defer os.Remove(tmp.Name())

	launchCmd := fmt.Sprintf(
		`try { $p = Start-Process powershell -Verb RunAs -Wait -PassThru `+
			`-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','%s'); `+
			`exit $p.ExitCode } catch { exit 1 }`,
		psEscape(tmp.Name()))

	cmd := exec.Command("powershell", "-NoProfile", "-Command", launchCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("elevated operation failed or was cancelled")
	}
	return nil
}

// svcInstallSCM installs a2ald as a Windows SCM service.
// Decision tree (see doc-local/Windows服务管理设计.md):
//  1. Idempotency — running from installed location + registered → success
//  2. Privilege check — must be elevated before any side effects
//  3. Confirm — ask [y/N] if replacing existing registration
//  4. prepareForInstall — stop all + remove all registrations + wait file lock
//  5. Copy binaries
//  6. sc create + description + failure policy
//  7. sc start (rollback on failure)
//  8. PATH + success output
func svcInstallSCM(exePath, dataDir string) error {
	installDir, err := targetInstallDir(false)
	if err != nil {
		return fmt.Errorf("determine install dir: %w", err)
	}
	destExe := filepath.Join(installDir, "a2ald.exe")

	// 1. Idempotency: already installed from the canonical location.
	if strings.EqualFold(filepath.Clean(exePath), filepath.Clean(destExe)) && scServiceExists(svcName) {
		fmt.Println("a2ald: already installed as Windows Service.")
		fmt.Println("  Use 'a2ald service status/stop/start' to manage.")
		return nil
	}

	// 2. Privilege check — before any side effects.
	if !isElevated() {
		return errNeedElevation
	}

	// 3. Confirm if replacing an existing registration.
	_, hasTask := queryTaskStatus(svcTaskName)
	if scServiceExists(svcName) || hasTask {
		if isStdinTerminal() {
			fmt.Printf("a2ald is already installed. Reinstall and restart? [y/N]: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.ToLower(strings.TrimSpace(line)) != "y" {
				return fmt.Errorf("cancelled")
			}
		} else {
			return fmt.Errorf("already-installed — service is already installed; to upgrade use 'a2ald update'")
		}
	}

	// 4. Stop all instances, remove all registrations, wait for file lock release.
	if err := prepareForInstall(destExe); err != nil {
		return err
	}

	// 5. Copy binaries to stable install location.
	copied, copyErr := installBinaries(exePath, installDir)
	if copyErr != nil {
		rollbackCopy(copied)
		return fmt.Errorf("install binaries: %w", copyErr)
	}

	// 6. Register with SCM.
	binPath := fmt.Sprintf(`"%s" -data-dir "%s"`, destExe, dataDir)
	if _, err := exec.Command("sc.exe", "create", svcName,
		"binPath=", binPath,
		"DisplayName=", svcDisplayName,
		"start=", "auto",
		"type=", "own",
	).CombinedOutput(); err != nil {
		rollbackCopy(copied)
		return fmt.Errorf("create service: %w", err)
	}
	exec.Command("sc.exe", "description", svcName, svcDescription).Run()
	exec.Command("sc.exe", "failure", svcName,
		"reset=", "3600",
		"actions=", "restart/5000/restart/15000/restart/30000",
	).Run()

	// 7. Start — rollback fully on failure.
	if _, err := exec.Command("sc.exe", "start", svcName).CombinedOutput(); err != nil {
		exec.Command("sc.exe", "delete", svcName).Run()
		rollbackCopy(copied)
		return fmt.Errorf("start service: %w", err)
	}

	// 8. PATH and output.
	_ = addToWindowsPath(installDir, true)

	fmt.Println("a2ald: installed and started as Windows Service.")
	fmt.Printf("  Installed at: %s\n", installDir)
	fmt.Printf("  Data:         %s\n", dataDir)
	fmt.Println("  Manage:       services.msc  or  a2ald service stop/start/status")
	fmt.Println("  Web UI:       http://127.0.0.1:2121/")
	fmt.Println("  MCP:          http://127.0.0.1:2121/mcp/")
	if !strings.EqualFold(filepath.Clean(exePath), filepath.Clean(destExe)) {
		fmt.Printf("  Source binary at %s can now be deleted.\n", exePath)
	}
	fmt.Println("  (Open a new terminal for PATH changes to take effect.)")
	return nil
}

// svcInstallTask installs a2ald as a Task Scheduler task (no admin required).
func svcInstallTask(exePath, dataDir string) error {
	installDir, err := targetInstallDir(true)
	if err != nil {
		return fmt.Errorf("determine install dir: %w", err)
	}
	destExe := filepath.Join(installDir, "a2ald.exe")

	_, hasTask := queryTaskStatus(svcTaskName)
	hasSCM := scServiceExists(svcName)

	// 1. Idempotency: already installed as Task from the canonical location.
	if strings.EqualFold(filepath.Clean(exePath), filepath.Clean(destExe)) && hasTask && !hasSCM {
		fmt.Println("a2ald: already installed as Task Scheduler task.")
		fmt.Println("  Use 'a2ald service status/stop/start' to manage.")
		return nil
	}

	// 2. Cannot install as Task while a SCM service is registered (needs admin to remove first).
	if hasSCM {
		if isElevated() {
			// We have admin — proceed, prepareForInstall will clean up SCM.
		} else {
			return fmt.Errorf("a Windows Service is already installed; remove it first: a2ald service uninstall")
		}
	}

	// 3. Confirm if replacing an existing registration (SCM or Task).
	if hasSCM || hasTask {
		if isStdinTerminal() {
			if hasSCM {
				fmt.Printf("a2ald is installed as a Windows Service. Switch to Task Scheduler (no-admin) mode? [y/N]: ")
			} else {
				fmt.Printf("a2ald is already installed as a Task Scheduler task. Reinstall? [y/N]: ")
			}
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.ToLower(strings.TrimSpace(line)) != "y" {
				return fmt.Errorf("cancelled")
			}
		} else {
			return fmt.Errorf("already-installed — service is already installed; to upgrade use 'a2ald update'")
		}
	}

	fmt.Println("a2ald: installing as Task Scheduler task (no admin required).")
	fmt.Println("  Note: task stops when you log out.")

	// 4. Stop all instances and wait for the Task binary to be released.
	if err := prepareForInstall(destExe); err != nil {
		return err
	}

	// 5. Copy binaries.
	copied, copyErr := installBinaries(exePath, installDir)
	if copyErr != nil {
		rollbackCopy(copied)
		return fmt.Errorf("install binaries: %w", copyErr)
	}

	// 6. Register Task via PowerShell (locale-neutral, handles quoting correctly).
	psArg := fmt.Sprintf(`-data-dir "%s"`, strings.ReplaceAll(dataDir, `"`, `\"`))
	psCmd := fmt.Sprintf(
		`$a = New-ScheduledTaskAction -Execute '%s' -Argument '%s'`+"\n"+
			`$t = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME`+"\n"+
			`$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries`+"\n"+
			`Register-ScheduledTask -TaskName '%s' -Action $a -Trigger $t -Settings $s -Force | Out-Null`,
		psEscape(destExe), psEscape(psArg), psEscape(svcTaskName))
	if out, err := exec.Command("powershell", "-NoProfile", "-Command", psCmd).CombinedOutput(); err != nil {
		rollbackCopy(copied)
		return fmt.Errorf("register scheduled task: %s", strings.TrimSpace(string(out)))
	}

	// 7. Start immediately (non-fatal if it fails; will run at next login).
	if err := psTaskOp("Start-ScheduledTask", svcTaskName); err != nil {
		fmt.Fprintln(os.Stderr, "  warning: installed but could not start immediately; will run at next login.")
	}

	_ = addToWindowsPath(installDir, false)

	fmt.Println("a2ald: installed as Task Scheduler task and started.")
	fmt.Printf("  Installed at: %s\n", installDir)
	fmt.Printf("  Data:         %s\n", dataDir)
	fmt.Println("  Web UI:       http://127.0.0.1:2121/")
	fmt.Println("  MCP:          http://127.0.0.1:2121/mcp/")
	if !strings.EqualFold(filepath.Clean(exePath), filepath.Clean(destExe)) {
		fmt.Printf("  Source binary at %s can now be deleted.\n", exePath)
	}
	fmt.Println("  (Open a new terminal for PATH changes to take effect.)")
	return nil
}

// ── Uninstall ─────────────────────────────────────────────────────────────────

// svcUninstall detects the installed mode and removes it completely.
// For SCM services, elevation is offered interactively when needed.
func svcUninstall(exePath string) error {
	hasSCM := scServiceExists(svcName)
	_, hasTask := queryTaskStatus(svcTaskName)

	if !hasSCM && !hasTask {
		return fmt.Errorf("not-installed: service is not installed")
	}

	// SCM removal requires admin; offer UAC elevation for interactive users.
	if hasSCM && !isElevated() {
		if isStdinTerminal() {
			fmt.Println("a2ald: administrator access required — a UAC prompt will appear...")
			if err := elevateAndRun(exePath, []string{"uninstall"}); err != nil {
				return err
			}
			fmt.Println("a2ald: uninstalled successfully.")
			return nil
		}
		fmt.Fprintln(os.Stderr, "a2ald: requires-admin — administrator access required to remove the Windows Service.")
		fmt.Fprintln(os.Stderr, "  Open an Administrator terminal and run: a2ald service uninstall")
		return fmt.Errorf("requires-admin")
	}

	// Stop and remove SCM service.
	if hasSCM {
		exec.Command("sc.exe", "stop", svcName).Run()
		time.Sleep(500 * time.Millisecond)
		if _, err := exec.Command("sc.exe", "delete", svcName).CombinedOutput(); err != nil {
			return fmt.Errorf("delete service: %w", err)
		}
		fmt.Println("a2ald: Windows Service removed.")
	}

	// Stop and remove Task Scheduler task.
	if hasTask {
		psTaskOp("Stop-ScheduledTask", svcTaskName)
		time.Sleep(300 * time.Millisecond)
		if err := psTaskOp("Unregister-ScheduledTask", svcTaskName, "-Confirm:$false"); err != nil {
			if !hasSCM {
				return fmt.Errorf("remove scheduled task: %w", err)
			}
			fmt.Fprintf(os.Stderr, "  warning: could not remove Task Scheduler task: %v\n", err)
		} else if !hasSCM {
			fmt.Println("a2ald: Task Scheduler task removed.")
		} else {
			fmt.Println("  (removed Task Scheduler task)")
		}
	}

	// Clean up install directories (wait for file lock release first).
	// waitForBinaryRelease errors are intentionally ignored: if the binary is still
	// locked (e.g. the elevated uninstall process is the installed exe running itself),
	// removeInstallDir will silently fail on that file — the registration is already
	// gone, so the orphaned binary on disk causes no functional harm.
	if hasSCM {
		dir, _ := targetInstallDir(false)
		_ = waitForBinaryRelease(filepath.Join(dir, "a2ald.exe"), 3*time.Second)
		removeInstallDir(dir)
		_ = removeFromWindowsPath(dir, true)
	}
	if hasTask {
		dir, _ := targetInstallDir(true)
		_ = waitForBinaryRelease(filepath.Join(dir, "a2ald.exe"), 3*time.Second)
		removeInstallDir(dir)
		_ = removeFromWindowsPath(dir, false)
	}
	return nil
}

// ── Start / Stop / Status ─────────────────────────────────────────────────────

func svcStart() error {
	if scServiceExists(svcName) {
		if !isElevated() {
			return fmt.Errorf("requires-admin — open an Administrator terminal to start the service")
		}
		if _, err := exec.Command("sc.exe", "start", svcName).CombinedOutput(); err != nil {
			if isExitCode(err, 1056) {
				fmt.Println("a2ald: service is already running.")
				return nil
			}
			return fmt.Errorf("start service: %w", err)
		}
		fmt.Println("a2ald: started.")
		return nil
	}
	if _, found := queryTaskStatus(svcTaskName); !found {
		return fmt.Errorf("not-installed: run 'a2ald service install' first")
	}
	if err := psTaskOp("Start-ScheduledTask", svcTaskName); err != nil {
		return fmt.Errorf("start task: %w", err)
	}
	fmt.Println("a2ald: started.")
	return nil
}

func svcStop() error {
	if scServiceExists(svcName) {
		if !isElevated() {
			return fmt.Errorf("requires-admin — open an Administrator terminal to stop the service")
		}
		if _, err := exec.Command("sc.exe", "stop", svcName).CombinedOutput(); err != nil {
			if isExitCode(err, 1062) {
				fmt.Println("a2ald: service is already stopped.")
				return nil
			}
			return fmt.Errorf("stop service: %w", err)
		}
		fmt.Println("a2ald: stopped.")
		return nil
	}
	if _, found := queryTaskStatus(svcTaskName); !found {
		return fmt.Errorf("not-installed: run 'a2ald service install' first")
	}
	if err := psTaskOp("Stop-ScheduledTask", svcTaskName); err != nil {
		return fmt.Errorf("stop task: %w", err)
	}
	fmt.Println("a2ald: stopped.")
	return nil
}

func svcStatus() error {
	// SCM service: PowerShell Get-Service returns locale-independent Status enum.
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`$s = Get-Service -Name '%s' -ErrorAction SilentlyContinue; if ($s) { $s.Status.ToString() } else { '' }`,
			psEscape(svcName))).Output()
	if err == nil {
		if status := strings.TrimSpace(string(out)); status != "" {
			fmt.Printf("Windows Service (%s): %s\n", svcDisplayName, strings.ToLower(status))
			return nil
		}
	}

	// Task Scheduler: PowerShell Get-ScheduledTask.State is also locale-independent.
	out, err = exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`$t = Get-ScheduledTask -TaskName '%s' -ErrorAction SilentlyContinue; if ($t) { $t.State.ToString() } else { '' }`,
			psEscape(svcTaskName))).Output()
	if err == nil {
		if status := strings.TrimSpace(string(out)); status != "" {
			// "Ready" means registered but not running — display as "stopped" to avoid confusion.
			if strings.EqualFold(status, "Ready") {
				status = "stopped"
			} else {
				status = strings.ToLower(status)
			}
			fmt.Printf("Task Scheduler (%s): %s\n", svcDisplayName, status)
			return nil
		}
	}

	fmt.Println("a2ald: not installed as a service.")
	fmt.Println("  Run 'a2ald service install' to install.")
	return nil
}

// ── emit-script ───────────────────────────────────────────────────────────────

func svcEmitScript(outPath string) error {
	if outPath == "" {
		outPath = "install-service.ps1"
	}
	if err := os.WriteFile(outPath, []byte(installServicePS1), 0644); err != nil {
		return err
	}
	abs, _ := filepath.Abs(outPath)
	fmt.Printf("a2ald: wrote %s\n", abs)
	fmt.Println("  Right-click → \"Run as administrator\", or:")
	fmt.Printf("  powershell -ExecutionPolicy Bypass -File \"%s\"\n", abs)
	return nil
}

// ── Core: prepareForInstall + waitForBinaryRelease + isFileLocked ─────────────

// prepareForInstall stops all running a2ald instances and removes all service
// registrations, then waits until the target binary is no longer locked.
// Must be called with admin privileges when an SCM service is registered.
func prepareForInstall(destExe string) error {
	if scServiceExists(svcName) {
		exec.Command("sc.exe", "stop", svcName).Run()
		time.Sleep(300 * time.Millisecond)
		exec.Command("sc.exe", "delete", svcName).Run()
		time.Sleep(300 * time.Millisecond)
	}
	if _, found := queryTaskStatus(svcTaskName); found {
		psTaskOp("Stop-ScheduledTask", svcTaskName)
		time.Sleep(300 * time.Millisecond)
		psTaskOp("Unregister-ScheduledTask", svcTaskName, "-Confirm:$false")
		time.Sleep(300 * time.Millisecond)
	}
	return waitForBinaryRelease(destExe, 5*time.Second)
}

// waitForBinaryRelease polls until path is no longer locked or timeout elapses.
func waitForBinaryRelease(path string, timeout time.Duration) error {
	if !fileExists(path) {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isFileLocked(path) {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("binary-in-use: %s is still held by another process; stop a2ald manually and retry", filepath.Base(path))
}

// isFileLocked reports whether path is held open by another process.
// Uses CreateFile with no sharing flags — the only reliable Windows approach.
func isFileLocked(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		var errno windows.Errno
		if errors.As(err, &errno) {
			return errno == windows.ERROR_SHARING_VIOLATION
		}
		return false
	}
	windows.CloseHandle(h)
	return false
}

// ── SCM helpers ───────────────────────────────────────────────────────────────

// scServiceExists reports whether a Windows Service is registered in SCM.
// sc.exe query does not require administrator rights.
func scServiceExists(name string) bool {
	return exec.Command("sc.exe", "query", name).Run() == nil
}

// isElevated reports whether the current process has administrator privileges.
func isElevated() bool {
	t, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer t.Close()
	return t.IsElevated()
}

// isExitCode reports whether err is an *exec.ExitError with the given exit code.
func isExitCode(err error, code int) bool {
	var e *exec.ExitError
	return errors.As(err, &e) && e.ExitCode() == code
}

// ── Task Scheduler helpers ────────────────────────────────────────────────────

// psTaskOp runs a ScheduledTask PowerShell cmdlet (Start/Stop/Unregister).
// Error output is included in the returned error for diagnosis.
func psTaskOp(cmdlet, taskName string, extra ...string) error {
	args := fmt.Sprintf(`%s -TaskName '%s'`, cmdlet, psEscape(taskName))
	for _, e := range extra {
		args += " " + e
	}
	out, err := exec.Command("powershell", "-NoProfile", "-Command", args).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", cmdlet, strings.TrimSpace(string(out)))
	}
	return nil
}

// queryTaskStatus queries Task Scheduler status via CSV output (ASCII-safe).
func queryTaskStatus(name string) (status string, found bool) {
	out, err := exec.Command("schtasks", "/query", "/tn", name, "/fo", "CSV", "/nh").CombinedOutput()
	if err != nil {
		return "", false
	}
	parts := parseCSVLine(strings.TrimSpace(string(out)))
	if len(parts) < 3 {
		return "unknown", true
	}
	switch parts[2] {
	case "Running":
		return "running", true
	case "Ready":
		return "ready (starts at next login)", true
	case "Disabled":
		return "disabled", true
	default:
		return strings.ToLower(parts[2]), true
	}
}

// ── Install directory helpers ─────────────────────────────────────────────────

// targetInstallDir returns the stable binary directory for the given install mode.
//
//	SCM  (admin): %ProgramFiles%\A2AL
//	Task (user):  %LocalAppData%\A2AL
func targetInstallDir(userMode bool) (string, error) {
	if userMode {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(base, "A2AL"), nil
	}
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "A2AL"), nil
}

// installBinaries copies a2ald.exe (and a2al.exe if present) to destDir.
// Returns the list of copied files for rollback on error.
func installBinaries(srcExe, destDir string) ([]string, error) {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, fmt.Errorf("create install dir: %w", err)
	}
	var copied []string

	destExe := filepath.Join(destDir, "a2ald.exe")
	if err := copyFile(srcExe, destExe); err != nil {
		return copied, fmt.Errorf("copy a2ald.exe: %w", err)
	}
	copied = append(copied, destExe)

	if srcCLI := filepath.Join(filepath.Dir(srcExe), "a2al.exe"); fileExists(srcCLI) {
		destCLI := filepath.Join(destDir, "a2al.exe")
		if err := copyFile(srcCLI, destCLI); err == nil {
			copied = append(copied, destCLI)
		}
	}
	return copied, nil
}

func copyFile(src, dst string) error {
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func rollbackCopy(files []string) {
	for _, f := range files {
		os.Remove(f)
	}
}

// removeInstallDir removes known binaries from dir, then the dir if empty.
func removeInstallDir(dir string) {
	if dir == "" {
		return
	}
	for _, name := range []string{"a2ald.exe", "a2al.exe"} {
		os.Remove(filepath.Join(dir, name))
	}
	os.Remove(dir)
}

// ── PATH registry helpers ─────────────────────────────────────────────────────

func addToWindowsPath(dir string, systemWide bool) error {
	k, err := openPathRegistryKey(systemWide, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	current, valType, err := k.GetStringValue("Path")
	if err != nil {
		if err == registry.ErrNotExist {
			current, valType = "", registry.SZ
		} else {
			return err
		}
	}
	for _, p := range filepath.SplitList(current) {
		if strings.EqualFold(strings.TrimSpace(p), dir) {
			return nil
		}
	}
	newPath := strings.TrimRight(current, ";")
	if newPath != "" {
		newPath += ";"
	}
	return setPathValue(k, newPath+dir, valType)
}

func removeFromWindowsPath(dir string, systemWide bool) error {
	k, err := openPathRegistryKey(systemWide, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	current, valType, err := k.GetStringValue("Path")
	if err != nil {
		return err
	}
	var parts []string
	for _, p := range filepath.SplitList(current) {
		if !strings.EqualFold(strings.TrimSpace(p), dir) {
			parts = append(parts, p)
		}
	}
	return setPathValue(k, strings.Join(parts, ";"), valType)
}

func openPathRegistryKey(systemWide bool, access uint32) (registry.Key, error) {
	if systemWide {
		return registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, access)
	}
	return registry.OpenKey(registry.CURRENT_USER, `Environment`, access)
}

func setPathValue(k registry.Key, value string, valType uint32) error {
	if valType == registry.EXPAND_SZ {
		return k.SetExpandStringValue("Path", value)
	}
	return k.SetStringValue("Path", value)
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

// parseCSVLine splits a single CSV line, stripping surrounding double-quotes.
func parseCSVLine(s string) []string {
	var fields []string
	for len(s) > 0 {
		if s[0] == '"' {
			end := strings.Index(s[1:], `"`)
			if end < 0 {
				break
			}
			fields = append(fields, s[1:end+1])
			s = s[end+2:]
			if len(s) > 0 && s[0] == ',' {
				s = s[1:]
			}
		} else {
			idx := strings.IndexByte(s, ',')
			if idx < 0 {
				fields = append(fields, s)
				break
			}
			fields = append(fields, s[:idx])
			s = s[idx+1:]
		}
	}
	return fields
}

func psEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// isStdinTerminal reports whether os.Stdin is connected to a Windows console.
func isStdinTerminal() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil
}
