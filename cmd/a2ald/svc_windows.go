// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/a2al/a2al/daemon"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

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

// runServiceMain runs d as a Windows SCM service; blocks until the service is stopped.
func runServiceMain(d *daemon.Daemon) error {
	return svc.Run(svcName, &a2alSvc{d: d})
}

func svcInstall(exePath, dataDir string, userMode bool) error {
	if userMode {
		return svcInstallTask(exePath, dataDir)
	}
	return svcInstallSCM(exePath, dataDir)
}

func svcInstallSCM(exePath, dataDir string) error {
	m, err := mgr.Connect()
	if err != nil {
		if isAccessDenied(err) {
			fmt.Fprintln(os.Stderr, "a2ald: admin access denied.")
			fmt.Fprintln(os.Stderr, "  Run as administrator, or use the no-admin mode:")
			fmt.Fprintln(os.Stderr, "    a2ald service install -user")
			fmt.Fprintln(os.Stderr, "  (-user note: service stops when you log out)")
		}
		return err
	}
	defer m.Disconnect()

	// Remove any pre-existing service cleanly.
	if old, err := m.OpenService(svcName); err == nil {
		_, _ = old.Control(svc.Stop)
		time.Sleep(500 * time.Millisecond)
		_ = old.Delete()
		old.Close()
	}

	// Build a quoted binary path that survives paths with spaces.
	// Format: "C:\path\to\a2ald.exe" -data-dir "C:\Users\...\a2al"
	binPath := fmt.Sprintf(`"%s" -data-dir "%s"`, exePath, dataDir)

	cfg := mgr.Config{
		DisplayName: svcDisplayName,
		Description: svcDescription,
		StartType:   mgr.StartAutomatic,
	}
	s, err := m.CreateService(svcName, binPath, cfg)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Auto-restart on failure with increasing delays (best-effort; ignore errors).
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 3600)

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Println("a2ald: installed and started as Windows Service.")
	fmt.Println("  Manage: services.msc  or  a2ald service stop/start/status")
	fmt.Println("  MCP:    http://127.0.0.1:2121/mcp/")
	return nil
}

func svcInstallTask(exePath, dataDir string) error {
	fmt.Println("a2ald: installing as Task Scheduler task (no admin required).")
	fmt.Println("  Note: task stops when you log out.")

	tr := fmt.Sprintf(`"%s" -data-dir "%s"`, exePath, dataDir)
	out, err := exec.Command("schtasks", "/create",
		"/tn", svcTaskName,
		"/tr", tr,
		"/sc", "ONLOGON",
		"/rl", "LIMITED",
		"/f",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /create: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	// Start immediately without waiting for the next login.
	if out2, err2 := exec.Command("schtasks", "/run", "/tn", svcTaskName).CombinedOutput(); err2 != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not start immediately: %s\n", strings.TrimSpace(string(out2)))
	}

	fmt.Println("a2ald: installed as Task Scheduler task and started.")
	fmt.Println("  MCP:  http://127.0.0.1:2121/mcp/")
	return nil
}

func svcUninstall(userMode bool) error {
	if userMode {
		out, err := exec.Command("schtasks", "/delete", "/tn", svcTaskName, "/f").CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks /delete: %w: %s", err, strings.TrimSpace(string(out)))
		}
		fmt.Println("a2ald: Task Scheduler task removed.")
		return nil
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service not found (is it installed?): %w", err)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop)
	time.Sleep(500 * time.Millisecond)
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Println("a2ald: Windows Service removed.")
	return nil
}

func svcStart() error {
	// Try SCM service first.
	if m, err := mgr.Connect(); err == nil {
		defer m.Disconnect()
		if s, err := m.OpenService(svcName); err == nil {
			defer s.Close()
			if err := s.Start(); err != nil {
				return fmt.Errorf("start service: %w", err)
			}
			fmt.Println("a2ald: started.")
			return nil
		}
		// SCM accessible but service not found → fall through to Task Scheduler.
	}
	// Try Task Scheduler (user-mode install).
	out, err := exec.Command("schtasks", "/run", "/tn", svcTaskName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("not installed as a service; run 'a2ald service install' first\n%s", strings.TrimSpace(string(out)))
	}
	fmt.Println("a2ald: started.")
	return nil
}

func svcStop() error {
	if m, err := mgr.Connect(); err == nil {
		defer m.Disconnect()
		if s, err := m.OpenService(svcName); err == nil {
			defer s.Close()
			if _, err := s.Control(svc.Stop); err != nil {
				return fmt.Errorf("stop service: %w", err)
			}
			fmt.Println("a2ald: stopped.")
			return nil
		}
		// SCM accessible but service not found → fall through to Task Scheduler.
	}
	out, err := exec.Command("schtasks", "/end", "/tn", svcTaskName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("not installed as a service; run 'a2ald service install' first\n%s", strings.TrimSpace(string(out)))
	}
	fmt.Println("a2ald: stopped.")
	return nil
}

func svcStatus() error {
	// Check SCM service.
	if m, err := mgr.Connect(); err == nil {
		defer m.Disconnect()
		if s, err := m.OpenService(svcName); err == nil {
			defer s.Close()
			st, err := s.Query()
			if err == nil {
				states := map[svc.State]string{
					svc.Running:      "running",
					svc.Stopped:      "stopped",
					svc.StartPending: "starting",
					svc.StopPending:  "stopping",
					svc.Paused:       "paused",
				}
				state, ok := states[st.State]
				if !ok {
					state = fmt.Sprintf("state(%d)", st.State)
				}
				fmt.Printf("Windows Service (%s): %s\n", svcDisplayName, state)
				return nil
			}
		}
	}
	// Check Task Scheduler.
	out, err := exec.Command("schtasks", "/query", "/tn", svcTaskName, "/fo", "LIST").CombinedOutput()
	if err != nil {
		fmt.Println("a2ald: not installed as a service.")
		fmt.Println("  Run 'a2ald service install' to install.")
		return nil
	}
	fmt.Printf("Task Scheduler task (%s):\n%s\n", svcTaskName, strings.TrimSpace(string(out)))
	return nil
}

func isAccessDenied(err error) bool {
	var errno windows.Errno
	return errors.As(err, &errno) && errno == windows.ERROR_ACCESS_DENIED
}
