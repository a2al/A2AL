// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/a2al/a2al/config"
)

var (
	errWakeCmdEmpty   = errors.New("wake cmd is required")
	errWakeCmdMissing = errors.New("wake cmd does not exist")
	errWakeCmdDir     = errors.New("wake cmd is a directory")
	errWakeShell      = errors.New("wake cmd cannot be a shell interpreter")
	errWakeNotAllowed = errors.New("wake cmd is not on the allowed_cmds list")
	errWakeVia        = errors.New("wake via must be exec or acp")
	errWakeNoHandle   = errors.New("no handle")
	errWakeNoCap      = errors.New("wake acp: cap is required")
)

var wakeShellNames = map[string]struct{}{
	"sh": {}, "bash": {}, "zsh": {}, "dash": {}, "csh": {}, "tcsh": {}, "fish": {},
	"cmd": {}, "powershell": {}, "pwsh": {},
}

type tailWriter struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func newTailWriter(n int) *tailWriter {
	if n <= 0 {
		n = wakeStderrCap
	}
	return &tailWriter{max: n}
}

func (t *tailWriter) Write(p []byte) (int, error) {
	if t == nil {
		return len(p), nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-t.max:]...)
	}
	return len(p), nil
}

func (t *tailWriter) String() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

func (d *Daemon) spawnWakeCommand(b wakeBinding, stdin []byte) {
	res := wakeLastResult{At: time.Now(), StartedAt: time.Now(), InFlight: true, Step: "start"}
	if d != nil && d.wake != nil {
		d.wake.patchLast(b.AID, func(cur *wakeLastResult) {
			*cur = res
		})
	}
	defer func() {
		res.InFlight = false
		res.At = time.Now()
		if d != nil && d.wake != nil {
			d.wake.setLast(b.AID, res)
		}
	}()
	if err := d.authorizeWakeCmd(b.Cmd); err != nil {
		res.Error = err.Error()
		if d != nil && d.log != nil {
			d.log.Warn("wake spawn refused", "aid", b.AID.String(), "cmd", b.Cmd, "err", err)
		}
		return
	}
	handle := ""
	if d != nil && d.wake != nil {
		handle = d.wake.snapshotHandle(b.AID)
	}
	if argsNeedHandle(b.Args) && handle == "" {
		res.Error = errWakeNoHandle.Error()
		if d != nil && d.log != nil {
			d.log.Warn("wake spawn refused", "aid", b.AID.String(), "err", errWakeNoHandle)
		}
		return
	}
	b.Args = expandWakeArgs(b.Args, handle)

	var err error
	if b.Via == "acp" {
		cfgCap := int64(0)
		if d != nil && d.cfg != nil {
			cfgCap = d.cfg.Wake.AcpCap
		} else {
			cfgCap = config.WakeACPCapDefault
		}
		capn := effectiveWakeCap(b.Cap, cfgCap, nil, "")
		if capn <= 0 {
			res.Error = errWakeNoCap.Error()
			return
		}
		res.Cap = capn
		res.CapUnit = wakeCostUnitTokens
		res.Source = wakeCostSourceACP
		res.Step = "initialize"
		acpRes, waitErr, driveErr := d.spawnWakeACP(b, stdin, handle, capn, func() {
			if d != nil && d.wake != nil {
				d.wake.commitDelivered(b.AID)
			}
		}, func(id string) {
			res.SessionID = id
			if d != nil && d.wake != nil && id != "" {
				d.wake.setHandle(b.AID, id)
				d.wake.patchLast(b.AID, func(cur *wakeLastResult) {
					cur.SessionID = id
					cur.InFlight = true
				})
			}
		}, func(step string) {
			res.Step = step
			if d != nil && d.wake != nil {
				d.wake.patchLast(b.AID, func(cur *wakeLastResult) {
					cur.Step = step
					cur.InFlight = true
					cur.StartedAt = res.StartedAt
				})
			}
		}, func(spend int64) {
			res.Spend = spend
			res.SpendUnit = wakeCostUnitTokens
			if d != nil && d.wake != nil {
				d.wake.patchLast(b.AID, func(cur *wakeLastResult) {
					cur.Spend = spend
					cur.SpendUnit = wakeCostUnitTokens
					cur.Cap = capn
					cur.CapUnit = wakeCostUnitTokens
					cur.InFlight = true
				})
			}
		}, func(pid int) {
			res.PID = pid
			if d != nil && d.wake != nil {
				d.wake.patchLast(b.AID, func(cur *wakeLastResult) {
					cur.PID = pid
					cur.InFlight = true
				})
			}
		})
		res.StopReason = acpRes.StopReason
		res.CancelledFor = acpRes.CancelledFor
		res.Stderr = acpRes.Stderr
		res.ModelTag = acpRes.ModelTag
		res.Spend = acpRes.Spend
		res.SpendUnit = wakeCostUnitTokens
		if acpRes.PID > 0 {
			res.PID = acpRes.PID
		}
		if acpRes.SessionID != "" {
			res.SessionID = acpRes.SessionID
		}
		if acpRes.Step != "" {
			res.Step = acpRes.Step
		}
		err = driveErr
		if err == nil && waitErr != nil {
			var ee *exec.ExitError
			if errors.As(waitErr, &ee) {
				c := ee.ExitCode()
				res.ExitCode = &c
			}
		}
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				c := ee.ExitCode()
				res.ExitCode = &c
			} else if waitErr != nil {
				if errors.As(waitErr, &ee) {
					c := ee.ExitCode()
					res.ExitCode = &c
				}
			}
			if d != nil && d.log != nil {
				d.log.Warn("wake spawn failed", "aid", b.AID.String(), "via", b.Via, "cmd", b.Cmd, "err", err)
			}
			res.Error = err.Error()
			return
		}
		z := 0
		if res.ExitCode == nil {
			res.ExitCode = &z
		}
		res.Ok = true
		return
	}

	err = d.spawnWakeExec(b, stdin, func() {
		if d != nil && d.wake != nil {
			d.wake.commitDelivered(b.AID)
		}
	}, &res)
	if err != nil {
		res.Error = err.Error()
		if d != nil && d.log != nil {
			d.log.Warn("wake spawn failed", "aid", b.AID.String(), "via", b.Via, "cmd", b.Cmd, "err", err)
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			c := ee.ExitCode()
			res.ExitCode = &c
		}
		return
	}
	z := 0
	res.ExitCode = &z
	res.Ok = true
}

func (d *Daemon) spawnWakeExec(b wakeBinding, stdin []byte, onStart func(), res *wakeLastResult) error {
	if res == nil {
		res = &wakeLastResult{}
	}
	cmd := exec.Command(b.Cmd, b.Args...)
	hideWakeWindow(cmd)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout = io.Discard
	stderr := newTailWriter(wakeStderrCap)
	cmd.Stderr = stderr
	if cwd := strings.TrimSpace(b.Cwd); cwd != "" {
		dir, err := resolveWakeCwd(cwd)
		if err != nil {
			return err
		}
		cmd.Dir = dir
	}
	res.Step = "exec"
	if err := cmd.Start(); err != nil {
		res.Stderr = stderr.String()
		return err
	}
	if cmd.Process != nil {
		res.PID = cmd.Process.Pid
		if d != nil && d.wake != nil {
			d.wake.patchLast(b.AID, func(cur *wakeLastResult) {
				cur.PID = res.PID
				cur.Step = "exec"
				cur.InFlight = true
			})
		}
	}
	if onStart != nil {
		onStart()
	}
	err := cmd.Wait()
	res.Stderr = stderr.String()
	return err
}

func (d *Daemon) authorizeWakeCmd(cmd string) error {
	resolved, err := resolveWakeCmd(cmd)
	if err != nil {
		return err
	}
	if err := rejectWakeShell(cmd); err != nil {
		return err
	}
	if err := rejectWakeShell(resolved); err != nil {
		return err
	}
	return d.checkWakeAllowList(resolved, cmd)
}

func resolveWakeCmd(cmd string) (string, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", errWakeCmdEmpty
	}
	if filepath.IsAbs(cmd) || strings.ContainsAny(cmd, `/\`) {
		st, err := os.Stat(cmd)
		if err != nil {
			return "", errWakeCmdMissing
		}
		if st.IsDir() {
			return "", errWakeCmdDir
		}
		if abs, err := filepath.Abs(cmd); err == nil {
			return filepath.Clean(abs), nil
		}
		return filepath.Clean(cmd), nil
	}
	p, err := exec.LookPath(cmd)
	if err != nil {
		return "", errWakeCmdMissing
	}
	if abs, err := filepath.Abs(p); err == nil {
		return filepath.Clean(abs), nil
	}
	return p, nil
}

func rejectWakeShell(cmd string) error {
	norm := strings.ReplaceAll(strings.ToLower(cmd), `\`, `/`)
	base := norm[strings.LastIndex(norm, "/")+1:]
	base = strings.TrimSuffix(base, ".exe")
	if _, bad := wakeShellNames[base]; bad {
		return errWakeShell
	}
	return nil
}

func (d *Daemon) checkWakeAllowList(resolved, original string) error {
	var list []string
	if d != nil && d.cfg != nil {
		list = d.cfg.Wake.AllowedCmds
	}
	if len(list) == 0 {
		return nil
	}
	for _, allowed := range list {
		if wakeCmdMatch(resolved, original, allowed) {
			return nil
		}
	}
	return errWakeNotAllowed
}

func wakeCmdMatch(resolved, original, allowed string) bool {
	allowed = strings.TrimSpace(allowed)
	if allowed == "" {
		return false
	}
	if wakePathEqual(original, allowed) || wakePathEqual(resolved, allowed) {
		return true
	}
	ar, err := resolveWakeCmd(allowed)
	if err != nil {
		return false
	}
	return wakePathEqual(resolved, ar)
}

func wakePathEqual(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func normalizeWakeVia(via string) (string, error) {
	via = strings.TrimSpace(strings.ToLower(via))
	switch via {
	case "", "exec":
		return "exec", nil
	case "acp":
		return "acp", nil
	default:
		return "", errWakeVia
	}
}
