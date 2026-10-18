// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/a2al/a2al"
)

type wakePutReq struct {
	Via        string   `json:"via"`
	Cmd        string   `json:"cmd"`
	Args       []string `json:"args"`
	Cwd        string   `json:"cwd"`
	SessionCwd string   `json:"session_cwd"`
	Cap        *int64   `json:"cap"`
}

type wakeHandleReq struct {
	Handle string `json:"handle"`
}

func (d *Daemon) handleWakeGet(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r) {
		http.Error(w, `{"error":"wake bind only available on loopback"}`, http.StatusForbidden)
		return
	}
	aid, err := a2al.ParseAddress(r.PathValue("aid"))
	if err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}
	if !d.isLocalAID(aid) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if d.wake == nil {
		writeJSON(w, map[string]any{"bound": false})
		return
	}
	b, last, ok := d.wake.snapshot(aid)
	out := map[string]any{"bound": ok}
	if ok {
		out["via"] = b.Via
		out["cmd"] = b.Cmd
		out["args"] = b.Args
		if b.Cwd != "" {
			out["cwd"] = b.Cwd
		}
		if b.SessionCwd != "" {
			out["session_cwd"] = b.SessionCwd
		}
		if b.Cap > 0 {
			out["cap"] = b.Cap
		}
	}
	if h := d.wake.snapshotHandle(aid); h != "" {
		out["handle"] = h
	}
	if m := lastMap(last); m != nil {
		out["last"] = m
	}
	writeJSON(w, out)
}

func lastMap(last wakeLastResult) map[string]any {
	if last.At.IsZero() && last.StartedAt.IsZero() && !last.InFlight && last.Error == "" && last.Spend == 0 && last.Cap == 0 && last.PID == 0 && last.SessionID == "" {
		return nil
	}
	m := map[string]any{"ok": last.Ok, "in_flight": last.InFlight}
	if !last.At.IsZero() {
		m["at"] = last.At.UTC().Format(time.RFC3339Nano)
	}
	if !last.StartedAt.IsZero() {
		m["started_at"] = last.StartedAt.UTC().Format(time.RFC3339Nano)
	}
	if last.Error != "" {
		m["error"] = last.Error
	}
	if last.PID > 0 {
		m["pid"] = last.PID
	}
	if last.SessionID != "" {
		m["session_id"] = last.SessionID
	}
	if last.ExitCode != nil {
		m["exit_code"] = *last.ExitCode
	}
	if last.Step != "" {
		m["step"] = last.Step
	}
	if last.Stderr != "" {
		m["stderr"] = last.Stderr
	}
	if last.StopReason != "" {
		m["stop_reason"] = last.StopReason
	}
	if last.CancelledFor != "" {
		m["cancelled_for"] = last.CancelledFor
	}
	if last.Cap > 0 || last.Spend > 0 || last.Source != "" {
		cost := map[string]any{
			"cap":             last.Cap,
			"cap_unit":        last.CapUnit,
			"spend":           last.Spend,
			"spend_unit":      last.SpendUnit,
			"source":          last.Source,
			"remaining":       nil,
			"remaining_unit":  nil,
			"remaining_basis": nil,
		}
		if last.CapUnit == "" && last.Cap > 0 {
			cost["cap_unit"] = wakeCostUnitTokens
		}
		if last.SpendUnit == "" && last.Spend > 0 {
			cost["spend_unit"] = wakeCostUnitTokens
		}
		if last.ModelTag != "" {
			cost["model_tag"] = last.ModelTag
		}
		if last.StopReason != "" {
			cost["stop_reason"] = last.StopReason
		}
		if last.CancelledFor != "" {
			cost["cancelled_for"] = last.CancelledFor
		}
		m["cost"] = cost
	}
	return m
}

func (d *Daemon) handleWakePut(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r) {
		http.Error(w, `{"error":"wake bind only available on loopback"}`, http.StatusForbidden)
		return
	}
	aid, err := a2al.ParseAddress(r.PathValue("aid"))
	if err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}
	if !d.isLocalAID(aid) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if d.wake == nil {
		http.Error(w, `{"error":"wake not available"}`, http.StatusServiceUnavailable)
		return
	}
	var req wakePutReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	via, err := normalizeWakeVia(req.Via)
	if err != nil {
		http.Error(w, `{"error":"via must be exec or acp"}`, http.StatusBadRequest)
		return
	}
	resolved, err := resolveWakeCmd(req.Cmd)
	if err != nil {
		writeWakeErr(w, err)
		return
	}
	if err := d.authorizeWakeCmd(req.Cmd); err != nil {
		writeWakeErr(w, err)
		return
	}
	cwd := strings.TrimSpace(req.Cwd)
	if cwd != "" {
		cwd, err = resolveWakeCwd(cwd)
		if err != nil {
			writeWakeErr(w, err)
			return
		}
	}
	sessionCwd := strings.TrimSpace(req.SessionCwd)
	var capn int64
	if req.Cap != nil {
		capn = *req.Cap
	}
	b := wakeBinding{
		AID:        aid,
		Via:        via,
		Cmd:        resolved,
		Args:       append([]string(nil), req.Args...),
		Cwd:        cwd,
		SessionCwd: sessionCwd,
		Cap:        capn,
	}
	if err := d.wake.putBinding(b); err != nil {
		http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		return
	}
	out := map[string]any{
		"bound": true,
		"via":   b.Via,
		"cmd":   b.Cmd,
		"args":  b.Args,
	}
	if b.Cwd != "" {
		out["cwd"] = b.Cwd
	}
	if b.SessionCwd != "" {
		out["session_cwd"] = b.SessionCwd
	}
	if b.Cap > 0 {
		out["cap"] = b.Cap
	}
	writeJSON(w, out)
}

func (d *Daemon) handleWakeDelete(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r) {
		http.Error(w, `{"error":"wake bind only available on loopback"}`, http.StatusForbidden)
		return
	}
	aid, err := a2al.ParseAddress(r.PathValue("aid"))
	if err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}
	if !d.isLocalAID(aid) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if d.wake != nil {
		d.wake.removeBinding(aid)
	}
	writeJSON(w, map[string]any{"bound": false})
}

func (d *Daemon) handleWakeTest(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r) {
		http.Error(w, `{"error":"wake bind only available on loopback"}`, http.StatusForbidden)
		return
	}
	aid, err := a2al.ParseAddress(r.PathValue("aid"))
	if err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}
	if !d.isLocalAID(aid) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if d.wake == nil || !d.wake.fireNow(aid) {
		http.Error(w, `{"error":"no wake binding"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "queued": true})
}

func (d *Daemon) handleWakeHandleGet(w http.ResponseWriter, r *http.Request) {
	if !wakeHandleGate(w, r, d) {
		return
	}
	aid, _ := a2al.ParseAddress(r.PathValue("aid"))
	h := ""
	if d.wake != nil {
		h = d.wake.snapshotHandle(aid)
	}
	writeJSON(w, map[string]any{"handle": h})
}

func (d *Daemon) handleWakeHandlePut(w http.ResponseWriter, r *http.Request) {
	if !wakeHandleGate(w, r, d) {
		return
	}
	aid, _ := a2al.ParseAddress(r.PathValue("aid"))
	var req wakeHandleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if d.wake == nil {
		http.Error(w, `{"error":"wake not available"}`, http.StatusServiceUnavailable)
		return
	}
	d.wake.setHandle(aid, req.Handle)
	writeJSON(w, map[string]any{"handle": strings.TrimSpace(req.Handle)})
}

func (d *Daemon) handleWakeHandleDelete(w http.ResponseWriter, r *http.Request) {
	if !wakeHandleGate(w, r, d) {
		return
	}
	aid, _ := a2al.ParseAddress(r.PathValue("aid"))
	if d.wake != nil {
		d.wake.setHandle(aid, "")
	}
	writeJSON(w, map[string]any{"handle": ""})
}

func wakeHandleGate(w http.ResponseWriter, r *http.Request, d *Daemon) bool {
	if !isLoopback(r) {
		http.Error(w, `{"error":"wake bind only available on loopback"}`, http.StatusForbidden)
		return false
	}
	aid, err := a2al.ParseAddress(r.PathValue("aid"))
	if err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return false
	}
	if !d.isLocalAID(aid) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return false
	}
	return true
}

func writeWakeErr(w http.ResponseWriter, err error) {
	msg := "wake refused"
	switch {
	case errors.Is(err, errWakeCmdEmpty), errors.Is(err, errWakeCmdMissing), errors.Is(err, errWakeCmdDir),
		errors.Is(err, errWakeShell), errors.Is(err, errWakeNotAllowed), errors.Is(err, errWakeVia),
		errors.Is(err, errWakeCwd), errors.Is(err, errWakeNoHandle), errors.Is(err, errWakeNoCap):
		msg = err.Error()
	}
	http.Error(w, `{"error":"`+msg+`"}`, http.StatusBadRequest)
}
