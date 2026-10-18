// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/a2al/a2al"
)

type wakeDiskFile struct {
	Bindings []wakeDiskBinding `json:"bindings"`
	State    []wakeDiskState   `json:"state,omitempty"`
}

type wakeDiskBinding struct {
	AID        string   `json:"aid"`
	Via        string   `json:"via"`
	Cmd        string   `json:"cmd"`
	Args       []string `json:"args,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	SessionCwd string   `json:"session_cwd,omitempty"`
	Cap        int64    `json:"cap,omitempty"`
}

type wakeDiskState struct {
	AID       string        `json:"aid"`
	Handle    string        `json:"handle,omitempty"`
	Delivered wakeDelivered `json:"delivered,omitempty"`
	Last      *wakeDiskLast `json:"last,omitempty"`
}

type wakeDiskLast struct {
	At           string `json:"at,omitempty"`
	StartedAt    string `json:"started_at,omitempty"`
	Ok           bool   `json:"ok"`
	Error        string `json:"error,omitempty"`
	ExitCode     *int   `json:"exit_code,omitempty"`
	PID          int    `json:"pid,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	Step         string `json:"step,omitempty"`
	Stderr       string `json:"stderr,omitempty"`
	StopReason   string `json:"stop_reason,omitempty"`
	CancelledFor string `json:"cancelled_for,omitempty"`
	Cap          int64  `json:"cap,omitempty"`
	CapUnit      string `json:"cap_unit,omitempty"`
	Spend        int64  `json:"spend,omitempty"`
	SpendUnit    string `json:"spend_unit,omitempty"`
	Source       string `json:"source,omitempty"`
	ModelTag     string `json:"model_tag,omitempty"`
}

func (s *wakeScheduler) storePath() string {
	if s == nil || s.d == nil || s.d.dataDir == "" {
		return ""
	}
	return filepath.Join(s.d.dataDir, wakeStoreFile)
}

func (s *wakeScheduler) loadFromDisk() {
	path := s.storePath()
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) && s.d != nil && s.d.log != nil {
			s.d.log.Warn("wake.json read", "err", err)
		}
		return
	}
	var df wakeDiskFile
	if err := json.Unmarshal(b, &df); err != nil {
		if s.d != nil && s.d.log != nil {
			s.d.log.Warn("wake.json parse", "err", err)
		}
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindings = make(map[a2al.Address]wakeBinding, len(df.Bindings))
	s.handles = make(map[a2al.Address]string)
	s.delivered = make(map[a2al.Address]wakeDelivered)
	s.last = make(map[a2al.Address]wakeLastResult)
	for _, row := range df.Bindings {
		aid, err := a2al.ParseAddress(row.AID)
		if err != nil || row.Cmd == "" {
			continue
		}
		via, err := normalizeWakeVia(row.Via)
		if err != nil {
			via = "exec"
		}
		s.bindings[aid] = wakeBinding{
			AID:        aid,
			Via:        via,
			Cmd:        row.Cmd,
			Args:       append([]string(nil), row.Args...),
			Cwd:        row.Cwd,
			SessionCwd: row.SessionCwd,
			Cap:        row.Cap,
		}
	}
	for _, row := range df.State {
		aid, err := a2al.ParseAddress(row.AID)
		if err != nil {
			continue
		}
		if row.Handle != "" {
			s.handles[aid] = row.Handle
		}
		s.delivered[aid] = row.Delivered
		if row.Last != nil {
			s.last[aid] = lastFromDisk(*row.Last)
		}
	}
}

func (s *wakeScheduler) putBinding(b wakeBinding) error {
	if s == nil {
		return errNotFound
	}
	s.mu.Lock()
	s.bindings[b.AID] = b
	s.mu.Unlock()
	return s.saveToDisk()
}

func (s *wakeScheduler) removeBinding(aid a2al.Address) {
	if s == nil {
		return
	}
	s.mu.Lock()
	_, ok := s.bindings[aid]
	if ok {
		delete(s.bindings, aid)
		w := s.windows[aid]
		delete(s.windows, aid)
		stopWakeWindow(w)
	}
	delete(s.handles, aid)
	delete(s.delivered, aid)
	delete(s.last, aid)
	delete(s.outgoing, aid)
	delete(s.busy, aid)
	delete(s.held, aid)
	s.mu.Unlock()
	if ok {
		_ = s.saveToDisk()
	}
}

func (s *wakeScheduler) saveToDisk() error {
	path := s.storePath()
	if path == "" {
		return nil
	}
	s.mu.Lock()
	aids := make([]string, 0, len(s.bindings))
	byAID := make(map[string]a2al.Address, len(s.bindings))
	for aid := range s.bindings {
		k := aid.String()
		aids = append(aids, k)
		byAID[k] = aid
	}
	sort.Strings(aids)
	df := wakeDiskFile{
		Bindings: make([]wakeDiskBinding, 0, len(aids)),
		State:    make([]wakeDiskState, 0),
	}
	seen := make(map[a2al.Address]struct{})
	for _, k := range aids {
		aid := byAID[k]
		b := s.bindings[aid]
		df.Bindings = append(df.Bindings, wakeDiskBinding{
			AID:        b.AID.String(),
			Via:        b.Via,
			Cmd:        b.Cmd,
			Args:       append([]string(nil), b.Args...),
			Cwd:        b.Cwd,
			SessionCwd: b.SessionCwd,
			Cap:        b.Cap,
		})
		st := diskStateLocked(s, aid)
		if st.Handle != "" || st.Last != nil || st.Delivered.HasInvites || st.Delivered.HasMailbox ||
			len(st.Delivered.Peers) > 0 || len(st.Delivered.Groups) > 0 {
			df.State = append(df.State, st)
		}
		seen[aid] = struct{}{}
	}
	extra := make([]string, 0)
	for aid := range s.handles {
		if _, ok := seen[aid]; !ok {
			extra = append(extra, aid.String())
		}
	}
	for aid := range s.delivered {
		if _, ok := seen[aid]; !ok {
			extra = append(extra, aid.String())
		}
	}
	for aid := range s.last {
		if _, ok := seen[aid]; !ok {
			extra = append(extra, aid.String())
		}
	}
	sort.Strings(extra)
	prev := ""
	for _, k := range extra {
		if k == prev {
			continue
		}
		prev = k
		aid, err := a2al.ParseAddress(k)
		if err != nil {
			continue
		}
		st := diskStateLocked(s, aid)
		if st.Handle != "" || st.Last != nil || st.Delivered.HasInvites || st.Delivered.HasMailbox ||
			len(st.Delivered.Peers) > 0 || len(st.Delivered.Groups) > 0 {
			df.State = append(df.State, st)
		}
	}
	s.mu.Unlock()
	raw, err := json.MarshalIndent(df, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func diskStateLocked(s *wakeScheduler, aid a2al.Address) wakeDiskState {
	st := wakeDiskState{AID: aid.String(), Handle: s.handles[aid], Delivered: s.delivered[aid]}
	if last, ok := s.last[aid]; ok && (!last.At.IsZero() || last.Error != "" || last.Spend > 0 || last.Cap > 0 || last.PID > 0 || last.SessionID != "") {
		dl := lastToDisk(last)
		st.Last = &dl
	}
	return st
}

func lastToDisk(last wakeLastResult) wakeDiskLast {
	d := wakeDiskLast{
		Ok:           last.Ok,
		Error:        last.Error,
		ExitCode:     last.ExitCode,
		PID:          last.PID,
		SessionID:    last.SessionID,
		Step:         last.Step,
		Stderr:       last.Stderr,
		StopReason:   last.StopReason,
		CancelledFor: last.CancelledFor,
		Cap:          last.Cap,
		CapUnit:      last.CapUnit,
		Spend:        last.Spend,
		SpendUnit:    last.SpendUnit,
		Source:       last.Source,
		ModelTag:     last.ModelTag,
	}
	if !last.At.IsZero() {
		d.At = last.At.UTC().Format(time.RFC3339Nano)
	}
	if !last.StartedAt.IsZero() {
		d.StartedAt = last.StartedAt.UTC().Format(time.RFC3339Nano)
	}
	return d
}

func lastFromDisk(d wakeDiskLast) wakeLastResult {
	res := wakeLastResult{
		Ok:           d.Ok,
		Error:        d.Error,
		ExitCode:     d.ExitCode,
		PID:          d.PID,
		SessionID:    d.SessionID,
		Step:         d.Step,
		Stderr:       d.Stderr,
		StopReason:   d.StopReason,
		CancelledFor: d.CancelledFor,
		Cap:          d.Cap,
		CapUnit:      d.CapUnit,
		Spend:        d.Spend,
		SpendUnit:    d.SpendUnit,
		Source:       d.Source,
		ModelTag:     d.ModelTag,
	}
	if d.At != "" {
		if t, err := time.Parse(time.RFC3339Nano, d.At); err == nil {
			res.At = t
		}
	}
	if d.StartedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, d.StartedAt); err == nil {
			res.StartedAt = t
		}
	}
	return res
}
