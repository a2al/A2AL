// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package logedge gates repetitive condition logs: emit on the edge (first
// sight or signature change), optionally a sparse pulse while the condition
// holds, and once more when it clears.
//
// Use it for periodic probes that fail the same way on every tick. Callers
// still own the slog line; this package only answers whether to print and
// with what counters. It is not a logger and not a retry scheduler.
package logedge

import (
	"sync"
	"time"
)

// Event says why a Result should (or should not) be logged.
type Event int

const (
	// Skip: same signature, pulse not due.
	Skip Event = iota
	// Rise: first observation, or the signature changed.
	Rise
	// Hold: same signature, Repeat elapsed since the last emission.
	Hold
	// Fall: Clear after a recorded condition.
	Fall
)

// Result is the decision for one Observe or Clear call.
type Result struct {
	Event Event
	// Streak is consecutive Observe hits for the current signature
	// (Fall: streak at the moment of Clear).
	Streak int
	Since  time.Time
	// Suppressed is how many Observe calls were skipped since the last
	// emission (Hold/Fall). Zero on Rise.
	Suppressed int
}

// Gate tracks per-key signatures. A zero Gate is ready to use (Repeat=0
// means edge-only: Rise/Fall, never Hold).
type Gate struct {
	// Repeat is the minimum interval between Hold pulses. Zero disables them.
	Repeat time.Duration

	now func() time.Time
	mu  sync.Mutex
	m   map[string]*ent
}

type ent struct {
	sig        string
	streak     int
	since      time.Time
	lastLog    time.Time
	suppressed int
}

func (g *Gate) tick() time.Time {
	if g != nil && g.now != nil {
		return g.now()
	}
	return time.Now()
}

func (g *Gate) ensure() {
	if g.m == nil {
		g.m = make(map[string]*ent)
	}
}

// Observe records that key currently has signature sig.
func (g *Gate) Observe(key, sig string) Result {
	if g == nil {
		return Result{Event: Rise, Streak: 1}
	}
	now := g.tick()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ensure()

	e, ok := g.m[key]
	if !ok || e.sig != sig {
		g.m[key] = &ent{sig: sig, streak: 1, since: now, lastLog: now}
		return Result{Event: Rise, Streak: 1, Since: now}
	}
	e.streak++
	if g.Repeat > 0 && now.Sub(e.lastLog) >= g.Repeat {
		n := e.suppressed
		e.suppressed = 0
		e.lastLog = now
		return Result{Event: Hold, Streak: e.streak, Since: e.since, Suppressed: n}
	}
	e.suppressed++
	return Result{Event: Skip, Streak: e.streak, Since: e.since, Suppressed: e.suppressed}
}

// Clear drops key. Fall if it was tracked, otherwise Skip.
func (g *Gate) Clear(key string) Result {
	if g == nil {
		return Result{Event: Skip}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.m == nil {
		return Result{Event: Skip}
	}
	e, ok := g.m[key]
	if !ok {
		return Result{Event: Skip}
	}
	delete(g.m, key)
	return Result{Event: Fall, Streak: e.streak, Since: e.since, Suppressed: e.suppressed}
}
