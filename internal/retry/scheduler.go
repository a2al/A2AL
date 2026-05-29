// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package retry provides a small generic scheduler for re-attempting a set of
// keyed targets with per-key backoff, deduplication and immediate-trigger
// support.
//
// It exists so that components needing the same shape of work — "keep trying
// this set of targets on a schedule until each one succeeds or the policy gives
// up" — share one tested implementation instead of each reinventing a ticker +
// backoff + dedup loop. Examples: retrying trusted bootstrap seeds during a
// cold start, or re-probing temporarily unreachable peers.
//
// It is deliberately scoped to active periodic scheduling. It is not meant to
// replace in-call synchronous retries (a single request/response round trip)
// nor passive suppression gates (negative caches), which have different shapes.
package retry

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// Outcome reports the result of one attempt against a key.
type Outcome int

const (
	// Again means the attempt did not succeed; the key is rescheduled with
	// backoff, subject to the give-up policy.
	Again Outcome = iota
	// Done means the key is finished (succeeded, or should be abandoned by the
	// attempt itself); it is removed from the scheduler.
	Done
)

// Policy controls retry timing and give-up conditions. The zero value yields a
// constant 1s interval that never gives up.
type Policy struct {
	// Base is the delay before the first retry and the minimum delay.
	Base time.Duration
	// Max caps the backoff delay. Zero means no cap (delay grows unbounded with Factor).
	Max time.Duration
	// Factor multiplies the delay after each failed attempt. Values <= 1 keep
	// the interval constant at Base.
	Factor float64
	// Jitter applies a random +/- fraction (0..1) to each computed delay.
	Jitter float64
	// MaxElapsed abandons a key this long after it was first added. Zero means
	// no time limit (rely on Run's context or Done).
	MaxElapsed time.Duration
	// MaxAttempts abandons a key after this many attempts. Zero means no limit.
	MaxAttempts int
}

func (p Policy) firstDelay() time.Duration {
	if p.Base <= 0 {
		return time.Second
	}
	return p.Base
}

func (p Policy) nextDelay(cur time.Duration) time.Duration {
	d := cur
	if p.Factor > 1 {
		d = time.Duration(float64(cur) * p.Factor)
	}
	if p.Max > 0 && d > p.Max {
		d = p.Max
	}
	if d <= 0 {
		d = p.firstDelay()
	}
	return d
}

func (p Policy) jittered(d time.Duration) time.Duration {
	if p.Jitter <= 0 {
		return d
	}
	f := 1 + p.Jitter*(2*rand.Float64()-1)
	if f < 0 {
		f = 0
	}
	return time.Duration(float64(d) * f)
}

type entry struct {
	firstAt  time.Time
	nextAt   time.Time
	delay    time.Duration
	attempts int
	inFlight bool
}

// Scheduler retries a set of keyed targets. The zero value is not usable; call
// New. A Scheduler is safe for concurrent use.
type Scheduler[K comparable] struct {
	policy   Policy
	attempt  func(ctx context.Context, key K) Outcome
	onGiveUp func(key K) // optional; invoked when the policy abandons a key

	mu      sync.Mutex
	entries map[K]*entry
	wake    chan struct{}
}

// New creates a Scheduler. attempt is invoked (each in its own goroutine) for
// every due key and its Outcome decides removal vs reschedule. onGiveUp, if
// non-nil, is called when the policy abandons a key (it never fires for keys
// that finish with Done or are explicitly Removed).
func New[K comparable](p Policy, attempt func(ctx context.Context, key K) Outcome, onGiveUp func(key K)) *Scheduler[K] {
	return &Scheduler[K]{
		policy:   p,
		attempt:  attempt,
		onGiveUp: onGiveUp,
		entries:  make(map[K]*entry),
		wake:     make(chan struct{}, 1),
	}
}

// Add schedules key for a first attempt after Policy.Base. If key is already
// scheduled it is left unchanged (dedup).
func (s *Scheduler[K]) Add(key K) {
	now := time.Now()
	s.mu.Lock()
	if _, ok := s.entries[key]; !ok {
		d := s.policy.firstDelay()
		s.entries[key] = &entry{firstAt: now, delay: d, nextAt: now.Add(d)}
	}
	s.mu.Unlock()
	s.signal()
}

// Trigger schedules key for an immediate attempt, adding it if absent and
// bringing forward an already-scheduled (not in-flight) entry. One entry per
// key is kept (dedup). If the key is currently in-flight the trigger is a
// no-op: the in-flight attempt's outcome will schedule the next round normally.
func (s *Scheduler[K]) Trigger(key K) {
	now := time.Now()
	s.mu.Lock()
	if e, ok := s.entries[key]; ok {
		if !e.inFlight {
			e.nextAt = now
		}
	} else {
		s.entries[key] = &entry{firstAt: now, delay: s.policy.firstDelay(), nextAt: now}
	}
	s.mu.Unlock()
	s.signal()
}

// Remove drops key from the scheduler. Safe to call for unknown keys.
func (s *Scheduler[K]) Remove(key K) {
	s.mu.Lock()
	delete(s.entries, key)
	s.mu.Unlock()
	s.signal()
}

// Len returns the number of scheduled keys.
func (s *Scheduler[K]) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *Scheduler[K]) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run drives the scheduler until ctx is cancelled or no keys remain. It blocks;
// callers typically launch it in a goroutine. In-flight attempts are not
// cancelled by Run returning — they observe ctx via the value passed to attempt.
func (s *Scheduler[K]) Run(ctx context.Context) {
	for {
		s.mu.Lock()
		empty := len(s.entries) == 0
		next, has := s.earliestLocked()
		s.mu.Unlock()
		if empty {
			return
		}
		var c <-chan time.Time
		var timer *time.Timer
		if has {
			d := time.Until(next)
			if d < 0 {
				d = 0
			}
			timer = time.NewTimer(d)
			c = timer.C
		}
		// When has=false every entry is in-flight; c is a nil channel so only
		// ctx.Done and wake are selectable. runAttempt always calls signal() on
		// completion, guaranteeing we re-evaluate once an attempt finishes.
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-s.wake:
			if timer != nil {
				timer.Stop()
			}
			// A wake can mean a key became due immediately (e.g. Trigger); fire
			// now instead of looping back to recompute the sleep duration.
			s.fireDue(ctx)
		case <-c:
			timer.Stop()
			s.fireDue(ctx)
		}
	}
}

// earliestLocked returns the soonest nextAt among entries that are not in
// flight. has is false when every entry is in flight (Run then waits on wake).
func (s *Scheduler[K]) earliestLocked() (next time.Time, has bool) {
	for _, e := range s.entries {
		if e.inFlight {
			continue
		}
		if !has || e.nextAt.Before(next) {
			next = e.nextAt
			has = true
		}
	}
	return next, has
}

func (s *Scheduler[K]) fireDue(ctx context.Context) {
	now := time.Now()
	s.mu.Lock()
	var due []K
	for k, e := range s.entries {
		if e.inFlight || e.nextAt.After(now) {
			continue
		}
		e.inFlight = true
		due = append(due, k)
	}
	s.mu.Unlock()
	for _, k := range due {
		go s.runAttempt(ctx, k)
	}
}

func (s *Scheduler[K]) runAttempt(ctx context.Context, key K) {
	out := s.attempt(ctx, key)
	now := time.Now()
	s.mu.Lock()
	e, ok := s.entries[key]
	if !ok {
		// Removed (or finished) concurrently while in flight.
		s.mu.Unlock()
		return
	}
	e.inFlight = false
	e.attempts++

	giveUp := false
	if out == Again {
		if s.policy.MaxAttempts > 0 && e.attempts >= s.policy.MaxAttempts {
			giveUp = true
		}
		if s.policy.MaxElapsed > 0 && now.Sub(e.firstAt) >= s.policy.MaxElapsed {
			giveUp = true
		}
	}
	if out == Done || giveUp {
		delete(s.entries, key)
		s.mu.Unlock()
		if giveUp && s.onGiveUp != nil {
			s.onGiveUp(key)
		}
		s.signal()
		return
	}

	e.delay = s.policy.nextDelay(e.delay)
	e.nextAt = now.Add(s.policy.jittered(e.delay))
	s.mu.Unlock()
	s.signal()
}
