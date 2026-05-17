// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"sync"
	"time"

	"github.com/a2al/a2al"
)

// backoffSequence is the poll interval sequence (15s→30s→1m→2m→4m→5m cap).
var backoffSequence = []time.Duration{
	15 * time.Second,
	30 * time.Second,
	1 * time.Minute,
	2 * time.Minute,
	4 * time.Minute,
	5 * time.Minute,
}

type aidSub struct {
	refCount int
	stepIdx  int // index into backoffSequence
	timer    *time.Timer
}

// subscriptionManager manages per-AID backoff poll timers on behalf of SSE subscribers.
// Each SSE connection to /agents/{aid}/events calls Acquire on connect and Release on disconnect.
type subscriptionManager struct {
	mu    sync.Mutex
	byAID map[a2al.Address]*aidSub

	// pollFn is called each time the timer fires.
	// It should fetch new records from DHT and store them (which in turn publishes bus events).
	pollFn func(aid a2al.Address)
}

func newSubscriptionManager(pollFn func(aid a2al.Address)) *subscriptionManager {
	return &subscriptionManager{
		byAID:  make(map[a2al.Address]*aidSub),
		pollFn: pollFn,
	}
}

// Acquire registers a new SSE subscriber for aid.
// On the first subscriber, performs an immediate poll and starts the backoff timer.
func (m *subscriptionManager) Acquire(aid a2al.Address) {
	m.mu.Lock()
	sub := m.byAID[aid]
	if sub == nil {
		sub = &aidSub{}
		m.byAID[aid] = sub
	}
	sub.refCount++
	first := sub.refCount == 1
	m.mu.Unlock()

	if first {
		// Immediate poll on first subscriber.
		go m.pollFn(aid)
		// Start the backoff timer.
		m.scheduleNext(aid)
	}
}

// Release unregisters an SSE subscriber. When refCount reaches zero, the timer is stopped.
func (m *subscriptionManager) Release(aid a2al.Address) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sub := m.byAID[aid]
	if sub == nil {
		return
	}
	sub.refCount--
	if sub.refCount <= 0 {
		if sub.timer != nil {
			sub.timer.Stop()
		}
		delete(m.byAID, aid)
	}
}

// NotifyActivity resets the backoff interval to the minimum for aid.
// Called whenever an activity signal arrives (DHT_PUSH, QUIC direct, explicit poll).
func (m *subscriptionManager) NotifyActivity(aid a2al.Address) {
	m.mu.Lock()
	sub := m.byAID[aid]
	if sub == nil {
		m.mu.Unlock()
		return
	}
	sub.stepIdx = 0
	if sub.timer != nil {
		sub.timer.Reset(backoffSequence[0])
	}
	m.mu.Unlock()
}

// scheduleNext arms the next poll timer for aid.
func (m *subscriptionManager) scheduleNext(aid a2al.Address) {
	m.mu.Lock()
	sub := m.byAID[aid]
	if sub == nil || sub.refCount == 0 {
		m.mu.Unlock()
		return
	}
	interval := backoffSequence[sub.stepIdx]
	if sub.stepIdx < len(backoffSequence)-1 {
		sub.stepIdx++
	}
	if sub.timer != nil {
		sub.timer.Stop()
	}
	sub.timer = time.AfterFunc(interval, func() {
		m.mu.Lock()
		sub2 := m.byAID[aid]
		if sub2 == nil || sub2.refCount == 0 {
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
		// Execute poll in a goroutine to not block the timer goroutine.
		go func() {
			m.pollFn(aid)
			m.scheduleNext(aid)
		}()
	})
	m.mu.Unlock()
}
