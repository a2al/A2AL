// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"sync"

	"github.com/a2al/a2al"
)

// LoggedEvent is a single entry in the per-AID event log.
type LoggedEvent struct {
	Seq  uint64 // monotonically increasing, per-AID, no gaps within a log's lifetime
	Type string
	Data any
	Ts   int64 // Unix milliseconds UTC — machine-sortable, consistent with entry.ts
}

const eventLogCap = 512

// aidLog is the ring buffer for a single AID.
type aidLog struct {
	mu      sync.RWMutex
	entries [eventLogCap]LoggedEvent
	count   int    // number of entries written (may exceed cap)
	nextSeq uint64 // next seq to assign; 1-based. 0 means uninitialised (treat as 1).
}

func (l *aidLog) ensureSeq() {
	if l.nextSeq == 0 {
		l.nextSeq = 1
	}
}

// append adds an event and returns its assigned seq.
func (l *aidLog) append(evt LoggedEvent) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ensureSeq()
	seq := l.nextSeq
	l.nextSeq++
	evt.Seq = seq
	idx := int(seq) % eventLogCap
	l.entries[idx] = evt
	l.count++
	return seq
}

// since returns all events with Seq > afterSeq, up to the ring capacity.
// afterSeq=0 means from the beginning of what is still buffered.
// Also returns oldest available seq and whether afterSeq was truncated.
func (l *aidLog) since(afterSeq uint64) (events []LoggedEvent, oldestSeq uint64, truncated bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.count == 0 {
		return nil, 0, false
	}
	last := l.nextSeq - 1
	oldest := uint64(1)
	if last > eventLogCap {
		oldest = last - eventLogCap + 1
	}

	// A cursor below the ring window fell off the back. A cursor above the
	// newest seq is from a previous daemon run: the log lives in memory, so a
	// restart resets numbering to 1 and every stale cursor points into a future
	// that will not arrive. Both mean "your cursor is unusable"; saying so lets
	// the client resync instead of waiting forever on a silent stream.
	if afterSeq != 0 && (afterSeq < oldest || afterSeq > last) {
		truncated = true
	}

	start := afterSeq + 1
	if start < oldest || truncated {
		start = oldest
	}

	for seq := start; seq <= last; seq++ {
		idx := int(seq) % eventLogCap
		events = append(events, l.entries[idx])
	}
	return events, oldest, truncated
}

// EventLog holds per-AID ring-buffer event logs.
//
// It also drives SSE live streams: after each Append the log notifies all
// registered watchers for that AID via a buffered channel (capacity 1).
// Watchers call Since to pull the new events.  This design eliminates the
// EventBus→SSE race that existed when both subscribed to the bus independently.
type EventLog struct {
	mu        sync.RWMutex
	logs      map[a2al.Address]*aidLog
	notifiers map[a2al.Address][]chan struct{} // per-AID watcher channels
}

// NewEventLog creates a new EventLog.
func NewEventLog() *EventLog {
	return &EventLog{
		logs:      make(map[a2al.Address]*aidLog),
		notifiers: make(map[a2al.Address][]chan struct{}),
	}
}

func (el *EventLog) getOrCreate(aid a2al.Address) *aidLog {
	el.mu.RLock()
	l := el.logs[aid]
	el.mu.RUnlock()
	if l != nil {
		return l
	}
	el.mu.Lock()
	defer el.mu.Unlock()
	if el.logs[aid] == nil {
		el.logs[aid] = &aidLog{}
	}
	return el.logs[aid]
}

// Append records an event for the given AID and notifies any active watchers.
// Returns the assigned monotonic sequence number.
func (el *EventLog) Append(aid a2al.Address, evt LoggedEvent) uint64 {
	seq := el.getOrCreate(aid).append(evt)
	// Notify watchers. We hold the write lock only long enough to snapshot the
	// slice; each send is non-blocking (capacity-1 channel, no-op if already signalled).
	el.mu.RLock()
	chs := el.notifiers[aid]
	el.mu.RUnlock()
	for _, c := range chs {
		select {
		case c <- struct{}{}:
		default:
		}
	}
	return seq
}

// Watch registers a watcher for the given AID. The returned channel receives
// a struct{} whenever new events are appended; the channel has capacity 1 so
// multiple rapid appends coalesce into a single notification. The caller must
// call the returned cancel function when done to release the channel.
func (el *EventLog) Watch(aid a2al.Address) (<-chan struct{}, func()) {
	c := make(chan struct{}, 1)
	el.mu.Lock()
	el.notifiers[aid] = append(el.notifiers[aid], c)
	el.mu.Unlock()
	return c, func() {
		el.mu.Lock()
		defer el.mu.Unlock()
		chs := el.notifiers[aid]
		for i, ch := range chs {
			if ch == c {
				el.notifiers[aid] = append(chs[:i], chs[i+1:]...)
				break
			}
		}
	}
}

// Since returns events for aid with seq > afterSeq.
// Returns (events, oldestSeq, truncated).
func (el *EventLog) Since(aid a2al.Address, afterSeq uint64) ([]LoggedEvent, uint64, bool) {
	el.mu.RLock()
	l := el.logs[aid]
	el.mu.RUnlock()
	if l == nil {
		return nil, 0, false
	}
	return l.since(afterSeq)
}
