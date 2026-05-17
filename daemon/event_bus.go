// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2al/a2al"
)

// Event is a single daemon-internal event.
// Type follows the naming convention "<domain>.<verb>" (e.g. "mailbox.received").
type Event struct {
	Type string
	AID  a2al.Address // zero = global / not agent-specific
	Data any
	At   time.Time
}

// Filter restricts which events a subscriber receives.
// Empty/zero values match everything in that dimension.
type Filter struct {
	AID   a2al.Address // zero = any AID
	Types []string     // empty = all types
}

func (f Filter) matches(e Event) bool {
	if f.AID != (a2al.Address{}) && f.AID != e.AID {
		return false
	}
	if len(f.Types) == 0 {
		return true
	}
	for _, t := range f.Types {
		if t == e.Type {
			return true
		}
	}
	return false
}

const subChanCap = 64

type subscription struct {
	id     uint64
	filter Filter
	ch     chan Event
}

// EventBus is a simple in-process publish/subscribe bus.
// All methods are safe for concurrent use.
type EventBus struct {
	log  *slog.Logger
	mu   sync.RWMutex
	subs map[uint64]*subscription
	next atomic.Uint64
}

// NewEventBus returns an initialised EventBus.
func NewEventBus(log *slog.Logger) *EventBus {
	return &EventBus{
		log:  log,
		subs: make(map[uint64]*subscription),
	}
}

// Subscribe registers a subscriber with the given filter.
// Returns a receive-only channel and a cancel function.
// The caller must call cancel when done to release resources.
func (b *EventBus) Subscribe(filter Filter) (<-chan Event, func()) {
	id := b.next.Add(1)
	sub := &subscription{
		id:     id,
		filter: filter,
		ch:     make(chan Event, subChanCap),
	}
	b.mu.Lock()
	b.subs[id] = sub
	b.mu.Unlock()
	cancel := func() {
		b.mu.Lock()
		delete(b.subs, id)
		b.mu.Unlock()
	}
	return sub.ch, cancel
}

// Publish delivers evt to all matching subscribers.
// Slow consumers are handled without blocking: if a subscriber's channel is
// full, the oldest event is discarded and the new one is enqueued.
func (b *EventBus) Publish(evt Event) {
	if evt.At.IsZero() {
		evt.At = time.Now()
	}
	b.mu.RLock()
	subs := make([]*subscription, 0, len(b.subs))
	for _, s := range b.subs {
		if s.filter.matches(evt) {
			subs = append(subs, s)
		}
	}
	b.mu.RUnlock()

	for _, s := range subs {
		select {
		case s.ch <- evt:
		default:
			// Channel full: discard oldest, then enqueue.
			select {
			case <-s.ch:
			default:
			}
			select {
			case s.ch <- evt:
			default:
			}
			if b.log != nil {
				b.log.Warn("event_bus: slow subscriber, event dropped", "sub_id", s.id, "type", evt.Type)
			}
		}
	}
}
