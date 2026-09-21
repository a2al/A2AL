// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"testing"

	"github.com/a2al/a2al"
)

func TestEventLog_SinceFromZero(t *testing.T) {
	el := NewEventLog()
	var aid a2al.Address
	aid[0] = 1

	if ev, oldest, trunc := el.Since(aid, 0); len(ev) != 0 || oldest != 0 || trunc {
		t.Fatalf("empty log: events=%d oldest=%d trunc=%v", len(ev), oldest, trunc)
	}

	s1 := el.Append(aid, LoggedEvent{Type: "group.unread", Ts: 1000})
	s2 := el.Append(aid, LoggedEvent{Type: "group.mentioned", Ts: 2000})
	if s1 != 1 || s2 != 2 {
		t.Fatalf("seq: got %d %d, want 1 2", s1, s2)
	}

	ev, oldest, trunc := el.Since(aid, 0)
	if trunc || oldest != 1 || len(ev) != 2 {
		t.Fatalf("after_seq=0: n=%d oldest=%d trunc=%v", len(ev), oldest, trunc)
	}
	if ev[0].Seq != 1 || ev[0].Type != "group.unread" || ev[1].Seq != 2 {
		t.Fatalf("order/content: %+v", ev)
	}

	ev, _, trunc = el.Since(aid, 1)
	if trunc || len(ev) != 1 || ev[0].Seq != 2 {
		t.Fatalf("after_seq=1: n=%d trunc=%v %+v", len(ev), trunc, ev)
	}

	ev, _, _ = el.Since(aid, 2)
	if len(ev) != 0 {
		t.Fatalf("caught up: still %d events", len(ev))
	}
}

// The event log is in memory, so a daemon restart renumbers from 1. A client
// resuming with a cursor from the previous run points past the newest event.
// That must be reported as truncated: silently returning nothing leaves an SSE
// watcher listening forever to a stream that will never reach its cursor.
func TestEventLog_SinceCursorFromPreviousRun(t *testing.T) {
	el := NewEventLog()
	var aid a2al.Address
	aid[0] = 1

	el.Append(aid, LoggedEvent{Type: "group.unread", Ts: 1000})
	el.Append(aid, LoggedEvent{Type: "mailbox.received", Ts: 2000})

	ev, oldest, trunc := el.Since(aid, 62)
	if !trunc {
		t.Error("stale cursor 62 with newest seq 2 was not reported as truncated")
	}
	if oldest != 1 {
		t.Errorf("oldest = %d, want 1", oldest)
	}
	if len(ev) != 2 {
		t.Fatalf("truncated cursor should replay the whole buffer, got %d events", len(ev))
	}
	if ev[0].Seq != 1 || ev[1].Seq != 2 {
		t.Errorf("replay out of order: %+v", ev)
	}
}
