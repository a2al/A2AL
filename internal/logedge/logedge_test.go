// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package logedge

import (
	"testing"
	"time"
)

func TestObserveRiseSkipHold(t *testing.T) {
	g := &Gate{Repeat: time.Minute}
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }

	r := g.Observe("k", "no_endpoint")
	if r.Event != Rise || r.Streak != 1 {
		t.Fatalf("first: %+v", r)
	}

	r = g.Observe("k", "no_endpoint")
	if r.Event != Skip || r.Streak != 2 || r.Suppressed != 1 {
		t.Fatalf("repeat: %+v", r)
	}

	now = now.Add(time.Minute)
	r = g.Observe("k", "no_endpoint")
	if r.Event != Hold || r.Streak != 3 || r.Suppressed != 1 {
		t.Fatalf("pulse: %+v", r)
	}
}

func TestObserveSigChangeIsRise(t *testing.T) {
	g := &Gate{Repeat: time.Hour}
	r := g.Observe("k", "no_endpoint")
	if r.Event != Rise {
		t.Fatalf("first: %+v", r)
	}
	r = g.Observe("k", "timeout")
	if r.Event != Rise || r.Streak != 1 {
		t.Fatalf("class change: %+v", r)
	}
}

func TestRepeatZeroNeverHold(t *testing.T) {
	g := &Gate{}
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	_ = g.Observe("k", "e")
	now = now.Add(time.Hour)
	r := g.Observe("k", "e")
	if r.Event != Skip {
		t.Fatalf("edge-only: %+v", r)
	}
}

func TestClearFallThenSkip(t *testing.T) {
	g := &Gate{}
	_ = g.Observe("k", "e")
	r := g.Clear("k")
	if r.Event != Fall || r.Streak != 1 {
		t.Fatalf("clear: %+v", r)
	}
	r = g.Clear("k")
	if r.Event != Skip {
		t.Fatalf("second clear: %+v", r)
	}
}

func TestNilGate(t *testing.T) {
	var g *Gate
	if r := g.Observe("k", "e"); r.Event != Rise {
		t.Fatalf("nil observe: %+v", r)
	}
	if r := g.Clear("k"); r.Event != Skip {
		t.Fatalf("nil clear: %+v", r)
	}
}
