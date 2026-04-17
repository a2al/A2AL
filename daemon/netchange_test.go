// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2al/a2al/config"
)

func TestPruneFlapTimesLocked(t *testing.T) {
	now := time.Now()
	d := &Daemon{
		netChangeTimes: []time.Time{
			now.Add(-3 * netFlapWindow),
			now.Add(-netFlapWindow - time.Second),
			now.Add(-netFlapWindow + time.Second),
			now.Add(-10 * time.Second),
		},
	}
	d.pruneFlapTimesLocked(now)
	if got, want := len(d.netChangeTimes), 2; got != want {
		t.Fatalf("prune flap times: got %d, want %d", got, want)
	}
	if !d.netChangeTimes[0].Equal(now.Add(-netFlapWindow + time.Second)) {
		t.Fatal("unexpected first retained flap time")
	}
}

func TestInFlapModeLocked(t *testing.T) {
	now := time.Now()
	d := &Daemon{
		netChangeTimes: []time.Time{
			now.Add(-30 * time.Second),
			now.Add(-20 * time.Second),
			now.Add(-10 * time.Second),
		},
	}
	if !d.inFlapModeLocked(now) {
		t.Fatal("expected flap mode true")
	}
}

func TestShouldDeferNodePublishLocked_Flapping(t *testing.T) {
	now := time.Now()
	d := &Daemon{
		netChangeTimes: []time.Time{
			now.Add(-30 * time.Second),
			now.Add(-20 * time.Second),
			now.Add(-10 * time.Second),
		},
	}
	deferNow, reason := d.shouldDeferNodePublishLocked(now)
	if !deferNow {
		t.Fatal("expected defer in flap mode")
	}
	if reason != "flapping" {
		t.Fatalf("unexpected reason: %s", reason)
	}
	if !d.deferredEndpointEval {
		t.Fatal("deferredEndpointEval should be set in flap mode")
	}
}

func TestShouldDeferNodePublishLocked_PostPublishQuiet(t *testing.T) {
	now := time.Now()
	d := &Daemon{
		nodePublishQuietTill: now.Add(5 * time.Second),
	}
	deferNow, reason := d.shouldDeferNodePublishLocked(now)
	if !deferNow {
		t.Fatal("expected defer in post-publish quiet period")
	}
	if reason != "post_publish_quiet" {
		t.Fatalf("unexpected reason: %s", reason)
	}
	if !d.deferredEndpointEval {
		t.Fatal("deferredEndpointEval should be set in quiet period")
	}
}

func TestShouldDeferNodePublishLocked_MinPublishGap(t *testing.T) {
	now := time.Now()
	d := &Daemon{
		nodeLastPublish: now.Add(-nodePublishMinGap + time.Second),
	}
	deferNow, reason := d.shouldDeferNodePublishLocked(now)
	if !deferNow {
		t.Fatal("expected defer for min publish gap")
	}
	if reason != "min_publish_gap" {
		t.Fatalf("unexpected reason: %s", reason)
	}
	if !d.deferredEndpointEval {
		t.Fatal("deferredEndpointEval should be set for min publish gap")
	}
}

func TestShouldDeferNodePublishLocked_Allowed(t *testing.T) {
	now := time.Now()
	d := &Daemon{
		nodeLastPublish: now.Add(-nodePublishMinGap - time.Second),
	}
	deferNow, reason := d.shouldDeferNodePublishLocked(now)
	if deferNow {
		t.Fatalf("expected no defer, got reason %s", reason)
	}
}

func TestTryConsumeNetChangeEvent(t *testing.T) {
	d := &Daemon{
		netChangeNotify: make(chan struct{}, 1),
	}
	if d.tryConsumeNetChangeEvent() {
		t.Fatal("unexpected event consume from empty channel")
	}
	d.netChangeNotify <- struct{}{}
	if !d.tryConsumeNetChangeEvent() {
		t.Fatal("expected event consume success")
	}
	if d.tryConsumeNetChangeEvent() {
		t.Fatal("channel should be empty after consume")
	}
}

func TestPollNetworkFingerprint_DebounceResampleStable_NoEvent(t *testing.T) {
	now := time.Now()
	step := int32(0)
	d := &Daemon{
		netChangeNotify: make(chan struct{}, 1),
		netFingerprintFn: func() string {
			// first poll sees change (B), debounce re-sample returns stable (A)
			if atomic.AddInt32(&step, 1) >= 2 {
				return "A"
			}
			return "B"
		},
		testNowFn:    func() time.Time { return now },
		netStableFP:  "A",
		netPendingFP: "B",
		netPendingAt: now.Add(-netDebounceBase - time.Second),
	}
	d.pollNetworkFingerprint()
	if d.netStableFP != "A" {
		t.Fatalf("stable fp changed unexpectedly: %s", d.netStableFP)
	}
	if d.tryConsumeNetChangeEvent() {
		t.Fatal("should not emit network-change event when re-sample returns stable")
	}
}

func TestPollNetworkFingerprint_DebounceConfirmed_EmitEvent(t *testing.T) {
	now := time.Now()
	d := &Daemon{
		netChangeNotify:  make(chan struct{}, 1),
		netFingerprintFn: func() string { return "B" },
		testNowFn:        func() time.Time { return now },
		netStableFP:      "A",
		netPendingFP:     "B",
		netPendingAt:     now.Add(-netDebounceBase - time.Second),
	}
	d.pollNetworkFingerprint()
	if d.netStableFP != "B" {
		t.Fatalf("stable fp not updated: %s", d.netStableFP)
	}
	if !d.tryConsumeNetChangeEvent() {
		t.Fatal("expected confirmed network-change event")
	}
}

func TestHandleGuardTick_QuietCompensationAndCascade(t *testing.T) {
	now := time.Now()
	var republishCalls int32
	cascadeStarted := make(chan struct{}, 1)
	cascadeRelease := make(chan struct{})
	d := &Daemon{
		netChangeNotify:      make(chan struct{}, 1),
		deferredEndpointEval: true,
		nodePublishQuietTill: now.Add(-time.Second),
		testNowFn:            func() time.Time { return now },
		testGuardRepublishFn: func(context.Context) { atomic.AddInt32(&republishCalls, 1) },
		testGuardCascadeFn: func(context.Context) {
			cascadeStarted <- struct{}{}
			<-cascadeRelease
		},
	}
	// No pending event: deferred eval should fire a republish.
	d.handleGuardTick(context.Background())
	if got := atomic.LoadInt32(&republishCalls); got != 1 {
		t.Fatalf("republish calls: got %d, want 1", got)
	}

	// Now add a cascade event: republish must NOT fire again (cascade owns it).
	d.deferredEndpointEval = true
	d.netChangeNotify <- struct{}{}
	d.handleGuardTick(context.Background())
	// Cascade must have started.
	select {
	case <-cascadeStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cascade did not start")
	}
	// Republish should NOT have been called a second time.
	if got := atomic.LoadInt32(&republishCalls); got != 1 {
		t.Fatalf("republish should not be called when cascade is pending: got %d", got)
	}
	close(cascadeRelease)
}

func TestShouldDeferNodePublishLocked_FlapEnterExit_TimeProgression(t *testing.T) {
	now := time.Now()
	d := &Daemon{}

	// Not flapping: only two recent events (< threshold).
	d.netChangeTimes = []time.Time{
		now.Add(-40 * time.Second),
		now.Add(-20 * time.Second),
	}
	deferNow, reason := d.shouldDeferNodePublishLocked(now)
	if deferNow {
		t.Fatalf("unexpected defer before flap threshold, reason=%s", reason)
	}

	// Enter flap mode: third event within flap window.
	d.netChangeTimes = append(d.netChangeTimes, now.Add(-5*time.Second))
	deferNow, reason = d.shouldDeferNodePublishLocked(now)
	if !deferNow || reason != "flapping" {
		t.Fatalf("expected flapping defer, got defer=%v reason=%s", deferNow, reason)
	}

	// Exit flap mode after window passes: old events should be pruned.
	later := now.Add(netFlapWindow + 2*time.Second)
	deferNow, reason = d.shouldDeferNodePublishLocked(later)
	if deferNow {
		t.Fatalf("unexpected defer after flap window elapsed, reason=%s", reason)
	}
}

func TestPollNetworkFingerprint_FlapDebounce_TableDriven(t *testing.T) {
	base := time.Now()
	cases := []struct {
		name          string
		changeTimes   []time.Time
		pendingSince  time.Time
		expectConfirm bool
	}{
		{
			name: "non-flap uses base debounce and confirms",
			changeTimes: []time.Time{
				base.Add(-3 * time.Minute), // pruned
				base.Add(-50 * time.Second),
			},
			pendingSince:  base.Add(-netDebounceBase - time.Second),
			expectConfirm: true,
		},
		{
			name: "flap mode requires extended debounce and blocks early confirm",
			changeTimes: []time.Time{
				base.Add(-60 * time.Second),
				base.Add(-40 * time.Second),
				base.Add(-20 * time.Second),
			},
			pendingSince:  base.Add(-netDebounceBase - time.Second), // enough for base, not enough for flap debounce
			expectConfirm: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			d := &Daemon{
				netChangeNotify:  make(chan struct{}, 1),
				netFingerprintFn: func() string { return "B" },
				testNowFn:        func() time.Time { return base },
				netStableFP:      "A",
				netPendingFP:     "B",
				netPendingAt:     tc.pendingSince,
				netChangeTimes:   append([]time.Time(nil), tc.changeTimes...),
			}
			d.pollNetworkFingerprint()
			gotEvent := d.tryConsumeNetChangeEvent()
			if gotEvent != tc.expectConfirm {
				t.Fatalf("event confirm mismatch: got %v, want %v", gotEvent, tc.expectConfirm)
			}
		})
	}
}

func TestStartCascadeAsync_SingleFlight(t *testing.T) {
	d := &Daemon{}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls int32
	d.testGuardCascadeFn = func(context.Context) {
		atomic.AddInt32(&calls, 1)
		started <- struct{}{}
		<-release
	}

	// Reuse guard path to verify event-triggered single-flight behavior.
	d.netChangeNotify = make(chan struct{}, 1)
	d.netChangeNotify <- struct{}{}
	d.handleGuardTick(context.Background())
	<-started

	// Second trigger during in-flight run should be dropped.
	d.netChangeNotify <- struct{}{}
	d.handleGuardTick(context.Background())
	select {
	case <-started:
		t.Fatal("unexpected second cascade start while first is running")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	time.Sleep(20 * time.Millisecond)

	// After first run exits, next event should start another cascade.
	release2 := make(chan struct{})
	d.testGuardCascadeFn = func(context.Context) {
		atomic.AddInt32(&calls, 1)
		started <- struct{}{}
		<-release2
	}
	d.netChangeNotify <- struct{}{}
	d.handleGuardTick(context.Background())
	<-started
	close(release2)

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("cascade calls: got %d, want 2", got)
	}
}

// TestHandleGuardTick_NoDualRepublishWhenCascadePending verifies that when a
// cascade event is pending, handleGuardTick does NOT simultaneously start a
// direct republish.  Concurrent republish + cascade would race on
// nodePublishSeq (both computing nextSeq = N+1) and the second one would
// receive ErrStaleRecord, re-setting deferredEndpointEval to true.
func TestHandleGuardTick_NoDualRepublishWhenCascadePending(t *testing.T) {
	now := time.Now()
	var republishCalls int32
	cascadeStarted := make(chan struct{}, 1)
	cascadeRelease := make(chan struct{})
	d := &Daemon{
		netChangeNotify:      make(chan struct{}, 1),
		deferredEndpointEval: true,
		nodePublishQuietTill: now.Add(-time.Second),
		testNowFn:            func() time.Time { return now },
		testGuardRepublishFn: func(context.Context) { atomic.AddInt32(&republishCalls, 1) },
		testGuardCascadeFn: func(context.Context) {
			cascadeStarted <- struct{}{}
			<-cascadeRelease
		},
	}
	d.netChangeNotify <- struct{}{}
	d.handleGuardTick(context.Background())

	// Cascade must have started.
	select {
	case <-cascadeStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cascade did not start")
	}

	// Direct republish must NOT have been triggered — cascade is responsible.
	if got := atomic.LoadInt32(&republishCalls); got != 0 {
		t.Fatalf("republish should not fire when cascade pending: got %d calls", got)
	}
	close(cascadeRelease)
}

func TestHandleGuardTick_FlapModeSuppressesDirectRepublish(t *testing.T) {
	now := time.Now()
	var republishCalls int32
	d := &Daemon{
		netChangeNotify:      make(chan struct{}, 1),
		deferredEndpointEval: true,
		nodePublishQuietTill: now.Add(-time.Second),
		testNowFn:            func() time.Time { return now },
		testGuardRepublishFn: func(context.Context) { atomic.AddInt32(&republishCalls, 1) },
		testGuardCascadeFn:   func(context.Context) {},
		netChangeTimes: []time.Time{
			now.Add(-40 * time.Second),
			now.Add(-20 * time.Second),
			now.Add(-5 * time.Second),
		},
	}
	d.handleGuardTick(context.Background())
	if got := atomic.LoadInt32(&republishCalls); got != 0 {
		t.Fatalf("republish should be suppressed in flap mode: got %d calls", got)
	}
}

func TestMaybeRepublishNodeOnEndpointChange_AutoPublishOffClearsDeferredFlag(t *testing.T) {
	d := &Daemon{
		cfg: &config.Config{AutoPublish: false},
	}
	d.netMu.Lock()
	d.deferredEndpointEval = true
	d.netMu.Unlock()

	d.maybeRepublishNodeOnEndpointChange(context.Background())

	d.netMu.Lock()
	defer d.netMu.Unlock()
	if d.deferredEndpointEval {
		t.Fatal("deferred flag should be cleared when auto_publish is disabled")
	}
}
