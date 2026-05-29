// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package retry

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSchedulerDoneRemoves verifies that an attempt returning Done removes the
// key and Run returns once the set drains.
func TestSchedulerDoneRemoves(t *testing.T) {
	var calls int32
	s := New[string](Policy{Base: 5 * time.Millisecond}, func(_ context.Context, _ string) Outcome {
		atomic.AddInt32(&calls, 1)
		return Done
	}, nil)
	s.Add("a")
	s.Add("b")

	done := make(chan struct{})
	go func() { s.Run(context.Background()); close(done) }()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after keys finished")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("attempt calls = %d, want 2", got)
	}
	if s.Len() != 0 {
		t.Fatalf("Len = %d, want 0", s.Len())
	}
}

// TestSchedulerDedup verifies Add on an existing key does not create a second
// entry.
func TestSchedulerDedup(t *testing.T) {
	s := New[string](Policy{Base: time.Hour}, func(_ context.Context, _ string) Outcome { return Again }, nil)
	s.Add("a")
	s.Add("a")
	s.Add("a")
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1 after dedup", s.Len())
	}
}

// TestSchedulerRetriesThenSucceeds verifies a key that returns Again is retried
// on the Base interval until it returns Done.
func TestSchedulerRetriesThenSucceeds(t *testing.T) {
	var calls int32
	s := New[string](Policy{Base: 5 * time.Millisecond}, func(_ context.Context, _ string) Outcome {
		if atomic.AddInt32(&calls, 1) < 3 {
			return Again
		}
		return Done
	}, nil)
	s.Add("a")

	done := make(chan struct{})
	go func() { s.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("attempt calls = %d, want 3", got)
	}
}

// TestSchedulerGiveUp verifies MaxAttempts abandons a key and fires onGiveUp.
func TestSchedulerGiveUp(t *testing.T) {
	var gaveUp atomic.Bool
	s := New[string](Policy{Base: 2 * time.Millisecond, MaxAttempts: 3},
		func(_ context.Context, _ string) Outcome { return Again },
		func(_ string) { gaveUp.Store(true) },
	)
	s.Add("a")

	done := make(chan struct{})
	go func() { s.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after give-up")
	}
	if !gaveUp.Load() {
		t.Fatal("onGiveUp was not called")
	}
	if s.Len() != 0 {
		t.Fatalf("Len = %d, want 0 after give-up", s.Len())
	}
}

// TestSchedulerTriggerImmediate verifies Trigger fires an attempt promptly even
// when Base is large.
func TestSchedulerTriggerImmediate(t *testing.T) {
	fired := make(chan struct{}, 1)
	s := New[string](Policy{Base: time.Hour}, func(_ context.Context, _ string) Outcome {
		select {
		case fired <- struct{}{}:
		default:
		}
		return Done
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Trigger("a")
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("Trigger did not fire an attempt promptly")
	}
}

// TestSchedulerContextCancel verifies Run returns when ctx is cancelled even
// while keys remain.
func TestSchedulerContextCancel(t *testing.T) {
	s := New[string](Policy{Base: 5 * time.Millisecond}, func(_ context.Context, _ string) Outcome { return Again }, nil)
	s.Add("a")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// TestSchedulerConcurrentAdd exercises the lock paths under concurrent mutation
// while Run drives attempts (use -race).
func TestSchedulerConcurrentAdd(t *testing.T) {
	s := New[int](Policy{Base: time.Millisecond}, func(_ context.Context, _ int) Outcome { return Done }, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go s.Run(ctx)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			s.Add(k)
			s.Trigger(k)
		}(i)
	}
	wg.Wait()
}
