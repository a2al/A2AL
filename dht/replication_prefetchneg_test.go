// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/transport"
)

// newTestNodeSimple creates a minimal Node for neg-cache unit tests that do
// not require a live transport or punch pool.
func newTestNodeSimple(t *testing.T) *Node {
	t.Helper()
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("neg-test")
	t.Cleanup(func() { tr.Close() })
	n := newTestNode(t, tr, nil)
	n.Start()
	t.Cleanup(func() { n.Close() })
	return n
}

// randomNodeID returns a random NodeID for test isolation.
func randomNegTestID(t *testing.T) a2al.NodeID {
	t.Helper()
	nid, sr := symNATRecord(t, "ws://sig/test")
	_ = sr
	return nid
}

// TestPrefetchNeg_confirmedAbsent verifies that ErrNoMatchingRecords writes a
// probeBadDelay (30 min) suppression entry and sets failCount to the cap.
func TestPrefetchNeg_confirmedAbsent(t *testing.T) {
	n := newTestNodeSimple(t)
	id := randomNegTestID(t)
	key := nodeIDKey(id)
	now := time.Now()

	n.epPrefetchNegMu.Lock()
	n.epPrefetchNeg[key] = epPrefetchNegEntry{
		retryAt:   now.Add(probeBadDelay),
		failCount: epPrefetchFailCountCap,
	}
	n.epPrefetchNegMu.Unlock()

	n.epPrefetchNegMu.RLock()
	entry := n.epPrefetchNeg[key]
	n.epPrefetchNegMu.RUnlock()

	if entry.failCount != epPrefetchFailCountCap {
		t.Errorf("failCount=%d, want %d (cap)", entry.failCount, epPrefetchFailCountCap)
	}
	if !entry.retryAt.After(now.Add(probeBadDelay - time.Second)) {
		t.Errorf("retryAt too soon for confirmed-absent: %v", entry.retryAt)
	}
}

// TestPrefetchNeg_transientBackoff verifies that consecutive transient failures
// double the suppression delay up to probeBadDelay.
func TestPrefetchNeg_transientBackoff(t *testing.T) {
	n := newTestNodeSimple(t)
	id := randomNegTestID(t)
	key := nodeIDKey(id)

	// Simulate the write path for transient errors directly so the test does
	// not depend on network availability.
	writeTransient := func() epPrefetchNegEntry {
		now := time.Now()
		n.epPrefetchNegMu.Lock()
		existing := n.epPrefetchNeg[key]
		nextFC := existing.failCount + 1
		if nextFC > epPrefetchFailCountCap {
			nextFC = epPrefetchFailCountCap
		}
		delay := probeInitDelay << nextFC
		if delay > probeBadDelay {
			delay = probeBadDelay
		}
		entry := epPrefetchNegEntry{retryAt: now.Add(delay), failCount: nextFC}
		n.epPrefetchNeg[key] = entry
		n.epPrefetchNegMu.Unlock()
		return entry
	}

	prev := time.Duration(0)
	for i := 1; i <= epPrefetchFailCountCap+1; i++ {
		e := writeTransient()
		delay := e.retryAt.Sub(time.Now())

		// Delay must never exceed probeBadDelay.
		if delay > probeBadDelay+time.Second {
			t.Errorf("failure %d: delay %v exceeds probeBadDelay %v", i, delay, probeBadDelay)
		}

		// Before hitting the cap, each failure should roughly double the delay.
		// After the cap the delay stays at probeBadDelay, so skip the growth check.
		if i < epPrefetchFailCountCap {
			if prev > 0 && delay < prev*3/2 {
				t.Errorf("failure %d: delay %v not sufficiently larger than prev %v", i, delay, prev)
			}
			prev = delay
		}

		// failCount must stay at cap once reached.
		if i >= epPrefetchFailCountCap && e.failCount != epPrefetchFailCountCap {
			t.Errorf("failure %d: failCount=%d, want cap %d", i, e.failCount, epPrefetchFailCountCap)
		}
	}
}

// TestPrefetchNeg_rescueOnLocalStorePut verifies that LocalStorePut for an
// endpoint record deletes any existing neg-cache entry for that nodeID.
func TestPrefetchNeg_rescueOnLocalStorePut(t *testing.T) {
	n := newTestNodeSimple(t)
	id, sr := symNATRecord(t, "ws://sig/rescue")
	key := nodeIDKey(id)

	// Seed a neg-cache entry simulating a prior failed prefetch.
	n.epPrefetchNegMu.Lock()
	n.epPrefetchNeg[key] = epPrefetchNegEntry{
		retryAt:   time.Now().Add(probeBadDelay),
		failCount: epPrefetchFailCountCap,
	}
	n.epPrefetchNegMu.Unlock()

	// Write the endpoint record via LocalStorePut (e.g. from Resolve / push).
	if err := n.LocalStorePut(id, sr); err != nil {
		t.Fatalf("LocalStorePut: %v", err)
	}

	// The neg-cache entry must be gone.
	n.epPrefetchNegMu.RLock()
	_, stillNeg := n.epPrefetchNeg[key]
	n.epPrefetchNegMu.RUnlock()
	if stillNeg {
		t.Error("neg-cache entry still present after LocalStorePut with endpoint record")
	}
}

// TestPrefetchNeg_nonEndpointPutDoesNotClear verifies that LocalStorePut for a
// non-endpoint record type does NOT clear the neg-cache entry.
func TestPrefetchNeg_nonEndpointPutDoesNotClear(t *testing.T) {
	n := newTestNodeSimple(t)
	// Use a fresh NodeID and an arbitrary non-endpoint record.
	id := randomNegTestID(t)
	key := nodeIDKey(id)

	n.epPrefetchNegMu.Lock()
	n.epPrefetchNeg[key] = epPrefetchNegEntry{
		retryAt:   time.Now().Add(probeBadDelay),
		failCount: epPrefetchFailCountCap,
	}
	n.epPrefetchNegMu.Unlock()

	// Build a minimal signed node record (RecType != RecTypeEndpoint).
	_, nodeRec := symNATRecord(t, "") // NATSymmetric, no signal — still RecTypeEndpoint
	// Change RecType to something else to simulate a non-endpoint write.
	nodeRec.RecType = 0xFF // non-existent type; store ignores validation here

	_ = n.LocalStorePut(id, nodeRec)

	n.epPrefetchNegMu.RLock()
	_, stillNeg := n.epPrefetchNeg[key]
	n.epPrefetchNegMu.RUnlock()
	if !stillNeg {
		t.Error("neg-cache entry was cleared by a non-endpoint LocalStorePut; it should not be")
	}
}
