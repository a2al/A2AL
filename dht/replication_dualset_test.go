// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"testing"
	"time"

	"github.com/a2al/a2al"
)

// makeRepEntry builds a repNodeEntry for testing.
func makeRepEntry(id a2al.NodeID, punched bool) *repNodeEntry {
	return &repNodeEntry{
		nodeID:    id,
		isPunched: punched,
		confirmedAt: time.Now(),
	}
}

// makeRepSet builds a repSet with pre-populated nodes.
func makeRepSet(key a2al.NodeID, entries ...*repNodeEntry) *repSet {
	rs := &repSet{
		storeKey: key,
		nodes:    make(map[string]*repNodeEntry, len(entries)),
	}
	for _, e := range entries {
		rs.nodes[nodeIDKey(e.nodeID)] = e
	}
	return rs
}

// countSets returns the number of entries in each set.
func countSets(rs *repSet) (xorCount, directCount, neitherCount int) {
	for _, e := range rs.nodes {
		if e.inXorSet {
			xorCount++
		}
		if e.inDirectSet {
			directCount++
		}
		if !e.inXorSet && !e.inDirectSet {
			neitherCount++
		}
	}
	return
}

// TestRebalanceRepSets_allDirect verifies that when all nodes are direct
// (non-punched) and count ≤ nRep, every node ends up in both sets.
func TestRebalanceRepSets_allDirect(t *testing.T) {
	var key a2al.NodeID // zero key

	var entries []*repNodeEntry
	for i := 0; i < nRep; i++ {
		var id a2al.NodeID
		id[31] = byte(i + 1)
		entries = append(entries, makeRepEntry(id, false))
	}
	rs := makeRepSet(key, entries...)

	rs.mu.Lock()
	rebalanceRepSets(rs, key)
	rs.mu.Unlock()

	xor, direct, neither := countSets(rs)
	if neither != 0 {
		t.Errorf("no node should be removed: neither=%d", neither)
	}
	if xor != nRep {
		t.Errorf("xorCount=%d, want %d", xor, nRep)
	}
	if direct != nRep {
		t.Errorf("directCount=%d, want %d", direct, nRep)
	}
	if len(rs.nodes) != nRep {
		t.Errorf("repSet size=%d, want %d", len(rs.nodes), nRep)
	}
}

// TestRebalanceRepSets_allPunched verifies that when all nodes are punched,
// they all go into the XOR set but the direct set is empty.
func TestRebalanceRepSets_allPunched(t *testing.T) {
	var key a2al.NodeID

	var entries []*repNodeEntry
	for i := 0; i < nRep; i++ {
		var id a2al.NodeID
		id[31] = byte(i + 1)
		entries = append(entries, makeRepEntry(id, true /* punched */))
	}
	rs := makeRepSet(key, entries...)

	rs.mu.Lock()
	rebalanceRepSets(rs, key)
	rs.mu.Unlock()

	xor, direct, neither := countSets(rs)
	if neither != 0 {
		t.Errorf("no node should be removed: neither=%d", neither)
	}
	if xor != nRep {
		t.Errorf("xorCount=%d, want %d", xor, nRep)
	}
	if direct != 0 {
		t.Errorf("directCount=%d, want 0 (all punched)", direct)
	}
}

// TestRebalanceRepSets_mixedEviction verifies the dual-set eviction semantics
// when there are more than nRep nodes:
//   - nRep+2 direct nodes: top-nRep go to both sets; excess 2 are removed.
//   - nRep punched nodes (XOR-closer than the direct overflow): all in XOR set,
//     none in direct set; closest nRep overall end up in XOR set.
func TestRebalanceRepSets_mixedEviction(t *testing.T) {
	var key a2al.NodeID

	// Direct nodes: IDs 1..nRep+2 (distance 1..nRep+2 from key).
	var entries []*repNodeEntry
	for i := 1; i <= nRep+2; i++ {
		var id a2al.NodeID
		id[31] = byte(i)
		entries = append(entries, makeRepEntry(id, false))
	}
	// Punched nodes: IDs 100..100+nRep-1 (farther than direct nodes but still relevant).
	for i := 0; i < nRep; i++ {
		var id a2al.NodeID
		id[30] = byte(1) // first non-zero byte at [30] → farther than [31]-only IDs
		id[31] = byte(i)
		entries = append(entries, makeRepEntry(id, true /* punched */))
	}
	rs := makeRepSet(key, entries...)

	rs.mu.Lock()
	rebalanceRepSets(rs, key)
	rs.mu.Unlock()

	xor, direct, neither := countSets(rs)

	// XOR set: top-nRep by XOR distance = direct nodes 1..nRep (all closer than punched).
	if xor != nRep {
		t.Errorf("xorCount=%d, want %d", xor, nRep)
	}
	// Direct set: top-nRep direct = same as XOR set here (direct nodes 1..nRep).
	if direct != nRep {
		t.Errorf("directCount=%d, want %d", direct, nRep)
	}
	// Nodes in neither set: direct overflow (2) + all punched (nRep) → removed.
	wantNeither := 2 + nRep
	if neither != 0 {
		t.Errorf("neither=%d, want 0 (should be removed)", neither)
	}
	wantTotal := nRep // only the top-nRep direct nodes survive
	if len(rs.nodes) != wantTotal {
		t.Errorf("repSet size=%d, want %d (removed neither=%d)", len(rs.nodes), wantTotal, wantNeither)
	}
}

// TestRebalanceRepSets_punchedInXorNotDirect verifies that a punched node that
// is XOR-closer than some direct nodes ends up in the XOR set but NOT the
// direct set, while the displaced direct node stays via the direct set.
func TestRebalanceRepSets_punchedInXorNotDirect(t *testing.T) {
	var key a2al.NodeID

	// nRep-1 direct nodes at distances 2..nRep (byte 31 = 2..nRep).
	var entries []*repNodeEntry
	for i := 2; i <= nRep; i++ {
		var id a2al.NodeID
		id[31] = byte(i)
		entries = append(entries, makeRepEntry(id, false))
	}
	// 1 punched node at distance 1 (closer than all direct nodes).
	var punchedID a2al.NodeID
	punchedID[31] = 1
	entries = append(entries, makeRepEntry(punchedID, true))

	// 1 direct node at distance nRep+1 (farther — will it survive?).
	var farDirectID a2al.NodeID
	farDirectID[31] = byte(nRep + 1)
	entries = append(entries, makeRepEntry(farDirectID, false))

	rs := makeRepSet(key, entries...)

	rs.mu.Lock()
	rebalanceRepSets(rs, key)
	rs.mu.Unlock()

	// Verify: punched node (dist=1) is in XOR set, not direct set.
	pk := nodeIDKey(punchedID)
	if e, ok := rs.nodes[pk]; !ok {
		t.Error("punched node should be in repSet (in XOR set)")
	} else {
		if !e.inXorSet {
			t.Error("punched XOR-close node should have inXorSet=true")
		}
		if e.inDirectSet {
			t.Error("punched node must not be in direct set")
		}
	}

	// Verify: the far direct node (dist=nRep+1) is in direct set (it's the
	// nRep-th direct node, since there are nRep-1 closer + 1 farther direct nodes).
	fdk := nodeIDKey(farDirectID)
	if e, ok := rs.nodes[fdk]; !ok {
		t.Error("far direct node should survive via direct set")
	} else {
		if !e.inDirectSet {
			t.Error("far direct node should have inDirectSet=true")
		}
	}
}

// TestRebalanceRepSets_idempotent verifies that calling rebalanceRepSets twice
// produces the same result.
func TestRebalanceRepSets_idempotent(t *testing.T) {
	var key a2al.NodeID
	var entries []*repNodeEntry
	for i := 0; i < nRep*2; i++ {
		var id a2al.NodeID
		id[31] = byte(i + 1)
		punched := i%3 == 0
		entries = append(entries, makeRepEntry(id, punched))
	}
	rs := makeRepSet(key, entries...)

	rs.mu.Lock()
	rebalanceRepSets(rs, key)
	size1 := len(rs.nodes)
	xor1, direct1, _ := countSets(rs)
	rebalanceRepSets(rs, key) // second call
	size2 := len(rs.nodes)
	xor2, direct2, _ := countSets(rs)
	rs.mu.Unlock()

	if size1 != size2 || xor1 != xor2 || direct1 != direct2 {
		t.Errorf("rebalance not idempotent: size %d→%d, xor %d→%d, direct %d→%d",
			size1, size2, xor1, xor2, direct1, direct2)
	}
}
