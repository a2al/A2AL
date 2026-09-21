// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"crypto/ed25519"
	"io"
	"os"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/group"
)

func testSyncIdentity(t *testing.T) (ed25519.PrivateKey, a2al.Address) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := crypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, aid
}

// TestRunGroupSync_BasicConvergence creates one source store with several
// entries, clones it into a lagging replica, adds more entries to the source,
// then syncs to verify the replica catches up.
func TestRunGroupSync_BasicConvergence(t *testing.T) {
	privA, aidA := testSyncIdentity(t)
	_, aidB := testSyncIdentity(t)

	// Source store (storeA): create the group and add an invite + message.
	dirA := t.TempDir()
	storeA, err := group.Create(dirA, privA, aidA, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeA.Close() })
	invEntry, err := group.NewEntry(privA, aidA, storeA.Heads(), group.KindInvite,
		group.WithBody(group.EncodeMemberBody(aidB)))
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.Append(invEntry, nil); err != nil {
		t.Fatal(err)
	}
	// storeA: genesis + invite = 2 entries.

	// Replica (storeB): open a fresh directory and replicate genesis + invite
	// by feeding the serialised entries directly (simulates a prior sync).
	dirB := t.TempDir()
	storeB, err := group.Create(dirB, privA, aidA, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeB.Close() })
	// Override storeB's genesis with storeA's genesis so they share the same root.
	// Easiest way: append storeA's entries into storeB.
	for _, e := range mustEntries(t, storeA) {
		raw, _ := e.Marshal()
		e2, _ := group.Unmarshal(raw)
		_ = storeB.Append(e2, nil) // idempotent; errors for own genesis OK
	}

	// Now add a new message to storeA that storeB doesn't have.
	msgEntry, err := group.NewEntry(privA, aidA, storeA.Heads(), "msg",
		group.WithBody([]byte("hello from A")))
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.Append(msgEntry, nil); err != nil {
		t.Fatal(err)
	}
	// storeA: genesis + invite + msg = 3 entries.
	// storeB: genesis + invite (= 2 entries, may also have storeB's own genesis).

	if storeA.EntryCount() < 3 {
		t.Fatalf("storeA: expected ≥3 entries, got %d", storeA.EntryCount())
	}
	haveA := storeA.EntryCount()
	before := storeB.EntryCount()

	// Sync via OS pipe pairs (kernel-buffered, so concurrent writes don't block
	// each other — matching real QUIC stream semantics).
	// A reads from bToA_r, writes to aToB_w.
	// B reads from aToB_r, writes to bToA_w.
	aToB_r, aToB_w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	bToA_r, bToA_w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		st  groupSyncStats
		err error
	}
	chA := make(chan result, 1)
	chB := make(chan result, 1)

	go func() {
		st, serr := runGroupSync(storeA, bToA_r, aToB_w)
		aToB_w.Close()
		chA <- result{st, serr}
	}()
	go func() {
		st, serr := runGroupSync(storeB, aToB_r, bToA_w)
		bToA_w.Close()
		chB <- result{st, serr}
	}()

	rA := <-chA
	rB := <-chB
	aToB_r.Close()
	bToA_r.Close()

	for _, r := range []result{rA, rB} {
		if r.err != nil && r.err != io.EOF && r.err != io.ErrClosedPipe {
			t.Errorf("sync error: %v", r.err)
		}
	}

	// storeB must have gained at least the new msg entry.
	if storeB.EntryCount() <= before {
		t.Errorf("storeB did not gain new entries: before=%d after=%d", before, storeB.EntryCount())
	}
	if rB.st.Received < 1 {
		t.Errorf("storeB: expected ≥1 new entry from A, got %d", rB.st.Received)
	}
	if rA.st.Sent < 1 {
		t.Errorf("storeA: expected to report sent entries, got %+v", rA.st)
	}
	if rB.st.PeerHave != uint64(haveA) {
		t.Errorf("storeB: peerHave=%d, want %d", rB.st.PeerHave, haveA)
	}
}

// TestRunGroupSync_AncestorGap verifies that an intermediate ancestor
// (not a DAG head) is received in a single sync round thanks to Closure.
func TestRunGroupSync_AncestorGap(t *testing.T) {
	privA, aidA := testSyncIdentity(t)
	_, aidB := testSyncIdentity(t)

	// storeA: genesis → invite(B) → msg
	dirA := t.TempDir()
	storeA, err := group.Create(dirA, privA, aidA, "gap test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeA.Close() })
	inv, _ := group.NewEntry(privA, aidA, storeA.Heads(), group.KindInvite,
		group.WithBody(group.EncodeMemberBody(aidB)))
	_ = storeA.Append(inv, nil)
	msg, _ := group.NewEntry(privA, aidA, storeA.Heads(), "msg",
		group.WithBody([]byte("hello")))
	_ = storeA.Append(msg, nil)
	// storeA has 3 entries: genesis, invite, msg

	// storeB: only genesis (from a copy of storeA before invite+msg were added)
	dirB := t.TempDir()
	storeB, err := group.Create(dirB, privA, aidA, "gap test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeB.Close() })
	// Append only the genesis from A to B.
	for _, e := range mustEntries(t, storeA)[:1] {
		raw, _ := e.Marshal()
		e2, _ := group.Unmarshal(raw)
		_ = storeB.Append(e2, nil)
	}
	if storeB.EntryCount() < 1 {
		t.Fatal("storeB: expected at least genesis")
	}

	rA, rB, aR, bR := syncPair(t, storeA, storeB)
	aR.Close()
	bR.Close()

	if rA.err != nil && rA.err != io.EOF && rA.err != io.ErrClosedPipe {
		t.Errorf("storeA error: %v", rA.err)
	}
	if rB.err != nil && rB.err != io.EOF && rB.err != io.ErrClosedPipe {
		t.Errorf("storeB error: %v", rB.err)
	}

	// storeB must have received BOTH invite and msg in one round (Closure fix).
	if rB.n < 2 {
		t.Errorf("expected ≥2 new entries (invite + msg), got %d — ancestor gap not resolved", rB.n)
	}
	if storeB.WantedParents() != nil {
		t.Errorf("storeB still has wanted parents after sync: %v", storeB.WantedParents())
	}
}

// syncPair runs runGroupSync for two stores over OS pipes.
// Callers must close the returned *os.File readers after collecting results.
func syncPair(t *testing.T, sA, sB *group.Store) (rA, rB syncResult, aToB_r, bToA_r *os.File) {
	t.Helper()
	aToB_r, aToB_w, _ := os.Pipe()
	bToA_r, bToA_w, _ := os.Pipe()

	chA := make(chan syncResult, 1)
	chB := make(chan syncResult, 1)
	go func() {
		st, err := runGroupSync(sA, bToA_r, aToB_w)
		aToB_w.Close()
		chA <- syncResult{st.Received, err}
	}()
	go func() {
		st, err := runGroupSync(sB, aToB_r, bToA_w)
		bToA_w.Close()
		chB <- syncResult{st.Received, err}
	}()
	return <-chA, <-chB, aToB_r, bToA_r
}

type syncResult struct {
	n   int
	err error
}

// mustEntries returns all entries from a store in read order.
func mustEntries(t *testing.T, s *group.Store) []group.Entry {
	t.Helper()
	ers, _, _, err := s.Read(0, 100, group.ReadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]group.Entry, len(ers))
	for i, er := range ers {
		entries[i] = er.Entry
	}
	return entries
}
