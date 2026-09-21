// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"testing"
	"time"

	"github.com/a2al/a2al"
)

func addrN(n byte) a2al.Address {
	var a a2al.Address
	a[0] = n
	return a
}

func TestPickAlignTargetsSmallRoomTakesAll(t *testing.T) {
	others := []a2al.Address{addrN(2), addrN(3), addrN(4)}
	order := alignCandidateOrder(others, nil, 7, a2al.Address{}, nil)
	if got := pickAlignTargets(order); len(got) != 3 {
		t.Fatalf("small room targets=%d, want 3 (not first-success)", len(got))
	}
}

func TestAuthoredWriteIsRunnableWithoutHeartbeat(t *testing.T) {
	now := time.Now()
	if !shouldRunAlign(&alignGroupState{
		authored: true,
		due:      now.Add(time.Hour),
	}, now, false) {
		t.Fatal("authored write must run without a heartbeat")
	}
	if shouldRunAlign(&alignGroupState{
		due: now.Add(-time.Second),
	}, now, false) {
		t.Fatal("periodic probing must remain heartbeat-gated")
	}
}

// Without a chain (the pre-center fallback) large rooms still walk, so no
// member is starved of a probe.
func TestPickAlignTargetsFallbackTakesTwoAndRotates(t *testing.T) {
	others := make([]a2al.Address, 6)
	for i := range others {
		others[i] = addrN(byte(i + 1))
	}
	a := pickAlignTargets(alignCandidateOrder(others, nil, 0, a2al.Address{}, nil))
	b := pickAlignTargets(alignCandidateOrder(others, nil, 1, a2al.Address{}, nil))
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("large room want 2+2, got %d+%d", len(a), len(b))
	}
	if a[0] == b[0] && a[1] == b[1] {
		t.Fatal("rotate did not change the pair")
	}
}

func TestPickAlignTargetsFallbackUsesLastSync(t *testing.T) {
	others := []a2al.Address{addrN(1), addrN(2), addrN(3), addrN(4), addrN(5)}
	got := pickAlignTargets(alignCandidateOrder(others, nil, 1, addrN(5), nil))
	if len(got) != 2 || got[0] != addrN(5) || got[1] != addrN(2) {
		t.Fatalf("targets=%v, want last-sync then walking peer", got)
	}
}

// The whole point of the chain: everyone converges on the same rendezvous
// instead of each picking their own walking peer.
func TestPickAlignTargetsFollowsChain(t *testing.T) {
	others := []a2al.Address{addrN(1), addrN(2), addrN(3), addrN(4), addrN(5)}
	chain := []a2al.Address{addrN(4), addrN(2), addrN(5), addrN(1), addrN(3)}
	got := pickAlignTargets(alignCandidateOrder(others, chain, 3, addrN(1), nil))
	if len(got) != 2 || got[0] != addrN(4) || got[1] != addrN(2) {
		t.Fatalf("targets=%v, want the two leading chain entries", got)
	}
}

// A failed center is skipped locally, not removed: it stays at the back of the
// order so a round always has targets, and it is retried once cooling expires.
func TestCoolingPeersSinkButAreNeverDropped(t *testing.T) {
	others := []a2al.Address{addrN(1), addrN(2), addrN(3), addrN(4), addrN(5)}
	chain := []a2al.Address{addrN(1), addrN(2), addrN(3), addrN(4), addrN(5)}
	cooling := map[a2al.Address]struct{}{addrN(1): {}}
	order := alignCandidateOrder(others, chain, 0, a2al.Address{}, cooling)
	if len(order) != 5 || order[4] != addrN(1) {
		t.Fatalf("order=%v, want the cooling peer last", order)
	}
	if got := pickAlignTargets(order); got[0] != addrN(2) || got[1] != addrN(3) {
		t.Fatalf("targets=%v, want the chain successors", got)
	}

	all := make(map[a2al.Address]struct{}, len(others))
	for _, p := range others {
		all[p] = struct{}{}
	}
	full := alignCandidateOrder(others, chain, 0, a2al.Address{}, all)
	if len(full) != 5 {
		t.Fatalf("order=%v, want every member even when all are cooling", full)
	}
	if len(pickAlignTargets(full)) != 2 {
		t.Fatal("a round must never end up with no target")
	}
}

// Failure and recovery are local edges: no announcement, no shared state.
func TestPeerFailCoolsThenRecovers(t *testing.T) {
	d := newTestDaemon(t)
	local, peer := addrN(1), addrN(2)
	var gid [32]byte

	d.notePeerFail(local, peer, gid)
	d.alignMu.Lock()
	cooling := d.coolingPeersLocked(local, gid, []a2al.Address{peer})
	d.alignMu.Unlock()
	if _, ok := cooling[peer]; !ok {
		t.Fatal("failed peer must cool")
	}

	d.alignMu.Lock()
	d.peerStateLocked(local, peer, gid).lastFail = time.Now().Add(-alignFailCooldown - time.Second)
	cooling = d.coolingPeersLocked(local, gid, []a2al.Address{peer})
	d.alignMu.Unlock()
	if len(cooling) != 0 {
		t.Fatal("cooling must expire on its own, without any notification")
	}

	d.notePeerFail(local, peer, gid)
	d.notePeerSync(local, peer, gid)
	d.alignMu.Lock()
	cooling = d.coolingPeersLocked(local, gid, []a2al.Address{peer})
	d.alignMu.Unlock()
	if len(cooling) != 0 {
		t.Fatal("a successful round must clear the cooling mark")
	}
}

func TestNextAlignBackoff(t *testing.T) {
	if g := nextAlignBackoff(alignProbeStart, 0, false, true); g != 10*time.Second {
		t.Fatalf("empty success: %v", g)
	}
	if g := nextAlignBackoff(10*time.Second, 0, false, true); g != 30*time.Second {
		t.Fatalf("second empty success: %v", g)
	}
	if g := nextAlignBackoff(30*time.Second, 0, false, true); g != time.Minute {
		t.Fatalf("third empty success: %v", g)
	}
	if g := nextAlignBackoff(time.Minute, 0, false, true); g != alignProbeMax {
		t.Fatalf("fourth empty success: %v", g)
	}
	if g := nextAlignBackoff(alignProbeMax, 0, false, true); g != alignProbeMax {
		t.Fatalf("cap: %v", g)
	}
	if g := nextAlignBackoff(time.Minute, 3, false, true); g != alignProbeStart {
		t.Fatalf("received resets: %v", g)
	}
	if g := nextAlignBackoff(time.Minute, 0, true, true); g != alignProbeStart {
		t.Fatalf("authored resets: %v", g)
	}
	if g := nextAlignBackoff(time.Minute, 0, false, false); g != time.Minute {
		t.Fatalf("failure keeps backoff: %v", g)
	}
}

func TestFailedTargetRefillExcludesQueuedTargets(t *testing.T) {
	order := []a2al.Address{addrN(1), addrN(2), addrN(3), addrN(4), addrN(5)}
	queued := map[a2al.Address]struct{}{addrN(1): {}, addrN(2): {}}
	// Both current targets are already queued; the replacement must come from
	// further down the order rather than being a duplicate.
	got, _, ok := nextQueuedCandidate(order, 0, queued)
	if !ok || got != addrN(3) {
		t.Fatalf("replacement=%v ok=%v, want peer 3", got, ok)
	}
}

func TestPeerRecentlySyncedBothDirections(t *testing.T) {
	d := newTestDaemon(t)
	local, peer := addrN(1), addrN(2)
	var gid [32]byte
	if d.peerRecentlySynced(local, peer, gid) {
		t.Fatal("empty pair must not skip")
	}
	d.notePeerSync(local, peer, gid)
	if !d.peerRecentlySynced(local, peer, gid) {
		t.Fatal("just synced should skip")
	}
	if !d.peerRecentlySynced(peer, local, gid) {
		t.Fatal("inbound success should skip the reverse pair")
	}
}

func TestKickAlignAuthoredDueNow(t *testing.T) {
	d := newTestDaemon(t)
	aid := addrN(1)
	var gid [32]byte
	d.kickAlignAuthored(aid, gid)
	d.alignMu.Lock()
	st := d.alignGroups[alignGroupKey{aid, gid}]
	d.alignMu.Unlock()
	if st == nil || !st.authored {
		t.Fatalf("authored kick missing: %+v", st)
	}
	if time.Since(st.due) > time.Second && time.Until(st.due) > time.Second {
		t.Fatalf("authored due not now: %v", st.due)
	}
	if st.backoff != alignProbeStart {
		t.Fatalf("authored backoff=%v", st.backoff)
	}
}

func TestReceivedResetsProbeWithoutFanout(t *testing.T) {
	d := newTestDaemon(t)
	aid := addrN(1)
	var gid [32]byte
	d.alignMu.Lock()
	st := d.groupStateLocked(aid, gid)
	st.backoff = alignProbeMax
	st.due = time.Now().Add(alignProbeMax)
	d.alignMu.Unlock()

	d.noteAlignReceived(aid, gid)

	d.alignMu.Lock()
	got := *d.alignGroups[alignGroupKey{aid, gid}]
	d.alignMu.Unlock()
	if got.backoff != alignProbeStart {
		t.Fatalf("backoff=%v, want %v", got.backoff, alignProbeStart)
	}
	if until := time.Until(got.due); until < 4*time.Second || until > 6*time.Second {
		t.Fatalf("due in %v, want about 5s", until)
	}
	if got.authored {
		t.Fatal("received content must not become an authored fan-out")
	}
}

func TestDeferredRoundDoesNotRaiseInformationBackoff(t *testing.T) {
	d := newTestDaemon(t)
	aid := addrN(1)
	var gid [32]byte
	d.alignMu.Lock()
	st := d.groupStateLocked(aid, gid)
	st.backoff = 30 * time.Second
	d.alignMu.Unlock()

	d.finishRound(aid, gid, false, true, true, 0)

	d.alignMu.Lock()
	got := *d.alignGroups[alignGroupKey{aid, gid}]
	d.alignMu.Unlock()
	if got.backoff != 30*time.Second {
		t.Fatalf("deferred backoff=%v, want unchanged", got.backoff)
	}
	if until := time.Until(got.due); until < 0 || until > 2*alignTickPeriod {
		t.Fatalf("deferred due in %v, want next tick", until)
	}
}

func TestReceivedDuringRoundSurvivesFinish(t *testing.T) {
	d := newTestDaemon(t)
	aid := addrN(1)
	var gid [32]byte
	d.alignMu.Lock()
	st := d.groupStateLocked(aid, gid)
	st.backoff = alignProbeMax
	st.received = true // simulates inbound content while a round is running
	d.alignMu.Unlock()

	d.finishRound(aid, gid, false, true, false, 0)

	d.alignMu.Lock()
	got := *d.alignGroups[alignGroupKey{aid, gid}]
	d.alignMu.Unlock()
	if got.backoff != alignProbeStart {
		t.Fatalf("concurrent receive backoff=%v, want %v", got.backoff, alignProbeStart)
	}
}
