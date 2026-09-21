// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
	"github.com/a2al/a2al/internal/registry"
)

func gidN(n byte) [32]byte {
	var g [32]byte
	g[0] = n
	return g
}

func memberMap(n int) map[a2al.Address]group.MemberRole {
	m := make(map[a2al.Address]group.MemberRole, n)
	for i := 1; i <= n; i++ {
		m[addrN(byte(i))] = group.RoleMember
	}
	return m
}

// The chain must be a pure function of (group_id, member set): every replica
// derives the same order without exchanging anything.
func TestCenterChainIsDeterministic(t *testing.T) {
	gid := gidN(9)
	a := centerChain(gid, memberMap(20))
	for i := 0; i < 20; i++ {
		b := centerChain(gid, memberMap(20))
		if len(a) != len(b) {
			t.Fatalf("chain length %d vs %d", len(a), len(b))
		}
		for j := range a {
			if a[j] != b[j] {
				t.Fatalf("chain diverged at %d across map iterations", j)
			}
		}
	}
}

func TestCenterChainSkipsNonMembers(t *testing.T) {
	gid := gidN(3)
	members := map[a2al.Address]group.MemberRole{
		addrN(1): group.RoleCreator,
		addrN(2): group.RoleAdmin,
		addrN(3): group.RoleMember,
		addrN(4): group.RolePending, // invited, may hold no replica at all
		addrN(5): group.RoleRevoked,
		addrN(6): group.RoleNone,
	}
	chain := centerChain(gid, members)
	if len(chain) != 3 {
		t.Fatalf("chain=%v, want only the 3 replica-holding members", chain)
	}
	for _, aid := range chain {
		if aid == addrN(4) || aid == addrN(5) || aid == addrN(6) {
			t.Fatalf("ineligible member %v in chain", aid)
		}
	}
	if centerRank(gid, members, addrN(4)) != -1 {
		t.Fatal("pending member must not get a rank")
	}
	if centerRank(gid, members, addrN(42)) != -1 {
		t.Fatal("stranger must not get a rank")
	}
}

func TestCenterRankMatchesChainIndex(t *testing.T) {
	gid := gidN(7)
	members := memberMap(15)
	chain := centerChain(gid, members)
	for i, aid := range chain {
		if got := centerRank(gid, members, aid); got != i {
			t.Fatalf("rank(%v)=%d, chain index %d", aid, got, i)
		}
	}
}

func TestIsCenterPicksExactlyTwo(t *testing.T) {
	gid := gidN(11)
	members := memberMap(12)
	chain := centerChain(gid, members)
	centers := 0
	for _, aid := range chain {
		if isCenter(gid, members, aid) {
			centers++
		}
	}
	if centers != centerCount {
		t.Fatalf("centers=%d, want %d", centers, centerCount)
	}
	if !isCenter(gid, members, chain[0]) || !isCenter(gid, members, chain[1]) {
		t.Fatal("the two leading chain entries must be the centers")
	}
}

// Membership churn must only displace the changed member, otherwise every
// invite would reshuffle every connection in the room.
func TestMemberChurnPreservesRelativeOrder(t *testing.T) {
	gid := gidN(5)
	base := memberMap(10)
	before := centerChain(gid, base)

	grown := memberMap(10)
	grown[addrN(99)] = group.RoleMember
	after := centerChain(gid, grown)

	filtered := make([]a2al.Address, 0, len(after))
	for _, aid := range after {
		if aid != addrN(99) {
			filtered = append(filtered, aid)
		}
	}
	if len(filtered) != len(before) {
		t.Fatalf("len %d vs %d", len(filtered), len(before))
	}
	for i := range before {
		if before[i] != filtered[i] {
			t.Fatalf("adding one member reordered the chain at %d", i)
		}
	}
}

// With the leading chain entries offline, center duty slides down the chain on
// its own. What must survive is convergence: any two online members still pick
// overlapping targets, so the room does not split into isolated islands.
func TestChainSlidesDownWhenLeadersAreOffline(t *testing.T) {
	gid := gidN(13)
	members := memberMap(20)
	chain := centerChain(gid, members)

	offline := make(map[a2al.Address]struct{}, 5)
	for _, aid := range chain[:5] {
		offline[aid] = struct{}{}
	}

	targets := make(map[a2al.Address][]a2al.Address)
	for _, self := range chain[5:] {
		others := make([]a2al.Address, 0, len(chain)-1)
		selfChain := make([]a2al.Address, 0, len(chain)-1)
		for _, aid := range chain {
			if aid == self {
				continue
			}
			others = append(others, aid)
			selfChain = append(selfChain, aid)
		}
		got := pickAlignTargets(alignCandidateOrder(others, selfChain, 0, a2al.Address{}, offline))
		if len(got) != alignLargeWant {
			t.Fatalf("%v got %d targets, want %d", self, len(got), alignLargeWant)
		}
		for _, p := range got {
			if _, down := offline[p]; down {
				t.Fatalf("%v targeted offline leader %v", self, p)
			}
		}
		targets[self] = got
	}

	for a, ta := range targets {
		for b, tb := range targets {
			if a == b {
				continue
			}
			shared := false
			for _, x := range ta {
				for _, y := range tb {
					if x == y {
						shared = true
					}
				}
			}
			if !shared {
				t.Fatalf("targets of %v and %v do not overlap: %v vs %v", a, b, ta, tb)
			}
		}
	}
}

// Push duty is decided by two observations we already keep, with no ledger and
// no delivery assumption.
func TestCenterPushDueSelectsRecentPullersThatAreBehind(t *testing.T) {
	d := newTestDaemon(t)
	self, behind, caughtUp, silent := addrN(1), addrN(2), addrN(3), addrN(4)
	gid := gidN(2)
	members := map[a2al.Address]group.MemberRole{
		self: group.RoleMember, behind: group.RoleMember,
		caughtUp: group.RoleMember, silent: group.RoleMember,
	}

	d.notePeerPull(self, behind, gid)
	d.notePeerRound(self, behind, gid, groupSyncStats{PeerHave: 3, LocalHave: 3})
	d.notePeerPull(self, caughtUp, gid)
	d.notePeerRound(self, caughtUp, gid, groupSyncStats{PeerHave: 5, LocalHave: 5})
	// silent never dialled us, so it is not converging on us.
	d.notePeerRound(self, silent, gid, groupSyncStats{})

	now := time.Now().Add(alignPeerCooldown + time.Second)
	due := d.centerPushDue(self, gid, members, 5, now)
	if len(due) != 1 || due[0] != behind {
		t.Fatalf("due=%v, want only the behind puller", due)
	}

	// A peer we just synced with is left alone until the 2s cooldown passes.
	d.notePeerSync(self, behind, gid)
	if due := d.centerPushDue(self, gid, members, 5, time.Now()); len(due) != 0 {
		t.Fatalf("due=%v, want none within the push cooldown", due)
	}

	// Long-silent pullers fall off the list rather than being dialled forever.
	d.alignMu.Lock()
	st := d.peerStateLocked(self, behind, gid)
	st.pulledAt = now.Add(-centerPullTTL - time.Minute)
	st.lastSync = time.Time{}
	d.alignMu.Unlock()
	if due := d.centerPushDue(self, gid, members, 5, now); len(due) != 0 {
		t.Fatalf("due=%v, want none after the pull relationship expired", due)
	}
}

func TestCenterPushDuePrefersLeastRecentlySynced(t *testing.T) {
	d := newTestDaemon(t)
	self, old, recent := addrN(1), addrN(2), addrN(3)
	gid := gidN(4)
	members := map[a2al.Address]group.MemberRole{
		self: group.RoleMember, old: group.RoleMember, recent: group.RoleMember,
	}
	now := time.Now()
	for _, p := range []a2al.Address{old, recent} {
		d.notePeerPull(self, p, gid)
		d.notePeerRound(self, p, gid, groupSyncStats{PeerHave: 1, LocalHave: 1})
	}
	d.alignMu.Lock()
	d.peerStateLocked(self, old, gid).lastSync = now.Add(-10 * time.Minute)
	d.peerStateLocked(self, recent, gid).lastSync = now.Add(-10 * time.Second)
	d.alignMu.Unlock()

	due := d.centerPushDue(self, gid, members, 9, now)
	if len(due) != 2 || due[0] != old {
		t.Fatalf("due=%v, want the least recently synced peer first", due)
	}
}

func TestCenterTokenBucketBurstsThenThrottles(t *testing.T) {
	d := newTestDaemon(t)
	aid := addrN(1)
	now := time.Now()
	allowed := 0
	for i := 0; i < 50; i++ {
		if d.centerTokenAvailable(aid, now) {
			allowed++
		}
	}
	if allowed != int(centerPushBurst) {
		t.Fatalf("allowed=%d on a single instant, want burst %d", allowed, int(centerPushBurst))
	}
	if !d.centerTokenAvailable(aid, now.Add(time.Second)) {
		t.Fatal("bucket must refill over time")
	}
}

// A peer that can dial us but that we cannot dial back is the ordinary NAT
// case. A failed push leaves lastSync untouched, so without honouring the
// failure cooldown such a peer stays due every single tick — and since the
// queue is oldest-first, its frozen lastSync sorts it ever earlier and drains
// the push budget this AID shares across every room it centers.
func TestCenterPushDueSkipsRecentlyFailedPeers(t *testing.T) {
	d := newTestDaemon(t)
	self, unreachable, healthy := addrN(1), addrN(2), addrN(3)
	gid := gidN(5)
	members := map[a2al.Address]group.MemberRole{
		self: group.RoleMember, unreachable: group.RoleMember, healthy: group.RoleMember,
	}
	now := time.Now()
	for _, p := range []a2al.Address{unreachable, healthy} {
		d.notePeerPull(self, p, gid)
		d.notePeerRound(self, p, gid, groupSyncStats{PeerHave: 1, LocalHave: 1})
	}
	d.alignMu.Lock()
	// Both pulled a while ago; the unreachable one sorts first precisely
	// because pushing to it keeps failing.
	d.peerStateLocked(self, unreachable, gid).lastSync = now.Add(-10 * time.Minute)
	d.peerStateLocked(self, healthy, gid).lastSync = now.Add(-time.Minute)
	d.alignMu.Unlock()

	if due := d.centerPushDue(self, gid, members, 9, now); len(due) != 2 {
		t.Fatalf("due=%v, want both peers before any failure", due)
	}

	d.notePeerFail(self, unreachable, gid)
	due := d.centerPushDue(self, gid, members, 9, now)
	if len(due) != 1 || due[0] != healthy {
		t.Fatalf("due=%v, want only the healthy peer while the other cools", due)
	}

	// The skip is temporary: it must be retried once the cooldown expires.
	if due := d.centerPushDue(self, gid, members, 9, now.Add(alignFailCooldown+time.Second)); len(due) != 2 {
		t.Fatalf("due=%v, want the cooled peer retried after the cooldown", due)
	}
}

// Revoked and pending entries never leave the member set, so counting the raw
// map would switch on center pushes in a room the scheduler still aligns with
// in full.
func TestCenterDutyCountsOnlyReplicaHolders(t *testing.T) {
	gid := gidN(12)
	members := map[a2al.Address]group.MemberRole{
		addrN(1): group.RoleCreator,
		addrN(2): group.RoleMember,
		addrN(3): group.RoleMember,
		addrN(4): group.RoleMember,
		addrN(5): group.RoleRevoked,
		addrN(6): group.RoleRevoked,
		addrN(7): group.RolePending,
	}
	if got := replicaHolders(members); got != 4 {
		t.Fatalf("replicaHolders=%d, want 4", got)
	}
	for _, aid := range centerChain(gid, members) {
		if centerDuty(gid, members, aid) {
			t.Fatalf("%v took center duty in a 4-member room", aid)
		}
	}

	members[addrN(8)] = group.RoleMember // now 5 replica holders
	chain := centerChain(gid, members)
	if !centerDuty(gid, members, chain[0]) || !centerDuty(gid, members, chain[1]) {
		t.Fatal("chain leaders must take duty once the room outgrows full alignment")
	}
	if centerDuty(gid, members, chain[2]) {
		t.Fatal("only the leading chain entries hold duty")
	}
}

// Duty is derived each tick; the log is only for the two flips that change
// what a reader of `group center: pushed` should expect.
func TestCenterDutyLogsOnlyOnFlip(t *testing.T) {
	var buf bytes.Buffer
	d := newTestDaemon(t)
	d.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	aid, gid := addrN(1), gidN(7)

	d.noteCenterDuty(aid, gid, false)
	if strings.Contains(buf.String(), "duty") {
		t.Fatal("first sight of no duty must stay quiet")
	}

	d.noteCenterDuty(aid, gid, true)
	if !strings.Contains(buf.String(), "took duty") {
		t.Fatalf("taking duty must log, got %q", buf.String())
	}
	buf.Reset()

	d.noteCenterDuty(aid, gid, true)
	if buf.Len() != 0 {
		t.Fatalf("steady duty must not re-log, got %q", buf.String())
	}

	d.noteCenterDuty(aid, gid, false)
	if !strings.Contains(buf.String(), "dropped duty") {
		t.Fatalf("losing duty must log, got %q", buf.String())
	}
}

// Scheduling may lean on the optimistic count, reporting may not: the final
// Give is never acknowledged, so what a writer is shown must stay strictly
// what the peer said about itself.
func TestReplicaHeadReportsObservationNotInference(t *testing.T) {
	d := newTestDaemon(t)
	self, peer := addrN(1), addrN(2)
	gid := gidN(6)

	d.notePeerRound(self, peer, gid, groupSyncStats{PeerHave: 3, LocalHave: 7})
	d.notePeerSync(self, peer, gid)

	head, _, ok := d.replicaHead(self, peer, gid)
	if !ok || head != 3 {
		t.Fatalf("replica_head=%d, want the peer's own report 3, not our inferred 7", head)
	}
	d.alignMu.Lock()
	covered := d.peerStateLocked(self, peer, gid).peerCoveredCount
	d.alignMu.Unlock()
	if covered != 7 {
		t.Fatalf("peerCoveredCount=%d, want 7 for push scheduling", covered)
	}

	// Neither count may slide backwards; the log is append-only.
	d.notePeerRound(self, peer, gid, groupSyncStats{PeerHave: 1, LocalHave: 2})
	if head, _, _ := d.replicaHead(self, peer, gid); head != 3 {
		t.Fatalf("replica_head=%d, want it to stay at 3", head)
	}
}

// An unseen replica must read as unknown, not as zero: reporting a number we
// never observed is exactly the delivery assumption this design refuses.
func TestReplicaHeadIsUnknownUntilSynced(t *testing.T) {
	d := newTestDaemon(t)
	self, peer := addrN(1), addrN(2)
	gid := gidN(8)

	d.notePeerRound(self, peer, gid, groupSyncStats{PeerHave: 7, LocalHave: 7})
	if _, _, ok := d.replicaHead(self, peer, gid); ok {
		t.Fatal("a peer we never completed a round with must read as unknown")
	}

	d.notePeerSync(self, peer, gid)
	head, at, ok := d.replicaHead(self, peer, gid)
	if !ok || head != 7 || at.IsZero() {
		t.Fatalf("replicaHead=(%d,%v,%v), want the observed count and time", head, at, ok)
	}
}

// A same-daemon round holds both replicas, so each head is a direct
// observation rather than the peer's own account of itself. This used to be
// dropped entirely: replica_head stayed at zero for co-resident members while
// replica_seen_at kept ticking, which reads as "peer holds nothing".
func TestLocalAlignRecordsObservedReplicaHead(t *testing.T) {
	d := newTestDaemon(t)
	d.groups = newGroupManager(d.dataDir, d.log)

	privA, aidA := testSyncIdentity(t)
	_, aidB := testSyncIdentity(t)
	for _, aid := range []a2al.Address{aidA, aidB} {
		if err := d.reg.Put(&registry.Entry{AID: aid}); err != nil {
			t.Fatal(err)
		}
	}
	storeA, err := d.groups.Create(aidA, privA, "local")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeA.Close() })
	gid := storeA.ID()
	storeB, err := d.groups.Join(aidB, gid, aidA, "local")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storeB.Close() })

	if _, err := d.alignWithPeer(context.Background(), aidA, gid, aidB, storeA); err != nil {
		t.Fatal(err)
	}
	d.notePeerSync(aidA, aidB, gid)

	want := uint64(storeA.EntryCount())
	if want == 0 {
		t.Fatal("test is vacuous: the creator replica is empty")
	}
	head, _, ok := d.replicaHead(aidA, aidB, gid)
	if !ok || head != want {
		t.Fatalf("replica_head=(%d,%v), want the peer's observed head %d", head, ok, want)
	}
	if head, _, ok := d.replicaHead(aidB, aidA, gid); !ok || head != want {
		t.Fatalf("reverse replica_head=(%d,%v), want %d", head, ok, want)
	}
}

// Salting by group ID is what keeps one node from being every room's center.
func TestCenterChainVariesByGroup(t *testing.T) {
	members := memberMap(20)
	first := centerChain(gidN(1), members)
	differs := false
	for g := byte(2); g <= 6; g++ {
		other := centerChain(gidN(g), members)
		if len(other) != len(first) {
			t.Fatalf("chain length changed across groups")
		}
		for i := range first {
			if first[i] != other[i] {
				differs = true
				break
			}
		}
	}
	if !differs {
		t.Fatal("chain order identical across 6 group IDs; gid salt is not applied")
	}
}
