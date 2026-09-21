// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
)

type simMember struct {
	aid   a2al.Address
	priv  ed25519.PrivateKey
	store *group.Store
}

// newSimRoom builds n replicas of one group, all caught up with the creator.
func newSimRoom(t *testing.T, n int) ([]simMember, [32]byte) {
	t.Helper()

	privC, aidC := testSyncIdentity(t)
	creatorStore, err := group.Create(t.TempDir(), privC, aidC, "sim")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = creatorStore.Close() })
	gid := creatorStore.Meta().GroupID

	members := []simMember{{aid: aidC, priv: privC, store: creatorStore}}
	for i := 1; i < n; i++ {
		priv, aid := testSyncIdentity(t)
		inv, err := group.NewEntry(privC, aidC, creatorStore.Heads(), group.KindInvite,
			group.WithBody(group.EncodeMemberBody(aid)))
		if err != nil {
			t.Fatal(err)
		}
		if err := creatorStore.Append(inv, nil); err != nil {
			t.Fatal(err)
		}
		s, err := group.Join(t.TempDir(), gid, aidC, "sim")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		members = append(members, simMember{aid: aid, priv: priv, store: s})
	}

	for _, m := range members[1:] {
		if _, err := syncGroupLocalPipe(creatorStore, m.store); err != nil {
			t.Fatalf("seed %v: %v", m.aid, err)
		}
	}
	for _, m := range members {
		if m.store.EntryCount() != creatorStore.EntryCount() {
			t.Fatalf("seed left %v at %d of %d entries", m.aid, m.store.EntryCount(), creatorStore.EntryCount())
		}
	}
	return members, gid
}

// simRound has every member align with the targets it derives locally, and
// nothing else: no center pushes, no fan-out, no coordination.
func simRound(t *testing.T, members []simMember, gid [32]byte, down map[a2al.Address]struct{}) int {
	t.Helper()
	roles := make(map[a2al.Address]group.MemberRole, len(members))
	for _, m := range members {
		roles[m.aid] = group.RoleMember
	}
	byAID := make(map[a2al.Address]*group.Store, len(members))
	for i := range members {
		byAID[members[i].aid] = members[i].store
	}

	streams := 0
	for _, m := range members {
		if _, off := down[m.aid]; off {
			continue
		}
		others := alignMemberList(roles, m.aid)
		chain := make([]a2al.Address, 0, len(others))
		for _, aid := range centerChain(gid, roles) {
			if aid != m.aid {
				chain = append(chain, aid)
			}
		}
		targets := pickAlignTargets(alignCandidateOrder(others, chain, 0, a2al.Address{}, down))
		if len(targets) > alignLargeWant {
			t.Fatalf("%v picked %d targets; large rooms must stay at %d", m.aid, len(targets), alignLargeWant)
		}
		for _, peer := range targets {
			if _, off := down[peer]; off {
				continue
			}
			streams++
			if _, err := syncGroupLocalPipe(m.store, byAID[peer]); err != nil {
				t.Fatalf("%v -> %v: %v", m.aid, peer, err)
			}
		}
	}
	return streams
}

func simConverged(members []simMember, down map[a2al.Address]struct{}) bool {
	want := -1
	for _, m := range members {
		if _, off := down[m.aid]; off {
			continue
		}
		n := m.store.EntryCount()
		if want < 0 {
			want = n
		} else if n != want {
			return false
		}
	}
	return true
}

func simAppend(t *testing.T, m simMember, text string) {
	t.Helper()
	e, err := group.NewEntry(m.priv, m.aid, m.store.Heads(), "msg", group.WithBody([]byte(text)))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.store.Append(e, nil); err != nil {
		t.Fatal(err)
	}
}

// Both sides of a local sync write their Have before reading the other's, so
// the stream underneath must not be able to block a writer. It used to be an
// unbuffered pipe, which deadlocked every same-daemon alignment.
func TestSyncGroupLocalPipeExchangesBothDirections(t *testing.T) {
	members, _ := newSimRoom(t, 2)
	a, b := members[0], members[1]
	simAppend(t, a, "from a")
	simAppend(t, b, "from b")

	want := a.store.EntryCount() + 1 // each side is missing exactly the other's entry
	if _, err := syncGroupLocalPipe(a.store, b.store); err != nil {
		t.Fatal(err)
	}
	if got := a.store.EntryCount(); got != want {
		t.Fatalf("a has %d entries, want %d", got, want)
	}
	if got := b.store.EntryCount(); got != want {
		t.Fatalf("b has %d entries, want %d", got, want)
	}
}

// Centers are a latency optimisation, so a room with center pushes entirely
// disabled must still converge — only slower. This is the test that would
// catch any hidden assumption that a center forwards on a writer's behalf.
func TestTwentyMemberRoomConvergesWithZeroCenterPush(t *testing.T) {
	members, gid := newSimRoom(t, 20)
	for i, idx := range []int{3, 11, 19} {
		simAppend(t, members[idx-1], fmt.Sprintf("message %d", i))
	}

	rounds := 0
	for ; rounds < 12 && !simConverged(members, nil); rounds++ {
		simRound(t, members, gid, nil)
	}
	if !simConverged(members, nil) {
		t.Fatalf("20 members did not converge in %d push-free rounds", rounds)
	}
	t.Logf("converged in %d rounds with no center pushes", rounds)
}

// The room must keep converging while the whole leading section of the chain
// is offline: duty slides down, and nobody falls back to dialling everyone.
func TestTwentyMemberRoomConvergesWithLeadersOffline(t *testing.T) {
	members, gid := newSimRoom(t, 20)

	roles := make(map[a2al.Address]group.MemberRole, len(members))
	for _, m := range members {
		roles[m.aid] = group.RoleMember
	}
	down := make(map[a2al.Address]struct{}, 5)
	for _, aid := range centerChain(gid, roles)[:5] {
		down[aid] = struct{}{}
	}

	for _, m := range members {
		if _, off := down[m.aid]; !off {
			simAppend(t, m, "from an online member")
			break
		}
	}

	maxStreams := 0
	rounds := 0
	for ; rounds < 12 && !simConverged(members, down); rounds++ {
		if s := simRound(t, members, gid, down); s > maxStreams {
			maxStreams = s
		}
	}
	if !simConverged(members, down) {
		t.Fatalf("online members did not converge in %d rounds with 5 leaders down", rounds)
	}
	if maxStreams > len(members)*alignLargeWant {
		t.Fatalf("%d streams in one round; the room degenerated towards full mesh", maxStreams)
	}
}
