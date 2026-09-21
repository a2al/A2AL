// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
)

// Alignment centers are derived, never negotiated: every replica that agrees on
// the group ID and the member set computes the same chain. Nothing about center
// identity is transmitted, stored, or voted on.
//
// A center is a rendezvous point for alignment, not a forwarder. It carries no
// delivery obligation; picking the "wrong" center only costs latency, because
// a2gp propagation is symmetric pull by every member.
const (
	// centerCount is how many leading chain entries act as centers.
	// One would be a single point; two keeps the target sets of any two
	// members overlapping even when reachability differs (NAT).
	centerCount = 2

	// centerPullTTL is how long a peer stays on our push list after it last
	// pulled from us.
	centerPullTTL = 15 * time.Minute
	// centerPushRate caps center-initiated streams per local AID across all
	// its rooms. Exceeding it only delays a push; members reach everything
	// through their own probing regardless.
	centerPushRate  = 10.0
	centerPushBurst = 20.0
)

// tokenBucket is a plain rate limiter; pulling in a dependency for this would
// be overkill.
type tokenBucket struct {
	tokens float64
	last   time.Time
}

func (b *tokenBucket) allow(now time.Time) bool {
	if b.last.IsZero() {
		b.tokens = centerPushBurst
	} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * centerPushRate
		if b.tokens > centerPushBurst {
			b.tokens = centerPushBurst
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// centerKey is the sort key of aid within gid's chain. Salting by group ID
// spreads center duty across rooms instead of concentrating it on whichever
// AIDs happen to hash low globally.
func centerKey(gid [32]byte, aid a2al.Address) [32]byte {
	buf := make([]byte, 0, len(gid)+len(aid))
	buf = append(buf, gid[:]...)
	buf = append(buf, aid[:]...)
	return sha256.Sum256(buf)
}

// centerChain orders every member eligible to hold a replica by centerKey.
// The first centerCount entries are the centers; the rest is the succession
// order used when those are unreachable.
//
// Pending invitees are excluded: they may hash to the front while holding no
// replica at all. The result is a total order, so all replicas of the same
// member set agree element for element.
func centerChain(gid [32]byte, members map[a2al.Address]group.MemberRole) []a2al.Address {
	out := make([]a2al.Address, 0, len(members))
	for aid, role := range members {
		if role < group.RoleMember {
			continue
		}
		out = append(out, aid)
	}
	keys := make(map[a2al.Address][32]byte, len(out))
	for _, aid := range out {
		keys[aid] = centerKey(gid, aid)
	}
	sort.Slice(out, func(i, j int) bool {
		ki, kj := keys[out[i]], keys[out[j]]
		if c := bytes.Compare(ki[:], kj[:]); c != 0 {
			return c < 0
		}
		// Hash collision: fall back to AID bytes so the order stays total.
		return bytes.Compare(out[i][:], out[j][:]) < 0
	})
	return out
}

// centerRank returns aid's position in the chain, or -1 if aid may not hold a
// replica. Rank is self-knowledge: an AID learns it took over or stepped down
// purely by recomputing after the member set changes.
func centerRank(gid [32]byte, members map[a2al.Address]group.MemberRole, aid a2al.Address) int {
	if members[aid] < group.RoleMember {
		return -1
	}
	self := centerKey(gid, aid)
	rank := 0
	for other, role := range members {
		if other == aid || role < group.RoleMember {
			continue
		}
		k := centerKey(gid, other)
		c := bytes.Compare(k[:], self[:])
		if c < 0 || (c == 0 && bytes.Compare(other[:], aid[:]) < 0) {
			rank++
		}
	}
	return rank
}

// isCenter reports whether aid leads gid's chain.
func isCenter(gid [32]byte, members map[a2al.Address]group.MemberRole, aid a2al.Address) bool {
	r := centerRank(gid, members, aid)
	return r >= 0 && r < centerCount
}

// replicaHolders counts the members that actually hold a replica. Revoked and
// pending entries stay in the member set forever, so raw map length is not a
// room size: using it here would enable center pushes in a room the scheduler
// still treats as small and aligns with in full.
func replicaHolders(members map[a2al.Address]group.MemberRole) int {
	n := 0
	for _, role := range members {
		if role >= group.RoleMember {
			n++
		}
	}
	return n
}

// centerDuty reports whether aid owes pushes for this room: centers only earn
// their keep once the room is too big for everyone to align with everyone.
func centerDuty(gid [32]byte, members map[a2al.Address]group.MemberRole, aid a2al.Address) bool {
	if replicaHolders(members) <= alignSmallRoomMax {
		return false
	}
	return isCenter(gid, members, aid)
}

// noteCenterDuty records whether this replica currently owes pushes, and logs
// only when that answer changes. The first "no" is silent: every small room
// starts there, and logging it would drown the two events that matter — taking
// duty when the room grows, and dropping it when the chain slides us out.
func (d *Daemon) noteCenterDuty(aid a2al.Address, gid [32]byte, duty bool) {
	d.alignMu.Lock()
	d.ensureAlignMaps()
	st := d.groupStateLocked(aid, gid)
	prev, known := st.centerDuty, st.centerDutyKnown
	st.centerDuty = duty
	st.centerDutyKnown = true
	d.alignMu.Unlock()

	if known && prev == duty {
		return
	}
	if !known && !duty {
		return
	}
	msg := "group center: took duty"
	if !duty {
		msg = "group center: dropped duty"
	}
	d.log.Debug(msg,
		"aid", hex.EncodeToString(aid[:4]),
		"group", hex.EncodeToString(gid[:4]))
}

// centerPushTick pushes fresh entries to the members that pull from us.
//
// This is a latency optimisation and nothing else. Every member still probes on
// its own schedule, so a push that is skipped, throttled or aimed at the wrong
// peer costs time, never entries.
//
// The whole decision is two numbers we already keep: who pulled from us
// recently, and how many entries we last saw them holding. There is no
// generation ledger to get wrong, and stepping down needs no announcement —
// a member set change simply makes centerRank say no.
func (d *Daemon) centerPushTick(ctx context.Context) {
	type job struct {
		aid a2al.Address
		gid [32]byte
	}
	var groups []job
	d.alignMu.Lock()
	for k := range d.alignGroups {
		groups = append(groups, job{k.aid, k.gid})
	}
	d.alignMu.Unlock()

	now := time.Now()
	for _, g := range groups {
		if !d.aidHasHeartbeat(g.aid) {
			continue
		}
		s, err := d.groups.Open(g.aid, g.gid)
		if err != nil {
			continue
		}
		ms, err := s.Members()
		if err != nil {
			continue
		}
		members := ms.All()
		duty := centerDuty(g.gid, members, g.aid)
		d.noteCenterDuty(g.aid, g.gid, duty)
		if !duty {
			continue
		}
		local := uint64(s.EntryCount())
		for _, peer := range d.centerPushDue(g.aid, g.gid, members, local, now) {
			if !d.centerTokenAvailable(g.aid, now) {
				break
			}
			if !d.markPeerInflight(g.aid, peer, g.gid) {
				continue
			}
			go d.centerPushTo(ctx, g.aid, g.gid, peer, s)
		}
	}
}

// centerPushDue lists members that pulled from us recently and are, as far as
// we last observed, behind. Oldest contact first so nobody starves under the
// rate limit.
func (d *Daemon) centerPushDue(aid a2al.Address, gid [32]byte, members map[a2al.Address]group.MemberRole, local uint64, now time.Time) []a2al.Address {
	d.alignMu.Lock()
	defer d.alignMu.Unlock()

	var due []a2al.Address
	for peer, role := range members {
		if peer == aid || role < group.RoleMember {
			continue
		}
		st := d.alignPeers[alignPeerKey{aid, peer, gid}]
		if st == nil || st.inflight {
			continue
		}
		if st.pulledAt.IsZero() || now.Sub(st.pulledAt) > centerPullTTL {
			continue
		}
		if now.Sub(st.lastSync) < alignPeerCooldown {
			continue
		}
		// A peer that can dial us but that we cannot dial back is the normal
		// NAT case, and a failed push leaves lastSync untouched. Without this
		// the peer stays due every tick, and because the queue is oldest-first
		// its stalling lastSync sorts it ever earlier, letting one unreachable
		// member drain this AID's push budget for every room it centers.
		if !st.lastFail.IsZero() && now.Sub(st.lastFail) < alignFailCooldown {
			continue
		}
		if local <= st.peerCoveredCount {
			continue
		}
		due = append(due, peer)
	}
	sort.Slice(due, func(i, j int) bool {
		a := d.alignPeers[alignPeerKey{aid, due[i], gid}]
		b := d.alignPeers[alignPeerKey{aid, due[j], gid}]
		return a.lastSync.Before(b.lastSync)
	})
	return due
}

func (d *Daemon) centerTokenAvailable(aid a2al.Address, now time.Time) bool {
	d.alignMu.Lock()
	defer d.alignMu.Unlock()
	if d.centerBuckets == nil {
		d.centerBuckets = make(map[a2al.Address]*tokenBucket)
	}
	b := d.centerBuckets[aid]
	if b == nil {
		b = &tokenBucket{}
		d.centerBuckets[aid] = b
	}
	return b.allow(now)
}

func (d *Daemon) centerPushTo(ctx context.Context, aid a2al.Address, gid [32]byte, peer a2al.Address, s *group.Store) {
	pushCtx, cancel := context.WithTimeout(ctx, alignGroupTimeout)
	defer cancel()
	_, err := d.alignWithPeer(pushCtx, aid, gid, peer, s)
	d.clearPeerInflight(aid, peer, gid)
	if err != nil {
		d.notePeerFail(aid, peer, gid)
		d.log.Debug("group center: push failed",
			"group", hex.EncodeToString(gid[:4]),
			"peer", hex.EncodeToString(peer[:4]), "err", err)
		return
	}
	d.notePeerSync(aid, peer, gid)
	d.log.Debug("group center: pushed",
		"aid", hex.EncodeToString(aid[:4]),
		"group", hex.EncodeToString(gid[:4]),
		"peer", hex.EncodeToString(peer[:4]))
}
