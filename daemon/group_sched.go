// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"sort"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
)

const (
	alignProbeStart   = 5 * time.Second
	alignProbeMax     = 2 * time.Minute
	alignPeerCooldown = 2 * time.Second
	// alignFailCooldown sinks a peer that just failed to the back of this
	// round's candidate order. Purely local: skipping a center affects only
	// this node, never the room. Deep dial backoff stays in the conn pool.
	alignFailCooldown = 60 * time.Second
	alignSmallRoomMax = 4 // including self
	alignLargeWant    = 2
	alignTickPeriod   = 1 * time.Second
	alignGroupTimeout = 60 * time.Second
	alignSweepPeriod  = 15 * time.Minute
)

type alignGroupKey struct {
	aid a2al.Address
	gid [32]byte
}

type alignPeerKey struct {
	local, peer a2al.Address
	gid         [32]byte
}

type alignGroupState struct {
	due          time.Time
	backoff      time.Duration
	rotate       uint32
	authored     bool
	running      bool
	lastSyncPeer a2al.Address
	received     bool
	// centerDuty is the last derived push obligation for this replica.
	// Known is false until the first evaluation, so a small room's first
	// "not on duty" does not log as a step-down.
	centerDuty      bool
	centerDutyKnown bool
}

type alignPeerState struct {
	lastSync time.Time
	lastFail time.Time
	// pulledAt is when this peer last dialled us for this group. Push duty
	// follows whoever actually treats us as their rendezvous, so it moves on
	// its own when the chain slides.
	pulledAt time.Time
	// peerEntryCount is what the peer's Have reported last time we aligned:
	// strictly "it had N entries when I last saw it". This is what a writer
	// is shown, so nothing inferred may be mixed into it.
	peerEntryCount uint64
	// peerCoveredCount additionally assumes a completed round left the peer
	// holding everything we advertised. Good enough to decide whether a push
	// would be redundant, too speculative to show anyone as evidence: the
	// final Give is never acknowledged, so this can overshoot.
	peerCoveredCount uint64
	inflight         bool
}

func (d *Daemon) ensureAlignMaps() {
	if d.alignGroups == nil {
		d.alignGroups = make(map[alignGroupKey]*alignGroupState)
	}
	if d.alignPeers == nil {
		d.alignPeers = make(map[alignPeerKey]*alignPeerState)
	}
}

// kickAlignAID marks every local replica of aid due immediately.
// Liveness edges (register, heartbeat, network recovery) call this.
func (d *Daemon) kickAlignAID(aid a2al.Address) {
	if d.groups == nil {
		return
	}
	metas, err := d.groups.List(aid)
	if err != nil || len(metas) == 0 {
		return
	}
	now := time.Now()
	d.alignMu.Lock()
	d.ensureAlignMaps()
	for _, meta := range metas {
		st := d.groupStateLocked(aid, meta.ID())
		st.due = now
		if st.backoff == 0 {
			st.backoff = alignProbeStart
		}
	}
	d.alignMu.Unlock()
}

// kickAlignAuthored marks a self-write that must be pushed this round.
func (d *Daemon) kickAlignAuthored(aid a2al.Address, gid [32]byte) {
	now := time.Now()
	d.alignMu.Lock()
	d.ensureAlignMaps()
	st := d.groupStateLocked(aid, gid)
	st.authored = true
	st.due = now
	st.backoff = alignProbeStart
	d.alignMu.Unlock()
}

// noteAlignReceived returns information probing to the fast cadence without
// turning received entries into another fan-out trigger.
func (d *Daemon) noteAlignReceived(aid a2al.Address, gid [32]byte) {
	d.alignMu.Lock()
	d.ensureAlignMaps()
	st := d.groupStateLocked(aid, gid)
	st.backoff = alignProbeStart
	st.received = true
	if !st.authored {
		st.due = time.Now().Add(alignProbeStart)
	}
	d.alignMu.Unlock()
}

func (d *Daemon) groupStateLocked(aid a2al.Address, gid [32]byte) *alignGroupState {
	if d.alignGroups == nil {
		d.alignGroups = make(map[alignGroupKey]*alignGroupState)
	}
	k := alignGroupKey{aid, gid}
	st := d.alignGroups[k]
	if st == nil {
		st = &alignGroupState{backoff: alignProbeStart, due: time.Now()}
		d.alignGroups[k] = st
	}
	return st
}

func (d *Daemon) peerStateLocked(local, peer a2al.Address, gid [32]byte) *alignPeerState {
	if d.alignPeers == nil {
		d.alignPeers = make(map[alignPeerKey]*alignPeerState)
	}
	k := alignPeerKey{local, peer, gid}
	st := d.alignPeers[k]
	if st == nil {
		st = &alignPeerState{}
		d.alignPeers[k] = st
	}
	return st
}

// notePeerSync records that local and peer just completed a successful a2gp
// round, from either direction. Probe rounds skip this pair for 2s.
func (d *Daemon) notePeerSync(local, peer a2al.Address, gid [32]byte) {
	now := time.Now()
	d.alignMu.Lock()
	d.ensureAlignMaps()
	fwd := d.peerStateLocked(local, peer, gid)
	fwd.lastSync = now
	fwd.lastFail = time.Time{}
	rev := d.peerStateLocked(peer, local, gid)
	rev.lastSync = now
	rev.lastFail = time.Time{}
	if st := d.alignGroups[alignGroupKey{local, gid}]; st != nil {
		st.lastSyncPeer = peer
	}
	if st := d.alignGroups[alignGroupKey{peer, gid}]; st != nil {
		st.lastSyncPeer = local
	}
	d.alignMu.Unlock()
}

// notePeerRound records what a completed a2gp round taught us about the peer's
// replica. Together these two counts are the whole push condition — no
// generation ledger, and nothing that can be wrongly cleared.
//
// The two are kept apart on purpose. Scheduling may lean on the optimistic
// count, because guessing wrong there only costs a redundant or delayed push.
// Reporting must not, because a writer reading an inferred number as an
// observation is exactly the delivery assumption this design refuses.
func (d *Daemon) notePeerRound(local, peer a2al.Address, gid [32]byte, stats groupSyncStats) {
	d.alignMu.Lock()
	d.ensureAlignMaps()
	st := d.peerStateLocked(local, peer, gid)
	if stats.PeerHave > st.peerEntryCount {
		st.peerEntryCount = stats.PeerHave
	}
	covered := stats.PeerHave
	if stats.LocalHave > covered {
		covered = stats.LocalHave
	}
	if covered > st.peerCoveredCount {
		st.peerCoveredCount = covered
	}
	d.alignMu.Unlock()
}

// notePeerPull records that the peer dialled us for this group.
func (d *Daemon) notePeerPull(local, peer a2al.Address, gid [32]byte) {
	d.alignMu.Lock()
	d.ensureAlignMaps()
	d.peerStateLocked(local, peer, gid).pulledAt = time.Now()
	d.alignMu.Unlock()
}

// replicaHead reports how many entries we last saw peer holding, and when.
// It is strictly an observation; a peer we have never aligned with returns
// false rather than a zero that could be read as "empty" or "not delivered".
func (d *Daemon) replicaHead(local, peer a2al.Address, gid [32]byte) (uint64, time.Time, bool) {
	d.alignMu.Lock()
	defer d.alignMu.Unlock()
	st := d.alignPeers[alignPeerKey{local, peer, gid}]
	if st == nil || st.lastSync.IsZero() {
		return 0, time.Time{}, false
	}
	return st.peerEntryCount, st.lastSync, true
}

// notePeerFail records a local alignment failure. The peer is not dropped,
// only pushed behind the healthy candidates for alignFailCooldown, after which
// it is probed again — recovery needs no announcement from anyone.
func (d *Daemon) notePeerFail(local, peer a2al.Address, gid [32]byte) {
	d.alignMu.Lock()
	d.ensureAlignMaps()
	d.peerStateLocked(local, peer, gid).lastFail = time.Now()
	d.alignMu.Unlock()
}

// coolingPeersLocked returns the subset of peers that failed recently.
func (d *Daemon) coolingPeersLocked(local a2al.Address, gid [32]byte, peers []a2al.Address) map[a2al.Address]struct{} {
	now := time.Now()
	var out map[a2al.Address]struct{}
	for _, p := range peers {
		st := d.alignPeers[alignPeerKey{local, p, gid}]
		if st == nil || st.lastFail.IsZero() || now.Sub(st.lastFail) >= alignFailCooldown {
			continue
		}
		if out == nil {
			out = make(map[a2al.Address]struct{}, len(peers))
		}
		out[p] = struct{}{}
	}
	return out
}

func (d *Daemon) runGroupAlignSweep(ctx context.Context) {
	tick := time.NewTicker(alignTickPeriod)
	sweep := time.NewTicker(alignSweepPeriod)
	defer tick.Stop()
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			d.alignTick(ctx)
			d.centerPushTick(ctx)
		case <-sweep.C:
			d.alignAliveAIDs(ctx)
		}
	}
}

func (d *Daemon) alignTick(ctx context.Context) {
	now := time.Now()
	type job struct {
		aid a2al.Address
		gid [32]byte
	}
	var jobs []job
	d.alignMu.Lock()
	for k, st := range d.alignGroups {
		// A self-write is itself proof that the local agent is active. Keep
		// heartbeat gating only for daemon-initiated periodic probing.
		hasHeartbeat := false
		if !st.authored {
			hasHeartbeat = d.aidHasHeartbeat(k.aid)
		}
		if !shouldRunAlign(st, now, hasHeartbeat) {
			continue
		}
		st.running = true
		jobs = append(jobs, job{k.aid, k.gid})
	}
	d.alignMu.Unlock()

	for _, j := range jobs {
		go d.alignRound(ctx, j.aid, j.gid)
	}
}

func shouldRunAlign(st *alignGroupState, now time.Time, hasHeartbeat bool) bool {
	if st == nil || st.running {
		return false
	}
	if !st.authored && !hasHeartbeat {
		return false
	}
	return st.authored || !now.Before(st.due)
}

func (d *Daemon) alignRound(ctx context.Context, aid a2al.Address, gid [32]byte) {
	defer func() {
		d.alignMu.Lock()
		if st := d.alignGroups[alignGroupKey{aid, gid}]; st != nil {
			st.running = false
		}
		d.alignMu.Unlock()
	}()

	s, err := d.groups.Open(aid, gid)
	if err != nil {
		d.alignMu.Lock()
		delete(d.alignGroups, alignGroupKey{aid, gid})
		d.alignMu.Unlock()
		return
	}
	// An empty replica is a join that has not pulled yet. Outbound for that
	// state is the join probe, not the regular align loop.
	if s.EntryCount() == 0 {
		d.finishRound(aid, gid, false, true, false, 0)
		return
	}
	ms, err := s.Members()
	if err != nil {
		d.finishRound(aid, gid, false, false, false, 0)
		return
	}
	members := ms.All()
	others := alignMemberList(members, aid)
	chain := centerChain(gid, members)

	d.alignMu.Lock()
	st := d.groupStateLocked(aid, gid)
	authored := st.authored
	st.authored = false
	st.received = false
	rotate := st.rotate
	if len(others)+1 > alignSmallRoomMax {
		st.rotate++
	}
	order := alignCandidateOrder(others, chain, rotate, st.lastSyncPeer, d.coolingPeersLocked(aid, gid, others))
	d.alignMu.Unlock()

	targets := pickAlignTargets(order)
	if len(targets) == 0 {
		d.finishRound(aid, gid, authored, true, false, 0)
		return
	}

	queue := append([]a2al.Address(nil), targets...)
	queued := make(map[a2al.Address]struct{}, len(others))
	for _, peer := range queue {
		queued[peer] = struct{}{}
	}
	tried := make(map[a2al.Address]struct{}, len(others))
	okAll := true
	deferred := false
	received := 0
	extra := 0
	gctx, cancel := context.WithTimeout(ctx, alignGroupTimeout)
	defer cancel()

	for qi := 0; qi < len(queue); qi++ {
		peer := queue[qi]
		if _, seen := tried[peer]; seen {
			continue
		}
		tried[peer] = struct{}{}

		if !authored && d.peerRecentlySynced(aid, peer, gid) {
			deferred = true
			continue
		}
		if !d.markPeerInflight(aid, peer, gid) {
			deferred = true
			continue
		}
		n, serr := d.alignWithPeer(gctx, aid, gid, peer, s)
		d.clearPeerInflight(aid, peer, gid)
		received += n
		if serr != nil {
			okAll = false
			d.notePeerFail(aid, peer, gid)
			d.log.Debug("group align: peer failed",
				"group", hex.EncodeToString(gid[:4]),
				"peer", hex.EncodeToString(peer[:4]), "err", serr)
			if cand, next, ok := nextQueuedCandidate(order, extra, queued); ok {
				extra = next
				queued[cand] = struct{}{}
				queue = append(queue, cand)
			}
			continue
		}
		d.notePeerSync(aid, peer, gid)
		if n > 0 {
			d.log.Info("group align: caught up",
				"aid", hex.EncodeToString(aid[:4]),
				"group", hex.EncodeToString(gid[:4]),
				"peer", hex.EncodeToString(peer[:4]), "new", n)
		}
	}

	d.finishRound(aid, gid, authored, okAll, deferred, received)
}

func (d *Daemon) finishRound(aid a2al.Address, gid [32]byte, authored, okAll, deferred bool, received int) {
	now := time.Now()
	d.alignMu.Lock()
	st := d.groupStateLocked(aid, gid)
	if st.received && received == 0 {
		received = 1
	}
	st.received = false
	st.backoff = nextAlignBackoff(st.backoff, received, authored || st.authored, okAll && !deferred)
	if st.authored {
		st.due = now
	} else if deferred {
		st.due = now.Add(alignTickPeriod)
	} else {
		st.due = now.Add(st.backoff)
	}
	d.alignMu.Unlock()
}

func (d *Daemon) peerRecentlySynced(local, peer a2al.Address, gid [32]byte) bool {
	d.alignMu.Lock()
	defer d.alignMu.Unlock()
	st := d.alignPeers[alignPeerKey{local, peer, gid}]
	return st != nil && !st.lastSync.IsZero() && time.Since(st.lastSync) < alignPeerCooldown
}

func (d *Daemon) markPeerInflight(local, peer a2al.Address, gid [32]byte) bool {
	d.alignMu.Lock()
	defer d.alignMu.Unlock()
	d.ensureAlignMaps()
	st := d.peerStateLocked(local, peer, gid)
	if st.inflight {
		return false
	}
	st.inflight = true
	return true
}

func (d *Daemon) clearPeerInflight(local, peer a2al.Address, gid [32]byte) {
	d.alignMu.Lock()
	if st := d.alignPeers[alignPeerKey{local, peer, gid}]; st != nil {
		st.inflight = false
	}
	d.alignMu.Unlock()
}

func (d *Daemon) alignWithPeer(ctx context.Context, local a2al.Address, gid [32]byte, peer a2al.Address, localStore *group.Store) (int, error) {
	d.regMu.RLock()
	isLocal := d.reg != nil && d.reg.Get(peer) != nil
	d.regMu.RUnlock()
	if isLocal {
		peerStore, err := d.groups.Open(peer, gid)
		if err != nil {
			return d.SyncGroupWith(ctx, gid, local, peer)
		}
		prevPeer := peerStore.MaxSeq()
		prevLocal := localStore.MaxSeq()
		n, err := syncGroupLocalPipe(localStore, peerStore)
		if err != nil {
			return 0, err
		}
		got := int(localStore.MaxSeq() - prevLocal)
		// Same-daemon rounds hold both stores, so each side's head is a direct
		// observation rather than the peer's own account of itself. Record it
		// both ways: without this, replica_head for a co-resident member stays
		// at zero forever while lastSync keeps ticking, which reads as "peer
		// holds nothing" instead of the truth.
		localHave := uint64(localStore.EntryCount())
		peerHave := uint64(peerStore.EntryCount())
		d.notePeerRound(local, peer, gid, groupSyncStats{PeerHave: peerHave, LocalHave: localHave})
		d.notePeerRound(peer, local, gid, groupSyncStats{PeerHave: localHave, LocalHave: peerHave})
		if peerStore.MaxSeq() > prevPeer {
			d.notifyGroupNewEntries(peer, gid, peerStore, prevPeer)
		}
		if localStore.MaxSeq() > prevLocal {
			d.notifyGroupNewEntries(local, gid, localStore, prevLocal)
		}
		_ = n
		return got, nil
	}
	return d.SyncGroupWith(ctx, gid, local, peer)
}

func alignMemberList(members map[a2al.Address]group.MemberRole, self a2al.Address) []a2al.Address {
	var out []a2al.Address
	for m, role := range members {
		if m == self || role < group.RoleMember {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i][:], out[j][:]) < 0
	})
	return out
}

// alignCandidateOrder ranks every other member for this round: center chain
// order first (the rendezvous everyone else is converging on too), then the
// last successful peer and a rotating walk as the chainless fallback.
//
// chain may contain this node itself; only members present in others are kept,
// and others already excludes self.
//
// Peers in cooling sink to the back instead of being dropped, so the order
// always covers everyone and a round can never end up with no target. Large
// rooms never fall back to dialling all N-1 members: that is the O(N^2) cost
// centers exist to remove, and it gets worse exactly when the network is bad.
func alignCandidateOrder(others, chain []a2al.Address, rotate uint32, lastSync a2al.Address, cooling map[a2al.Address]struct{}) []a2al.Address {
	n := len(others)
	if n == 0 {
		return nil
	}
	in := make(map[a2al.Address]struct{}, n)
	for _, p := range others {
		in[p] = struct{}{}
	}
	seen := make(map[a2al.Address]struct{}, n)
	hot := make([]a2al.Address, 0, n)
	var cold []a2al.Address
	add := func(p a2al.Address) {
		if _, ok := in[p]; !ok {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		if _, c := cooling[p]; c {
			cold = append(cold, p)
			return
		}
		hot = append(hot, p)
	}
	for _, p := range chain {
		add(p)
	}
	add(lastSync)
	for i := 0; i < n; i++ {
		add(others[int(rotate+uint32(i))%n])
	}
	return append(hot, cold...)
}

// pickAlignTargets takes this round's targets off the candidate order.
// Small rooms take everyone; large rooms take the two leading candidates and
// leave the rest as replacements for failures.
func pickAlignTargets(order []a2al.Address) []a2al.Address {
	if len(order)+1 <= alignSmallRoomMax {
		return append([]a2al.Address(nil), order...)
	}
	if len(order) > alignLargeWant {
		return append([]a2al.Address(nil), order[:alignLargeWant]...)
	}
	return append([]a2al.Address(nil), order...)
}

// nextQueuedCandidate walks further down the candidate order to replace a
// target that just failed.
func nextQueuedCandidate(order []a2al.Address, start int, queued map[a2al.Address]struct{}) (a2al.Address, int, bool) {
	for i := start; i < len(order); i++ {
		cand := order[i]
		if _, exists := queued[cand]; exists {
			continue
		}
		return cand, i + 1, true
	}
	return a2al.Address{}, len(order), false
}

func nextAlignBackoff(cur time.Duration, received int, authored, okAll bool) time.Duration {
	if received > 0 || authored {
		return alignProbeStart
	}
	if !okAll {
		if cur < alignProbeStart {
			return alignProbeStart
		}
		return cur
	}
	switch {
	case cur < 10*time.Second:
		return 10 * time.Second
	case cur < 30*time.Second:
		return 30 * time.Second
	case cur < time.Minute:
		return time.Minute
	default:
		return alignProbeMax
	}
}
