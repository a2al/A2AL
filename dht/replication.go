// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)

// Replication strategy parameters (节点行为策略 §2 and §3).
const (
	nRep              = 8                // soft replication target N_rep
	repHardCap        = routing.K        // hard cap = K = 16
	probeInitDelay    = 30 * time.Second // Unknown node: initial probe interval
	// pathCacheSoftTTL is the node-local expiry for path-cached sovereign records
	// when the publisher cannot be reached to confirm the node is in repSet.
	// Aligned to 4× probeInitDelay so it fits naturally in the health-probe cycle.
	pathCacheSoftTTL = 4 * probeInitDelay // = 2 minutes
	probeMaxDelay     = 1 * time.Hour    // Good node: ceiling; in practice StoreAt (every 30 min) contacts the node first
	probeBadDelay     = 30 * time.Minute // Bad node: grace window before eviction
	probeTickInterval  = 15 * time.Second // health probe loop wake-up interval
	replChBuf          = 64               // replication task channel buffer
	gapFillPunchBudget = 2                // max new ICE attempts per gap-fill cycle

	// epPrefetchFailCountCap is the maximum failCount stored in epPrefetchNegEntry.
	// probeInitDelay << epPrefetchFailCountCap must exceed probeBadDelay so the
	// exponential back-off always hits the cap branch before integer shift overflow.
	// 30s << 7 = 3840s ≈ 64 min > probeBadDelay (30 min). ✓
	epPrefetchFailCountCap = 7
)

// repKey uniquely identifies one (storeKey, publisher) replication unit.
// Topic records share a storeKey but each publisher maintains its own repSet.
type repKey struct {
	storeKey  a2al.NodeID
	publisher a2al.NodeID
}

// repNodeEntry tracks one confirmed remote replica and its probe schedule.
type repNodeEntry struct {
	nodeID         a2al.NodeID
	confirmedAt    time.Time
	confirmedSeq   uint64        // Seq of the last record this node confirmed holding (0 = unknown)
	failCount      int
	badSince       time.Time     // non-zero: node is in 30-min grace window before eviction
	nextProbeAt    time.Time
	nextProbeDelay time.Duration // current exponential back-off interval

	// Phase 0 reserved fields — declared here so Phase 7 can start populating
	// them without touching unrelated code. All three are zero/false until
	// Phase 7 (ReplicationSet dual-set) is implemented; existing logic must
	// not read or write these fields before that phase.
	isPunched   bool // node was reached via ICE hole-punch, not direct UDP
	inXorSet    bool // member of the XOR-distance-closest N_rep set
	inDirectSet bool // member of the directly-reachable N_rep set
}

// repSet tracks confirmed remote replicas for one (storeKey, publisher) pair.
type repSet struct {
	mu          sync.Mutex
	storeKey    a2al.NodeID
	rec         protocol.SignedRecord
	nodes       map[string]*repNodeEntry // nodeIDKey(id) → entry
	renewEpoch time.Time // set to cycleStart after each renewBackground completes; active = confirmedAt.After(renewEpoch)
}

// replTask is a work item for the replication maintainer (过程二).
// A zero rec (empty Address) signals a refill-only task: use the record
// already stored in the repSet.  A non-zero rec updates the stored record first.
type replTask struct {
	rk  repKey
	rec protocol.SignedRecord
}

// startReplicationWorkers launches 过程二 (replication maintainer) and
// 过程三 (health probe) goroutines bound to n.ctx.
// Called from Start() under recvOnce.
func (n *Node) startReplicationWorkers() {
	n.wg.Add(2)
	go n.replMaintainer(n.ctx)
	go n.healthProbeLoop(n.ctx)
}

// enqueueReplication queues a replication task.  Non-blocking: drops if the
// channel is full (the maintainer will catch up on the next probe cycle).
func (n *Node) enqueueReplication(rk repKey, rec protocol.SignedRecord) {
	select {
	case n.replCh <- replTask{rk: rk, rec: rec}:
	default:
	}
}

// getOrCreateRepSet returns the repSet for rk, creating it if absent.
func (n *Node) getOrCreateRepSet(rk repKey) *repSet {
	n.repMu.Lock()
	defer n.repMu.Unlock()
	rs := n.repSets[rk]
	if rs == nil {
		rs = &repSet{
			storeKey: rk.storeKey,
			nodes:    make(map[string]*repNodeEntry),
		}
		n.repSets[rk] = rs
	}
	return rs
}

// RepSetSize returns the total number of tracked remote replicas for a record.
// Deprecated: prefer RepSetCounts which also returns the active (confirmed this
// cycle) count. RepSetSize is kept for callers that only need the total.
func (n *Node) RepSetSize(storeKey, publisher a2al.NodeID) int {
	_, total := n.RepSetCounts(storeKey, publisher)
	return total
}

// RepSetCounts returns (active, total) replica counts for (storeKey, publisher).
//
//   - active: confirmed in the most recent renewBackground cycle — these are
//     the replicas we have 100% confidence in right now.
//   - total: all entries currently tracked (includes entries whose renewal has
//     not yet succeeded in the current cycle).
//
// Before the first renewal cycle completes, active == 0.
func (n *Node) RepSetCounts(storeKey, publisher a2al.NodeID) (active, total int) {
	rk := repKey{storeKey: storeKey, publisher: publisher}
	n.repMu.RLock()
	rs := n.repSets[rk]
	n.repMu.RUnlock()
	if rs == nil {
		return 0, 0
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	epoch := rs.renewEpoch
	for _, e := range rs.nodes {
		total++
		if !epoch.IsZero() && e.confirmedAt.After(epoch) {
			active++
		}
	}
	return active, total
}

// RemoveRepSetsForPublisher removes all repSets whose publisher matches the
// given NodeID.  Call when an agent is deleted so background probes and
// refill tasks cease.
func (n *Node) RemoveRepSetsForPublisher(publisher a2al.NodeID) {
	n.repMu.Lock()
	for rk := range n.repSets {
		if rk.publisher == publisher {
			delete(n.repSets, rk)
			delete(n.renewInFlight, rk)
		}
	}
	n.repMu.Unlock()
}

// ─── 过程二: Replication Maintainer ───────────────────────────────────────────

// replMaintainer processes replication tasks from replCh.  Each task is
// handled in a separate goroutine so slow StoreAt calls don't block the
// channel.
func (n *Node) replMaintainer(ctx context.Context) {
	defer n.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-n.replCh:
			go n.processReplTask(ctx, task)
		}
	}
}

// processReplTask fills gaps in direct and punched replication tracks.
func (n *Node) processReplTask(ctx context.Context, task replTask) {
	rs := n.getOrCreateRepSet(task.rk)

	if len(task.rec.Address) > 0 {
		rs.mu.Lock()
		rs.rec = task.rec
		rs.mu.Unlock()
	}

	rs.mu.Lock()
	rec := rs.rec
	existing := make(map[string]struct{}, len(rs.nodes))
	for k := range rs.nodes {
		existing[k] = struct{}{}
	}
	rs.mu.Unlock()

	if len(rec.Address) == 0 {
		return
	}
	directNeed, punchedNeed, active := repSetTrackNeeds(rs)
	if active >= repHardCap || (directNeed <= 0 && punchedNeed <= 0) {
		return
	}

	directPool := n.tabNearestHealthy(task.rk.storeKey, repHardCap)
	xorPool := n.tabNearest(task.rk.storeKey, repHardCap)
	// Proactively fetch endpoint records for NAT candidates that are not yet
	// cached locally (same as in renewBackground).  Only worthwhile while the
	// punched track still needs filling — when full the picker selects no NAT.
	if punchedNeed > 0 {
		n.prefetchNATEndpoints(ctx, xorPool)
	}
	direct, nat := n.pickGapFillPeers(task.rk.storeKey, rs, directPool, xorPool, existing)
	if len(direct) > 0 {
		n.storeAndRecord(ctx, direct, task.rk, rec, rs)
	}
	n.gapFillStoreNAT(ctx, task.rk, rec, rs, nat)
}

// scheduleReplicate kicks off async replication for a record that was just
// written to the local store.  Updates (or creates) the repSet, then spawns
// renewBackground (FindNode + StoreAt to best reachable nodes).
//
//防重入: if a renewBackground goroutine is already running for rk, the new
// call updates rs.rec in place (the running goroutine will pick up the latest
// record) and returns immediately.  The caller's record is guaranteed to be
// pushed on the next TTL/2 republish cycle if the current run completes first.
func (n *Node) scheduleReplicate(storeKey a2al.NodeID, rec protocol.SignedRecord) {
	var pubAddr a2al.Address
	copy(pubAddr[:], rec.Address)
	publisher := a2al.NodeIDFromAddress(pubAddr)
	rk := repKey{storeKey: storeKey, publisher: publisher}

	rs := n.getOrCreateRepSet(rk)
	rs.mu.Lock()
	rs.rec = rec // always update: running goroutine re-reads rs.rec at start
	rs.mu.Unlock()

	n.repMu.Lock()
	_, inFlight := n.renewInFlight[rk]
	if inFlight {
		n.repMu.Unlock()
		return
	}
	n.renewInFlight[rk] = struct{}{}
	n.repMu.Unlock()

	go func() {
		defer func() {
			n.repMu.Lock()
			delete(n.renewInFlight, rk)
			n.repMu.Unlock()
		}()
		n.renewBackground(rk, rs)
	}()
}

// renewBackground is the async body shared by initial publication (过程一) and
// TTL renewal (过程四).  It reads the latest record from rs, runs FindNode to
// refresh topology, renews existing replicas, and stores to closer new peers.
//
// Filtering strategy for newPeers (discovered by FindNode):
//   - Always skip nodes already in the repSet and nodes the health system
//     has marked Bad (PeerHealthBad) — these are known-unreachable and would
//     only waste the 2 s per-RPC timeout.
//   - When repSet < N_rep: attempt all remaining candidates (gap filling).
//   - When repSet >= N_rep: only attempt nodes that are XOR-closer than the
//     current farthest repSet member (topology refresh without exhausting
//     unreachable peers).  Up to repHardCap total.
//
// Additional housekeeping:
//   - Failed renewals get nextProbeAt = now so 过程三 detects failure within
//     one tick (≤15 s) instead of waiting up to probeMaxDelay (10 min).
//   - If repSet is still below N_rep after all attempts a refill task is
//     queued to 过程二.
func (n *Node) renewBackground(rk repKey, rs *repSet) {
	ctx := n.ctx
	// Record the cycle start before any I/O.  renewEpoch is set to this value
	// only after all storeAndRecord calls complete, so that active = "confirmed
	// in the most recently COMPLETED cycle" is always a stable snapshot.
	cycleStart := time.Now()

	// Always read the latest record (may have been updated while we were queued).
	rs.mu.Lock()
	rec := rs.rec
	rs.mu.Unlock()
	if len(rec.Address) == 0 {
		return
	}

	// FindNode discovers the current k-closest peers to the key.
	// In passive mode skip the iterative query: a well-connected passive node
	// accumulates a dense local routing table through incoming traffic, so
	// tabNearestHealthy gives an equally good result without any outbound RPCs.
	var found []protocol.NodeInfo
	if n.passiveRouting.Load() {
		found = n.tabNearestHealthy(rk.storeKey, repHardCap)
	} else {
		q := NewQuery(n)
		var fnErr error
		found, fnErr = q.FindNode(ctx, rk.storeKey)
		if fnErr != nil || ctx.Err() != nil {
			found = nil
		}
	}

	// Re-read the latest record after FindNode: the goroutine may have been
	// suspended (e.g. OS sleep/wake) or a new publication may have arrived
	// while FindNode was in flight.  Using the freshest record here ensures
	// we never push a stale or expired record to existing replicas.
	rs.mu.Lock()
	rec = rs.rec
	rs.mu.Unlock()
	if len(rec.Address) == 0 {
		return
	}

	rs.mu.Lock()
	now := time.Now()
	existingIDs := make([]a2al.NodeID, 0, len(rs.nodes))
	existing := make(map[string]struct{}, len(rs.nodes))
	// Snapshot confirmedAt so we can detect which renewals failed below.
	preRenewConfirmed := make(map[string]time.Time, len(rs.nodes))
	// Phase 6: collect bad repSet members for punch trigger after unlock.
	var badRepNodes []a2al.NodeID
	for k, e := range rs.nodes {
		existing[k] = struct{}{}
		preRenewConfirmed[k] = e.confirmedAt
		// For confirmed replicas (existing repSet members), skip renewal only
		// when the repSet-level eviction grace window is active (badSince set
		// by probeRepNode after repeated dedicated-probe failures).  The global
		// PeerHealthBad flag is intentionally not checked here: it can be
		// raised by health probes whose failures do not indicate that the peer
		// is unreachable for StoreAt, and it has no recovery path for existing
		// replicas (renewal success is the only thing that clears failCount).
		// Relying on badSince keeps the two concerns separate: global health
		// governs new candidate selection; repSet-level health governs eviction.
		if !e.badSince.IsZero() {
			// Do not shorten the grace window: only override nextProbeAt when
			// probeBadDelay has already elapsed.  Cascades triggered by
			// sleep/wake or network change call renewBackground immediately,
			// and resetting nextProbeAt = now would collapse the 30-min grace
			// to a single probeTickInterval (15 s), causing healthy nodes to
			// be evicted faster than the normal eviction path.
			if time.Since(e.badSince) >= probeBadDelay {
				e.nextProbeAt = now
			}
			badRepNodes = append(badRepNodes, e.nodeID) // Phase 6
			continue
		}
		// Skip renewal RPC only when all three conditions hold:
		//   1. rec version unchanged (confirmedSeq == rec.Seq)
		//   2. already confirmed by a real RPC in the current cycle
		//      (confirmedAt.After(renewEpoch)); nodes not yet confirmed this
		//      cycle must be contacted regardless — that is the mandatory
		//      fact-finding of each renewal pass.
		//   3. node is probe-healthy (failCount == 0); a node with pending
		//      probe failures needs a StoreAt to re-establish facts.
		// confirmedAt is intentionally NOT updated here: it is a pure fact
		// field updated only by a successful StoreAt RPC.  Nodes removed from
		// preRenewConfirmed are excluded from the post-renewal fast-probe check
		// so they are not mistaken for renewal failures.
		if e.confirmedSeq == rec.Seq &&
			e.confirmedAt.After(rs.renewEpoch) &&
			e.failCount == 0 {
			delete(preRenewConfirmed, k)
			continue
		}
		existingIDs = append(existingIDs, e.nodeID)
	}
	rs.mu.Unlock()

	// Phase 6 (过程二, High priority): trigger ICE punch for each bad repSet
	// member that has a signal URL.  These nodes are in the grace window and
	// their record availability is directly at risk — punch is worth the cost.
	for _, nid := range badRepNodes {
		if er := n.lookupEndpointRecord(nid); er != nil {
			n.triggerPunch(nid, er, PunchPriorityHigh)
		}
	}

	// Renew existing replicas (they expire without a fresh STORE).
	if len(existingIDs) > 0 {
		existingPeers := make([]protocol.NodeInfo, 0, len(existingIDs))
		for _, id := range existingIDs {
			existingPeers = append(existingPeers, protocol.NodeInfo{
				NodeID: append([]byte(nil), id[:]...),
			})
		}
		n.storeAndRecord(ctx, existingPeers, rk, rec, rs)

		// For nodes whose renewal just failed (confirmedAt unchanged from the
		// pre-renewal snapshot), set nextProbeAt = now so 过程三 detects the
		// failure within one tick (≤15 s) instead of waiting up to probeMaxDelay.
		// Skipped nodes were removed from preRenewConfirmed above and will not
		// appear here, so they are not mistaken for renewal failures.
		now := time.Now()
		rs.mu.Lock()
		for k, before := range preRenewConfirmed {
			if e, ok := rs.nodes[k]; ok && e.confirmedAt == before {
				e.nextProbeAt = now
			}
		}
		rs.mu.Unlock()
	}

	// Gap-fill new peers via dual-track plan (direct + punched XOR-near NAT).
	directPool := n.tabNearestHealthy(rk.storeKey, repHardCap)
	xorPool := n.tabNearest(rk.storeKey, repHardCap)
	if len(found) > 0 {
		xorPool = found
	}
	// Proactively fetch endpoint records for NAT candidates that are not yet
	// cached locally.  Without their signal URLs, pickGapFillPeers would skip
	// them; this ensures the NAT track can actually be populated this cycle.
	// Only worthwhile while the punched track still needs filling — when full
	// the picker selects no NAT.
	if _, punchedNeed, _ := repSetTrackNeeds(rs); punchedNeed > 0 {
		n.prefetchNATEndpoints(ctx, xorPool)
	}
	direct, nat := n.pickGapFillPeers(rk.storeKey, rs, directPool, xorPool, existing)
	if len(direct) > 0 {
		n.storeAndRecord(ctx, direct, rk, rec, rs)
	}
	n.gapFillStoreNAT(ctx, rk, rec, rs, nat)

	// Cycle complete: publish the epoch so RepSetCounts and repSetTrackNeeds
	// reflect this cycle's results.  Setting it here (after all storeAndRecord
	// calls) ensures active is always a stable snapshot of a completed cycle,
	// never a transient partial view mid-renewal.
	rs.mu.Lock()
	rs.renewEpoch = cycleStart
	rs.mu.Unlock()

	// If either track is still short, queue 过程二 refill (may surface candidates
	// from routing-table updates not yet visible to this renewBackground run).
	directNeed, punchedNeed, _ := repSetTrackNeeds(rs)
	if directNeed > 0 || punchedNeed > 0 {
		n.enqueueReplication(rk, protocol.SignedRecord{})
	}
	active, finalSize := n.RepSetCounts(rk.storeKey, rk.publisher)
	n.log.Debug("replication status",
		"key", fmt.Sprintf("%x", rk.storeKey[:4]),
		"active", active,
		"replicas", finalSize,
		"target", nRep,
	)
}

// storeAndRecord sends STORE to peers one by one with storeStagger delay
// between launches and records confirmed stores into the repSet.
// Used by processReplTask and renewBackground.
//
// Rejection semantics:
//   - StoreReasonRecordInvalid: the record itself was rejected (e.g. expired
//     in the brief window between our validity check and the RPC).  The peer is
//     reachable and healthy; do NOT remove it from the repSet.
//   - StoreReasonPolicy: the peer permanently refuses this key/record.  Remove
//     it from the repSet so gap-fill can find a willing replacement.
//
// Probe schedule (nextProbeDelay/nextProbeAt) is owned exclusively by
// probeRepNode (过程三) so that the exponential back-off is not reset on
// every TTL renewal.
func (n *Node) storeAndRecord(ctx context.Context, peers []protocol.NodeInfo, rk repKey, rec protocol.SignedRecord, rs *repSet) {
	for i, ni := range peers {
		if ctx.Err() != nil {
			return
		}
		if i > 0 {
			t := time.NewTimer(storeStagger)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return
			}
		}

		var id a2al.NodeID
		copy(id[:], ni.NodeID)
		if id == n.nid {
			continue
		}
		// Global back-off gate: quick-reject when all address families are in
		// back-off.  lookupPeerHealthAware below enforces the same constraint
		// at the address level, but this check avoids the extra lock
		// acquisitions for peers that are clearly blocked.
		// StoreAt will call recordFailure/recordSuccess internally, so health
		// state is always updated regardless of the outcome.
		if !n.PeerAllowContact(id) {
			continue
		}
		// Select the dial address that is not in back-off.  If v4 is in
		// back-off, this returns stableV6 (if known); if neither family is
		// available, it returns false and we skip the peer.
		addr, ok := n.lookupPeerHealthAware(id)
		if !ok {
			continue
		}
		if n.learnedPathFirst.Load() {
			// warm=true for confirmed repSet members: prefer verified live over anchor.
			warm := n.repSetContains(rs, id)
			// Prefer v6 hint when the peer has a healthy v6 stable address.
			// lookupPeerHealthAware is v4-first; this restores v6 participation
			// for dual-stack peers on the L1 warm path without changing L0 semantics.
			// If v6 is in back-off or has no known address, hint stays as the v4 addr.
			hint := addr
			if v6hint, ok := n.lookupFamilyHealthAware(id, true); ok {
				hint = v6hint
			}
			n.maybeWaitRepSetPunch(ctx, id, rs, hint)
			if planAddr := n.outboundPlan(id, hint, warm).addr; planAddr != nil {
				addr = planAddr
			}
		}

		pctx, cancel := context.WithTimeout(ctx, queryPeerTimeout)
		stored, _, meta, reason, err := n.StoreAt(pctx, addr, rk.storeKey, rec)
		cancel()
		if err != nil {
			dial := meta.dialAddr
			if dial == nil {
				dial = addr
			}
			n.log.Debug("replication StoreAt failed",
				"peer", addr,
				"path", deliverPathLabel(meta),
				"dial", dial,
				"err", err,
			)
			// Warm-path anchor fallback: when a verified-live or lastInbound
			// path fails, retry once with the published anchor before giving up.
			// Skipped when the warm path already fell through to anchor (same addr).
			if meta.reason == "l1_warm_live" || meta.reason == "l1_warm_inbound" {
				v6, _ := addrIsV6(addr)
				if fallback := n.publicStableDialAddr(id, v6); fallback != nil && fallback.String() != addr.String() {
					pctx2, cancel2 := context.WithTimeout(ctx, queryPeerTimeout)
					stored, _, meta, reason, err = n.StoreAt(pctx2, fallback, rk.storeKey, rec)
					cancel2()
					if err != nil {
						fdial := meta.dialAddr
						if fdial == nil {
							fdial = fallback
						}
						n.log.Debug("replication StoreAt failed (anchor fallback)",
							"peer", fallback,
							"path", deliverPathLabel(meta),
							"dial", fdial,
							"err", err,
						)
					}
				}
			}
			if err != nil {
				continue
			}
		}
		if !stored {
			// The peer is reachable but rejected the record.  Classify by reason:
			//   RecordInvalid — the record itself was bad (peer is healthy).
			//     Do not remove from repSet; the concurrent fresh-record publish
			//     will succeed on the next renewal cycle.
			//   Policy (or unknown) — the peer permanently refuses this key.
			//     Remove from repSet so gap-fill can find a willing replacement.
			if reason == protocol.StoreReasonRecordInvalid {
				n.log.Debug("replication StoreAt rejected: record invalid, keeping in repSet", "peer", addr)
				continue
			}
			k := infoKey(ni)
			rs.mu.Lock()
			_, wasReplica := rs.nodes[k]
			if wasReplica {
				delete(rs.nodes, k)
			}
			rs.mu.Unlock()
			if wasReplica {
				n.log.Debug("replication StoreAt rejected: removed from repSet", "peer", addr)
			} else {
				n.log.Debug("replication StoreAt rejected", "peer", addr)
			}
			continue
		}
		n.log.Debug("replication StoreAt ok", "peer", addr)

		k := infoKey(ni)
		// Phase 7: check whether this peer is currently in the routing table
		// as a punched entry so repSet membership can be classified correctly.
		n.tabMu.RLock()
		punched := n.table.IsPunched(id)
		n.tabMu.RUnlock()

		now := time.Now()
		rs.mu.Lock()
		if e, exists := rs.nodes[k]; exists {
			// Renewal confirmed: update liveness state but leave probe schedule alone.
			e.confirmedAt = now
			e.confirmedSeq = rec.Seq
			e.failCount = 0
			e.badSince = time.Time{}
			e.isPunched = punched // refresh in case the node was promoted from punched
		} else {
			rs.nodes[k] = &repNodeEntry{
				nodeID:         id,
				confirmedAt:    now,
				confirmedSeq:   rec.Seq,
				nextProbeAt:    now.Add(probeInitDelay),
				nextProbeDelay: probeInitDelay,
				isPunched:      punched,
			}
		}
		// Phase 7: rebalance dual-set membership after each insertion/update.
		rebalanceRepSets(rs, rk.storeKey)
		rs.mu.Unlock()

		// Feed the confirmed-reachable peer back into the routing table.
		// Every successful STORE is evidence of reachability; absorbing it here
		// ensures the routing table reflects our actual communication outcomes
		// (§4.4: every DHT interaction refreshes the routing table).
		var tabNI protocol.NodeInfo
		tabNI.NodeID = append([]byte(nil), id[:]...)
		if ua, ok := addr.(*net.UDPAddr); ok {
			if ip4 := ua.IP.To4(); ip4 != nil {
				tabNI.IP = append([]byte(nil), ip4...)
			} else {
				tabNI.IP = append([]byte(nil), ua.IP.To16()...)
			}
			tabNI.Port = uint16(ua.Port)
		}
		n.tabAdd(tabNI, routing.EntryMeta{VerifiedAt: time.Now()}, addr)
	}
}

// repSetTrackNeeds returns remaining direct and punched slots (each targets nRep)
// and the active replica count.
//
// Both need values and the returned active count are derived exclusively from
// active replicas — those confirmed in the most recently completed
// renewBackground cycle (confirmedAt.After(renewEpoch)).  The hardcap guard
// in callers uses active, not the raw node count, so that stale entries from
// a prior cycle do not permanently block gap-fill.
//
// Before the first cycle completes (renewEpoch.IsZero()), all entries are
// counted, preventing an initial gap-fill from being suppressed.
func repSetTrackNeeds(rs *repSet) (directNeed, punchedNeed, active int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var direct, punched int
	epoch := rs.renewEpoch
	for _, e := range rs.nodes {
		if !epoch.IsZero() && !e.confirmedAt.After(epoch) {
			continue
		}
		if e.isPunched {
			punched++
		} else {
			direct++
		}
	}
	active = direct + punched
	if n := nRep - direct; n > 0 {
		directNeed = n
	}
	if n := nRep - punched; n > 0 {
		punchedNeed = n
	}
	return directNeed, punchedNeed, active
}

// pickGapFillPeers splits gap-fill candidates into direct and NAT (signal) tracks.
//
// Direct track: reachability first, no XOR gate. Fills directNeed unconditionally;
// when at capacity (directNeed=0) admits one extra candidate that is XOR-closer than
// the farthest punched member, enabling a recovered direct node to displace a worse
// punched entry without waiting for the next TTL renewal.
//
// NAT track: no XOR gate.  Fills punchedNeed candidates from xorPool (which is
// XOR-ascending, so nearest are tried first).  When the track is full
// (punchedNeed=0) it admits nothing: NAT quality converges over refill cycles
// via the nearest-first ordering, rather than via active ICE-punch displacement
// (which would be too costly for a mere distance swap).
func (n *Node) pickGapFillPeers(storeKey a2al.NodeID, rs *repSet, directPool, xorPool []protocol.NodeInfo, existing map[string]struct{}) (direct, nat []protocol.NodeInfo) {
	directNeed, punchedNeed, active := repSetTrackNeeds(rs)
	if active >= repHardCap || (directNeed <= 0 && punchedNeed <= 0) {
		return nil, nil
	}

	// Farthest punched member's XOR distance — for the direct quality-displacement
	// gate (admit a direct node closer than the worst punched member when the
	// direct track is full).
	var xorFarthestPunched a2al.NodeID
	hasXorFarthestPunched := false
	rs.mu.Lock()
	for _, e := range rs.nodes {
		if e.isPunched {
			d := xorNodeID(e.nodeID, storeKey)
			if !hasXorFarthestPunched || xorGT(d, xorFarthestPunched) {
				xorFarthestPunched, hasXorFarthestPunched = d, true
			}
		}
	}
	rs.mu.Unlock()
	qualitySlotUsed := false

	for _, ni := range directPool {
		if directNeed <= 0 && (!hasXorFarthestPunched || qualitySlotUsed) {
			break
		}
		k := infoKey(ni)
		if k == "" {
			continue
		}
		if _, ok := existing[k]; ok {
			continue
		}
		var id a2al.NodeID
		if len(ni.NodeID) != len(id) {
			continue
		}
		copy(id[:], ni.NodeID)
		if id == n.nid || !n.PeerAllowContact(id) {
			continue
		}
		if n.reachProfile(id).prefersICEOverColdUDP() {
			continue
		}
		if directNeed > 0 {
			direct = append(direct, ni)
			directNeed--
		} else if hasXorFarthestPunched && !qualitySlotUsed {
			d := xorNodeID(id, storeKey)
			if xorGT(xorFarthestPunched, d) {
				direct = append(direct, ni)
				qualitySlotUsed = true
			}
		}
	}

	punchBudget := gapFillPunchBudget
	for _, ni := range xorPool {
		if punchedNeed <= 0 {
			break
		}
		k := infoKey(ni)
		if k == "" {
			continue
		}
		if _, ok := existing[k]; ok {
			continue
		}
		var id a2al.NodeID
		if len(ni.NodeID) != len(id) {
			continue
		}
		copy(id[:], ni.NodeID)
		if id == n.nid {
			continue
		}
		if n.lookupEndpointRecord(id) == nil || n.reachProfile(id).prefersUDPAnchor() {
			continue
		}
		hasConn := n.punch != nil && n.punch.HasConn(id)
		if !hasConn {
			if punchBudget <= 0 {
				continue
			}
			punchBudget--
		}
		nat = append(nat, ni)
		punchedNeed--
	}
	return direct, nat
}

// gapFillStoreNAT punch-waits then reuses storeAndRecord per NAT candidate.
func (n *Node) gapFillStoreNAT(ctx context.Context, rk repKey, rec protocol.SignedRecord, rs *repSet, peers []protocol.NodeInfo) {
	if n.punch == nil || len(peers) == 0 {
		return
	}
	for i, ni := range peers {
		if ctx.Err() != nil {
			return
		}
		if i > 0 {
			t := time.NewTimer(storeStagger)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return
			}
		}
		var id a2al.NodeID
		if len(ni.NodeID) != len(id) {
			continue
		}
		copy(id[:], ni.NodeID)
		if !n.punch.HasConn(id) {
			if er := n.lookupEndpointRecord(id); er != nil {
				n.triggerPunchWithOptions(id, er, PunchPriorityHigh, true)
			}
			if !waitForHasConn(ctx, func() bool { return n.punch.HasConn(id) }, repSetPunchWait) {
				continue
			}
		}
		n.storeAndRecord(ctx, []protocol.NodeInfo{ni}, rk, rec, rs)
	}
}

// rebalanceRepSets recomputes XOR-set and direct-set membership for every
// entry in rs and removes nodes that belong to neither set (Phase 7).
//
// Semantics (§8.2 dual-set):
//
//	XOR set   = top-nRep nodes by XOR distance (punched + direct)
//	Direct set = top-nRep nodes by XOR distance among non-punched nodes only
//	Effective repSet = XOR set ∪ Direct set (max size 2×nRep = repHardCap)
//
// A node removed from one set is kept alive if it still belongs to the other.
// Only nodes in neither set are deleted from rs.nodes.
//
// Must be called with rs.mu held.
func rebalanceRepSets(rs *repSet, key a2al.NodeID) {
	if len(rs.nodes) == 0 {
		return
	}

	// Sort all entries by XOR distance (ascending = closer first).
	type entry struct {
		k    string
		e    *repNodeEntry
		dist a2al.NodeID
	}
	all := make([]entry, 0, len(rs.nodes))
	for k, e := range rs.nodes {
		all = append(all, entry{k: k, e: e, dist: xorNodeID(e.nodeID, key)})
	}
	sort.Slice(all, func(i, j int) bool {
		return !xorGT(all[i].dist, all[j].dist) && all[i].dist != all[j].dist
	})

	// Assign XOR-set membership: top-nRep regardless of isPunched.
	xorCount := 0
	for i := range all {
		if xorCount < nRep {
			all[i].e.inXorSet = true
			xorCount++
		} else {
			all[i].e.inXorSet = false
		}
	}

	// Assign direct-set membership: top-nRep among non-punched entries only.
	directCount := 0
	for i := range all {
		if all[i].e.isPunched {
			all[i].e.inDirectSet = false
			continue
		}
		if directCount < nRep {
			all[i].e.inDirectSet = true
			directCount++
		} else {
			all[i].e.inDirectSet = false
		}
	}

	// Remove entries that belong to neither set.
	for _, item := range all {
		if !item.e.inXorSet && !item.e.inDirectSet {
			delete(rs.nodes, item.k)
		}
	}
}

// repSetEnforceHardCap removes the XOR-farthest node when |repSet| > repHardCap.
// Kept as a safety net for legacy call sites; new code uses rebalanceRepSets.
// Must be called with rs.mu held.
func repSetEnforceHardCap(rs *repSet, key a2al.NodeID) {
	if len(rs.nodes) <= repHardCap {
		return
	}
	var farthestK string
	var farthestDist a2al.NodeID
	first := true
	for k, e := range rs.nodes {
		d := xorNodeID(e.nodeID, key)
		if first || xorGT(d, farthestDist) {
			farthestK = k
			farthestDist = d
			first = false
		}
	}
	if farthestK != "" {
		delete(rs.nodes, farthestK)
	}
}

// ─── 过程三: Health Probe ──────────────────────────────────────────────────────

// healthProbeLoop periodically PINGs each node in every repSet, advancing its
// exponential back-off probe schedule.  Bad nodes are given a 30-min grace
// window (probeBadDelay) before eviction; eviction triggers a refill via 过程二.
func (n *Node) healthProbeLoop(ctx context.Context) {
	defer n.wg.Done()
	ticker := time.NewTicker(probeTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.runHealthProbes(ctx)
			n.store.PruneExpiredOneShotSubs()
		}
	}
}

func (n *Node) runHealthProbes(ctx context.Context) {
	n.repMu.RLock()
	keys := make([]repKey, 0, len(n.repSets))
	for k := range n.repSets {
		keys = append(keys, k)
	}
	n.repMu.RUnlock()

	now := time.Now()
	// One RPC per nodeID per heartbeat: the same replica may appear in
	// multiple repSets (different storeKey/publisher pairs).
	probeCache := make(map[string]repProbeExecOutcome)
	for _, rk := range keys {
		if ctx.Err() != nil {
			return
		}
		n.repMu.RLock()
		rs := n.repSets[rk]
		n.repMu.RUnlock()
		if rs == nil {
			continue
		}
		rs.mu.Lock()
		var toProbe []*repNodeEntry
		for _, e := range rs.nodes {
			if now.After(e.nextProbeAt) {
				toProbe = append(toProbe, e)
			}
		}
		rs.mu.Unlock()

		for _, e := range toProbe {
			if ctx.Err() != nil {
				return
			}
			n.probeRepNode(ctx, rk, rs, e, probeCache)
		}
	}

	// Run routing table maintenance in the same heartbeat (no extra goroutine).
	n.runRoutingMaintenance(ctx)
}

// Per-cycle resource limits for the routing maintenance loop.
const (
	maintRefillPerCycle = 2 // max FindNode refill queries launched per heartbeat

	// hearsayProbeBucketThreshold is the minimum bucket index (CPL) at which a
	// newly absorbed hearsay node gets a single opportunistic PING.
	// Bucket ≥ 3 means the peer occupies ≤ 1/16 of the key space and is
	// routing-critical; one probe attempt is worthwhile to promote it quickly.
	hearsayProbeBucketThreshold = 3
)

// runRoutingMaintenance performs one pass of routing table upkeep:
// Launches at most maintRefillPerCycle background FindNode queries for
// under-filled buckets, prioritising higher-CPL (closer-to-self) buckets.
//
// Hearsay nodes are verified lazily: they gain VerifiedAt only through
// natural RPC traffic (StoreAt, FindNode responses) or the opportunistic
// single-probe fired by absorbNodeInfo for XOR-close nodes.
//
// Called by runHealthProbes every probeTickInterval (15 s).
func (n *Node) runRoutingMaintenance(ctx context.Context) {
	now := time.Now()
	freshCutoff := now.Add(-verifiedFreshWindow)

	n.tabMu.Lock()
	work := n.table.CollectMaintenanceWork(now, freshCutoff, freshCutoff)
	n.tabMu.Unlock()

	// Refill under-filled buckets — at most maintRefillPerCycle FindNode queries.
	// Sort descending by bucket index so higher-CPL (closer-to-self, routing-critical)
	// buckets are served first when the cap binds.
	//
	// Skipped in passive mode: passive node routing tables fill naturally
	// through incoming traffic; proactive FindNode is unnecessary and noisy.
	if !n.passiveRouting.Load() {
		refill := work.BucketsToRefill
		if len(refill) > 1 {
			sort.Sort(sort.Reverse(sort.IntSlice(refill)))
		}
		if len(refill) > maintRefillPerCycle {
			refill = refill[:maintRefillPerCycle]
		}
		for _, bi := range refill {
			if ctx.Err() != nil {
				return
			}
			target := randomIDInBucket(n.nid, bi)

			// Snapshot the bucket's discovery count (main + pending) before the
			// FindNode.  We compare it with the count after the goroutine
			// returns to decide whether the query actually brought in any new
			// peers — verifiedFreshCount would never reflect FindNode results
			// in time because those results enter as hearsay (VerifiedAt = 0).
			n.tabMu.RLock()
			beforeCount := n.table.BucketDiscoveryCount(bi)
			n.tabMu.RUnlock()

			go func(bucketIdx int, before int, t a2al.NodeID) {
				qctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				q := NewQuery(n)
				_, _ = q.FindNode(qctx, t)

				// Record whether the bucket grew so CollectMaintenanceWork can
				// adjust the futile-attempt counter and cooldown accordingly.
				n.tabMu.Lock()
				after := n.table.BucketDiscoveryCount(bucketIdx)
				n.table.RecordRefillOutcome(bucketIdx, after > before)
				n.tabMu.Unlock()
			}(bi, beforeCount, target)
		}
	}
}

// randomIDInBucket generates a random NodeID whose BucketIndex relative to self
// equals bi.  The first bi bits match self; bit bi is flipped; remaining bits
// are random.
func randomIDInBucket(self a2al.NodeID, bi int) a2al.NodeID {
	var id a2al.NodeID
	copy(id[:], self[:])

	// Flip bit bi (most-significant bit = 0).
	byteIdx := bi / 8
	bitIdx := uint(7 - (bi % 8))
	id[byteIdx] ^= 1 << bitIdx

	// Randomise all bits after position bi.
	startByte := byteIdx + 1
	if _, err := crand.Read(id[startByte:]); err == nil {
		// Also randomise the low bits of byteIdx (after bit bi).
		mask := byte((1 << bitIdx) - 1)
		if mask > 0 {
			var b [1]byte
			if _, err := crand.Read(b[:]); err == nil {
				id[byteIdx] = (id[byteIdx] &^ mask) | (b[0] & mask)
			}
		}
	}
	return id
}

// repProbeExecOutcome is the node-level result of one replication health probe
// RPC. Shared across repSets within a single runHealthProbes heartbeat.
type repProbeExecOutcome struct {
	iceConnOK      bool
	noAddr         bool
	probeSkip      bool
	punchAttempted bool
	err            error
}

// probeRepNode probes one replica node with PING, updating its probe schedule.
// probeCache deduplicates RPCs when the same nodeID is due in multiple repSets
// during one heartbeat.
//
// State machine (Fix 2):
//   Unknown/recovering:  failCount < badHealthThreshold → fast retry at probeInitDelay
//   Newly bad:           failCount reaches threshold → set badSince, schedule retry at
//                        probeBadDelay (30 min), proactively signal 过程二 to find a
//                        replacement while the bad node has its grace window.
//   Persistently bad:    badSince set AND probe fails again → evict, signal 过程二.
//   Recovery:            any success clears failCount and badSince; back-off advances.
//
// Fix 7: rs.mu is always released before calling enqueueReplication to avoid
// holding the lock while touching the channel.
func (n *Node) probeRepNode(ctx context.Context, rk repKey, rs *repSet, e *repNodeEntry, probeCache map[string]repProbeExecOutcome) {
	key := nodeIDKey(e.nodeID)
	out, ok := probeCache[key]
	if !ok {
		out = n.execRepProbe(ctx, e.nodeID)
		probeCache[key] = out
	}
	n.applyRepProbeOutcome(ctx, rk, rs, e, out)
}

// execRepProbe performs the node-level RPC for one replication health probe.
func (n *Node) execRepProbe(ctx context.Context, id a2al.NodeID) repProbeExecOutcome {
	var out repProbeExecOutcome

	// For ICE-capable NAT peers (signal URL present), consult the punch channel
	// before attempting a UDP probe — stale NAT-mapped ports always time out.
	if n.punch != nil {
		profile := n.reachProfile(id)
		er := n.lookupEndpointRecord(id)
		if er != nil && profile.prefersICEOverColdUDP() {
			if n.punch.HasConn(id) {
				n.log.Debug("replication probe: ice conn ok", "nodeID", id, "profile", profile)
				out.iceConnOK = true
				return out
			}
			// NAT/ICE-dependent peer: trigger ICE redialing and count this round as
			// a miss so the state machine advances (dead peers get evicted).
			n.triggerPunch(id, er, PunchPriorityHigh)
			n.log.Debug("replication probe: ice redial", "nodeID", id, "profile", profile)
			out.probeSkip = true
			out.punchAttempted = true
			return out
		}
	}

	// repSet probe uses the same warm candidate selection as renewal: prefer
	// recently-verified live paths over the published anchor so that probe and
	// StoreAt agree on which path is actually reachable.
	var (
		probeAddr net.Addr
		ok        bool
	)
	if plan := n.outboundPlan(id, nil, true /* warm: always a repSet member */); plan.addr != nil {
		probeAddr = plan.addr
		ok = true
	}
	if !ok {
		probeAddr, ok = n.lookupPeerHealthAware(id)
	}
	if !ok {
		probeAddr, ok = n.lookupPeer(id)
	}
	if !ok {
		n.log.Debug("replication probe: no dial addr", "nodeID", id)
		out.noAddr = true
		return out
	}

	pctx, cancel := context.WithTimeout(ctx, queryPeerTimeout)
	// n.log.Debug("replication probe: ping", "nodeID", id, "profile", profile, "addr", probeAddr, "ice_skip", out.probeSkip)
	_, err := n.PingIdentity(pctx, probeAddr)
	cancel()
	if err != nil {
		// PingIdentity called recordFailure internally (penalty++, backoff
		// extended).  Since this is a dedicated health probe — not a "real"
		// communication — undo the increment and halve the remaining back-off
		// instead of growing it, giving the node a chance to recover.
		n.recordProbeFailure(id, probeAddr)
	}
	out.err = err
	return out
}

// applyRepProbeOutcome updates one repSet entry from a shared probe result.
func (n *Node) applyRepProbeOutcome(ctx context.Context, rk repKey, rs *repSet, e *repNodeEntry, out repProbeExecOutcome) {
	if out.iceConnOK || (!out.probeSkip && !out.noAddr && out.err == nil) {
		// Success: advance the exponential back-off, clear bad state.
		rs.mu.Lock()
		e.failCount = 0
		e.badSince = time.Time{}
		next := e.nextProbeDelay * 2
		if next == 0 || next > probeMaxDelay {
			next = probeMaxDelay
		}
		e.nextProbeDelay = next
		e.nextProbeAt = time.Now().Add(next)
		rs.mu.Unlock()
		return
	}

	if out.noAddr {
		rs.mu.Lock()
		e.failCount++
		e.nextProbeAt = time.Now().Add(probeInitDelay)
		rs.mu.Unlock()
		return
	}

	// Failure path (UDP failure or punch-channel miss).
	rs.mu.Lock()

	// When network is suspected down, do not advance the repSet failure state
	// machine: healthy replicas must not be evicted for a local outage.
	// Schedule a fast retry so the probe fires again once connectivity returns.
	if n.suspectOffline() {
		e.nextProbeAt = time.Now().Add(probeInitDelay)
		rs.mu.Unlock()
		return
	}

	e.failCount++

	switch {
	case !e.badSince.IsZero():
		// Node was already marked bad; grace window has now elapsed and it still
		// fails → evict permanently.
		delete(rs.nodes, nodeIDKey(e.nodeID))
		rs.mu.Unlock()
		n.log.Debug("replication probe: node evicted after grace window", "nodeID", e.nodeID)
		n.enqueueReplication(rk, protocol.SignedRecord{})

	case e.failCount >= badHealthThreshold:
		// If the node was confirmed in the most recently completed renewal
		// cycle (confirmedAt.After(renewEpoch)), it was healthy just moments
		// ago.  Give it one extra fast-retry round before entering the 30-min
		// grace window: reset failCount to 1 so the next probe failure is the
		// first "real" strike.  This dampens false evictions during the brief
		// connectivity gap that follows a sleep/wake or network change event.
		//
		// The check is intentionally narrow: only nodes confirmed this cycle
		// benefit; stale entries that merely survived from earlier cycles do
		// not.  The grace window (badSince) is still entered on the very next
		// failure, so eviction is delayed by at most one probeInitDelay (30 s),
		// not indefinitely.
		if e.confirmedAt.After(rs.renewEpoch) {
			e.failCount = 1
			e.nextProbeAt = time.Now().Add(probeInitDelay)
			rs.mu.Unlock()
			n.log.Debug("replication probe: node bad deferred (recently confirmed)", "nodeID", e.nodeID)
			return
		}
		// Newly bad: enter 30-min grace window.
		e.badSince = time.Now()
		e.nextProbeAt = time.Now().Add(probeBadDelay)
		rs.mu.Unlock()
		n.log.Debug("replication probe: node bad, grace window started", "nodeID", e.nodeID)
		// Proactively look for a replacement while waiting.
		n.enqueueReplication(rk, protocol.SignedRecord{})
		// Phase 6 (过程三, Low priority): UDP has confirmed unreachable; try ICE.
		// Skip if already triggered above (triggerPunch deduplicates anyway, but
		// avoid the lock overhead).
		if !out.punchAttempted {
			if er := n.lookupEndpointRecord(e.nodeID); er != nil {
				n.triggerPunch(e.nodeID, er, PunchPriorityLow)
			}
		}

	default:
		// Still accumulating failures; fast retry.
		e.nextProbeAt = time.Now().Add(probeInitDelay)
		rs.mu.Unlock()
	}
}

// prefetchNATEndpoints fetches and caches endpoint records for candidates in
// xorPool that lack a locally-cached signal URL but are not known-public.
//
// Problem: pickGapFillPeers skips NAT candidates when lookupEndpointRecord
// returns nil — it cannot punch to a node with no signal URL.  Nodes may
// appear in xorPool (from FindNode traversal or tabNearest) without their
// endpoint records having been cached locally, especially if we have never
// called Resolve or connected to them.  Such nodes are classified ReachUnknown
// (no local evidence) and would never pass prefersICEOverColdUDP() even though
// they are prime candidates: they may be NAT-behind nodes whose records simply
// haven't been fetched yet.
//
// Filter logic (applied before any network query):
//
//  1. Skip known-public peers (prefersUDPAnchor) — they use UDP anchors, not ICE.
//  2. Skip nodes whose any cached endpoint record is already present
//     (lookupEndpointRecordAny != nil): either a signal URL was found on a
//     prior fetch (lookupEndpointRecord will return it), or we already know
//     there is no signal URL — either way another FindRecords adds nothing.
//  3. Negative cache (epPrefetchNeg): skip nodes whose recent FindRecords
//     failed, with two suppression tiers:
//       - ErrNoMatchingRecords (confirmed absent): probeBadDelay (30 min).
//         The network was queried and truly has no endpoint record; retrying
//         sooner is wasteful.
//       - Other error (timeout, network hiccup): exponential back-off from
//         probeInitDelay (30 s), doubling each consecutive failure, capped at
//         probeBadDelay.  A single transient failure retries within ~60 s;
//         persistent failures converge to the same 30-min window.
//     Entries are invalidated immediately when an endpoint record for the same
//     nodeID is written to the local store via any path (LocalStorePut), so a
//     node discovered through Resolve, Connect, or a push cannot remain
//     suppressed even if it was previously neg-cached.
//     Note: jobs not dispatched due to the overall fctx timeout are NOT
//     neg-cached — they were never attempted, so no inference can be drawn.
//
// On success FindRecords (P0 fix) writes results into the local store so that
// the immediately-following pickGapFillPeers call can find them.
//
// Concurrency is bounded to gapFillPunchBudget×2 goroutines.
func (n *Node) prefetchNATEndpoints(ctx context.Context, candidates []protocol.NodeInfo) {
	type work struct{ id a2al.NodeID }
	now := time.Now()
	var jobs []work
	for _, ni := range candidates {
		var id a2al.NodeID
		if len(ni.NodeID) != len(id) {
			continue
		}
		copy(id[:], ni.NodeID)
		if id == n.nid {
			continue
		}
		// Filter 1: known-public peers use stable UDP anchors; ICE is not needed.
		if n.reachProfile(id).prefersUDPAnchor() {
			continue
		}
		// Filter 2: any cached endpoint record means we already fetched and stored
		// the result (with or without a signal URL); no need to query again.
		if n.lookupEndpointRecordAny(id) != nil {
			continue
		}
		// Filter 3: negative cache — skip recently-failed lookups.
		n.epPrefetchNegMu.RLock()
		negEntry, neg := n.epPrefetchNeg[nodeIDKey(id)]
		n.epPrefetchNegMu.RUnlock()
		if neg && now.Before(negEntry.retryAt) {
			continue
		}
		jobs = append(jobs, work{id: id})
	}
	if len(jobs) == 0 {
		return
	}

	fctx, cancel := context.WithTimeout(ctx, natEndpointFetchTimeout)
	defer cancel()

	sem := make(chan struct{}, gapFillPunchBudget*2)
	var wg sync.WaitGroup
	for _, j := range jobs {
		select {
		case sem <- struct{}{}:
		case <-fctx.Done():
			// Remaining jobs were not dispatched due to the overall prefetch
			// timeout.  We do NOT write neg-cache entries for them: a timeout
			// reflects local budget pressure, not a confirmed absence of an
			// endpoint record on the network.  The next gap-fill cycle will
			// retry them normally.
			return
		}
		wg.Add(1)
		go func(nodeID a2al.NodeID) {
			defer func() {
				<-sem
				wg.Done()
			}()
			q := NewQuery(n)
			_, err := q.FindRecords(fctx, nodeID, protocol.RecTypeEndpoint)
			if err == nil {
				return
			}
			key := nodeIDKey(nodeID)
			writeNow := time.Now()

			n.epPrefetchNegMu.Lock()
			existing := n.epPrefetchNeg[key]

			var retryAt time.Time
			var nextFailCount int
			if errors.Is(err, ErrNoMatchingRecords) {
				// Confirmed absent: the iterative query traversed the network and
				// found no endpoint record.  Jump straight to the maximum suppression
				// window; pin failCount at cap so any subsequent transient failure
				// also stays at probeBadDelay without risking shift overflow.
				retryAt = writeNow.Add(probeBadDelay)
				nextFailCount = epPrefetchFailCountCap
			} else {
				// Transient failure (timeout, network error): exponential back-off
				// starting at probeInitDelay, doubling each failure, capped at
				// probeBadDelay.  After epPrefetchFailCountCap consecutive failures
				// the interval reaches probeBadDelay and stays there — same
				// long-term behaviour as before, but with faster recovery after a
				// single network hiccup.
				//
				// failCount is read from the zero-value entry on first failure
				// (nextFailCount = 0+1 = 1 → 60 s), which is intentional.
				nextFailCount = existing.failCount + 1
				if nextFailCount > epPrefetchFailCountCap {
					nextFailCount = epPrefetchFailCountCap
				}
				delay := probeInitDelay << nextFailCount
				if delay > probeBadDelay {
					delay = probeBadDelay
				}
				retryAt = writeNow.Add(delay)
			}
			n.epPrefetchNeg[key] = epPrefetchNegEntry{retryAt: retryAt, failCount: nextFailCount}

			// Evict expired entries to bound map growth over long sessions.
			for k, e := range n.epPrefetchNeg {
				if writeNow.After(e.retryAt) {
					delete(n.epPrefetchNeg, k)
				}
			}
			n.epPrefetchNegMu.Unlock()
		}(j.id)
	}
	wg.Wait()
}

// natEndpointFetchTimeout is the wall-clock budget for a prefetchNATEndpoints
// call.  Each FindRecords can take up to queryPeerTimeout per hop; 5 s gives
// one full iterative query round-trip time with a small margin.
const natEndpointFetchTimeout = 5 * time.Second

// ─── XOR distance helpers ────────────────────────────────────────────────────

func xorNodeID(a, b a2al.NodeID) a2al.NodeID {
	var d a2al.NodeID
	for i := range d {
		d[i] = a[i] ^ b[i]
	}
	return d
}

// xorGT reports whether XOR distance a is strictly greater than b
// (i.e. a is farther from the key than b).
func xorGT(a, b a2al.NodeID) bool {
	for i := range a {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return false
}
