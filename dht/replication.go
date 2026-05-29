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
	mu       sync.Mutex
	storeKey a2al.NodeID
	rec      protocol.SignedRecord
	nodes    map[string]*repNodeEntry // nodeIDKey(id) → entry
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

// RepSetSize returns the number of confirmed remote replicas for a record
// identified by (storeKey, publisher).  Returns 0 if no repSet exists yet.
// The value is a point-in-time snapshot; it can change as renewBackground and
// probeRepNode run in the background.
func (n *Node) RepSetSize(storeKey, publisher a2al.NodeID) int {
	rk := repKey{storeKey: storeKey, publisher: publisher}
	n.repMu.RLock()
	rs := n.repSets[rk]
	n.repMu.RUnlock()
	if rs == nil {
		return 0
	}
	rs.mu.Lock()
	sz := len(rs.nodes)
	rs.mu.Unlock()
	return sz
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
	directNeed, punchedNeed, total := repSetTrackNeeds(rs)
	if total >= repHardCap || (directNeed <= 0 && punchedNeed <= 0) {
		return
	}

	directPool := n.tabNearestHealthy(task.rk.storeKey, repHardCap)
	xorPool := n.tabNearest(task.rk.storeKey, repHardCap)
	// Proactively fetch endpoint records for NAT candidates that are not yet
	// cached locally (same as in renewBackground).
	xorFar, hasXorFar := xorFarthestInRepSet(rs)
	n.prefetchNATEndpoints(ctx, task.rk.storeKey, hasXorFar, xorFar, xorPool)
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

	rs.mu.Lock()
	existingIDs := make([]a2al.NodeID, 0, len(rs.nodes))
	existing := make(map[string]struct{}, len(rs.nodes))
	// Snapshot confirmedAt so we can detect which renewals failed below.
	preRenewConfirmed := make(map[string]time.Time, len(rs.nodes))
	// Phase 6: collect bad repSet members for punch trigger after unlock.
	var badRepNodes []a2al.NodeID
	{
		now := time.Now()
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
			e.nextProbeAt = now
			badRepNodes = append(badRepNodes, e.nodeID) // Phase 6
			continue
		}
			existingIDs = append(existingIDs, e.nodeID)
		}
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

		// For nodes whose renewal just failed (confirmedAt unchanged), set
		// nextProbeAt = now so 过程三 detects failure within one tick (≤15 s)
		// instead of waiting up to probeMaxDelay (10 min) for the next scheduled
		// probe.
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
	xorFar, hasXorFar := xorFarthestInRepSet(rs)
	n.prefetchNATEndpoints(ctx, rk.storeKey, hasXorFar, xorFar, xorPool)
	direct, nat := n.pickGapFillPeers(rk.storeKey, rs, directPool, xorPool, existing)
	if len(direct) > 0 {
		n.storeAndRecord(ctx, direct, rk, rec, rs)
	}
	n.gapFillStoreNAT(ctx, rk, rec, rs, nat)

	// If either track is still short, queue 过程二 refill (may surface candidates
	// from routing-table updates not yet visible to this renewBackground run).
	directNeed, punchedNeed, _ := repSetTrackNeeds(rs)
	if directNeed > 0 || punchedNeed > 0 {
		n.enqueueReplication(rk, protocol.SignedRecord{})
	}
	rs.mu.Lock()
	finalSize := len(rs.nodes)
	rs.mu.Unlock()
	n.log.Debug("replication status",
		"key", fmt.Sprintf("%x", rk.storeKey[:4]),
		"replicas", finalSize,
		"target", nRep,
	)
}

// storeAndRecord sends STORE to peers one by one with storeStagger delay
// between launches and records confirmed stores into the repSet.
// Used by processReplTask and renewBackground.
//
// Fix 3: successful StoreAt only updates confirmedAt / failCount.
// The probe schedule (nextProbeDelay/nextProbeAt) is owned exclusively by
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
		if n.isHairpinAddr(addr) {
			continue
		}

		if n.learnedPathFirst.Load() {
			n.maybeWaitRepSetPunch(ctx, id, rs, addr)
			if planAddr := n.outboundPlan(id, addr).addr; planAddr != nil {
				addr = planAddr
			}
		}

		pctx, cancel := context.WithTimeout(ctx, queryPeerTimeout)
		stored, _, err := n.StoreAt(pctx, addr, rk.storeKey, rec)
		cancel()
		if err != nil {
			n.log.Debug("replication StoreAt failed", "peer", addr, "err", err)
			continue
		}
		if !stored {
			// The peer is reachable but its recordAuthPolicy rejected this
			// record (e.g. unsupported delegation type, policy mismatch).
			// This is a record-scoped signal: do not penalise the peer's
			// global health score.
			//
			// If the peer was already a confirmed replica (renewal path),
			// remove it from the repSet — it is no longer holding the record
			// and will not accept a re-store.  The stillNeed check at the end
			// of renewBackground will detect the resulting gap and queue a
			// processReplTask to find a replacement.
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

		rs.mu.Lock()
		if e, exists := rs.nodes[k]; exists {
			// Renewal confirmed: update liveness state but leave probe schedule alone.
			e.confirmedAt = time.Now()
			e.failCount = 0
			e.badSince = time.Time{}
			e.isPunched = punched // refresh in case the node was promoted from punched
		} else {
			rs.nodes[k] = &repNodeEntry{
				nodeID:         id,
				confirmedAt:    time.Now(),
				nextProbeAt:    time.Now().Add(probeInitDelay),
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

// repSetTrackNeeds returns remaining direct and punched slots (each targets nRep).
func repSetTrackNeeds(rs *repSet) (directNeed, punchedNeed, total int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var direct, punched int
	for _, e := range rs.nodes {
		if e.isPunched {
			punched++
		} else {
			direct++
		}
	}
	total = len(rs.nodes)
	if n := nRep - direct; n > 0 {
		directNeed = n
	}
	if n := nRep - punched; n > 0 {
		punchedNeed = n
	}
	return directNeed, punchedNeed, total
}

// pickGapFillPeers splits gap-fill candidates into direct and NAT (signal) tracks.
// Direct: reachability first, no XOR gate. NAT: XOR-near from xorPool, signal required.
func (n *Node) pickGapFillPeers(storeKey a2al.NodeID, rs *repSet, directPool, xorPool []protocol.NodeInfo, existing map[string]struct{}) (direct, nat []protocol.NodeInfo) {
	directNeed, punchedNeed, total := repSetTrackNeeds(rs)
	if total >= repHardCap || (directNeed <= 0 && punchedNeed <= 0) {
		return nil, nil
	}

	// Single pass: compute both the overall farthest XOR distance (NAT-track gate)
	// and the farthest punched member's distance (quality-displacement gate).
	//
	// NAT gate: only XOR-closer candidates are worth punching to.
	// NOTE: xorFarthestInRepSet performs the same computation for the prefetch
	// path.  The two are intentionally kept separate so pickGapFillPeers remains
	// self-contained; if this gate logic ever changes, update both sites.
	//
	// Quality-displacement: when the direct track is at capacity (directNeed=0)
	// but punched members exist, one direct candidate that is XOR-closer than
	// the farthest punched member is admitted.  rebalanceRepSets then recomputes
	// global XOR-set and direct-set membership and evicts the global-worst entry
	// (not necessarily that specific punched node).  This enables a recovered
	// direct node to re-enter the repSet without waiting for the next TTL renewal.
	var xorFarthest, xorFarthestPunched a2al.NodeID
	hasXorFarthest, hasXorFarthestPunched := false, false
	rs.mu.Lock()
	for _, e := range rs.nodes {
		d := xorNodeID(e.nodeID, storeKey)
		if !hasXorFarthest || xorGT(d, xorFarthest) {
			xorFarthest, hasXorFarthest = d, true
		}
		if e.isPunched && (!hasXorFarthestPunched || xorGT(d, xorFarthestPunched)) {
			xorFarthestPunched, hasXorFarthestPunched = d, true
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
		if hasXorFarthest {
			d := xorNodeID(id, storeKey)
			if !xorGT(xorFarthest, d) {
				continue
			}
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

	profile := n.reachProfile(id)
	var (
		probeAddr net.Addr
		ok        bool
	)
	if profile.prefersUDPAnchor() {
		v6 := false
		if a, has := n.lookupPeerHealthAware(id); has {
			if isV6, ok2 := addrIsV6(a); ok2 {
				v6 = isV6
			}
		}
		probeAddr = n.publicStableDialAddr(id, v6)
		ok = probeAddr != nil
	}
	if !ok {
		probeAddr, ok = n.lookupPeerHealthAware(id)
	}
	if !ok {
		probeAddr, ok = n.lookupPeer(id)
	}
	if !ok {
		n.log.Debug("replication probe: no dial addr", "nodeID", id, "profile", profile)
		out.noAddr = true
		return out
	}

	pctx, cancel := context.WithTimeout(ctx, queryPeerTimeout)
	n.log.Debug("replication probe: ping", "nodeID", id, "profile", profile, "addr", probeAddr, "ice_skip", out.probeSkip)
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
//  3. XOR gate: skip candidates that are farther than the current farthest
//     replica (same gate used by pickGapFillPeers).  Even if we retrieved
//     their endpoint record they would still be filtered out by the picker.
//  4. Negative cache (epPrefetchNeg): skip nodes whose recent FindRecords
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
func (n *Node) prefetchNATEndpoints(ctx context.Context, storeKey a2al.NodeID, hasXorFarthest bool, xorFarthest a2al.NodeID, candidates []protocol.NodeInfo) {
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
		// Filter 2: XOR gate — mirrors the same condition in pickGapFillPeers.
		// A node farther than our current farthest replica would not be selected
		// by the picker even if we retrieved its endpoint record.
		// Applied before the store and neg-cache lookups (both of which acquire
		// locks) because this check is a free computation.
		if hasXorFarthest {
			d := xorNodeID(id, storeKey)
			if !xorGT(xorFarthest, d) {
				continue
			}
		}
		// Filter 3: any cached endpoint record means we already fetched and stored
		// the result (with or without a signal URL); no need to query again.
		if n.lookupEndpointRecordAny(id) != nil {
			continue
		}
		// Filter 4: negative cache — skip recently-failed lookups.
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

// xorFarthestInRepSet returns the XOR distance (relative to rs.storeKey) of
// the farthest node currently in rs.  Used by prefetchNATEndpoints to apply
// the same XOR gate as pickGapFillPeers: there is no point fetching the
// endpoint record of a node that is farther than every existing replica.
func xorFarthestInRepSet(rs *repSet) (far a2al.NodeID, ok bool) {
	rs.mu.Lock()
	for _, e := range rs.nodes {
		d := xorNodeID(e.nodeID, rs.storeKey)
		if !ok || xorGT(d, far) {
			far = d
			ok = true
		}
	}
	rs.mu.Unlock()
	return
}

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
