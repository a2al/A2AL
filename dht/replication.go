// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	crand "crypto/rand"
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
	probeTickInterval = 15 * time.Second // health probe loop wake-up interval
	replChBuf         = 64              // replication task channel buffer
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

// processReplTask fills any gap in a repSet (|nodes| < N_rep) by selecting
// candidates from the routing table and performing staggered StoreAt RPCs.
// Used for refill after bad-node removal (过程三) and for new-record seeding
// (before renewBackground has run FindNode).
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
	need := nRep - len(rs.nodes)
	rs.mu.Unlock()

	if len(rec.Address) == 0 || need <= 0 {
		return
	}

	candidates := n.tabNearestHealthy(task.rk.storeKey, repHardCap)
	var filtered []protocol.NodeInfo
	for _, ni := range candidates {
		k := infoKey(ni)
		if k == "" {
			continue
		}
		if _, inSet := existing[k]; inSet {
			continue
		}
		var id a2al.NodeID
		copy(id[:], ni.NodeID)
		if !n.PeerAllowContact(id) {
			continue
		}
		filtered = append(filtered, ni)
	}
	if len(filtered) > need {
		filtered = filtered[:need]
	}
	if len(filtered) == 0 {
		return
	}
	n.storeAndRecord(ctx, filtered, task.rk, rec, rs)
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
			found = n.tabNearestHealthy(rk.storeKey, repHardCap)
		}
	}

	rs.mu.Lock()
	existingIDs := make([]a2al.NodeID, 0, len(rs.nodes))
	existing := make(map[string]struct{}, len(rs.nodes))
	// Snapshot confirmedAt so we can detect which renewals failed below.
	preRenewConfirmed := make(map[string]time.Time, len(rs.nodes))
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
			continue
		}
			existingIDs = append(existingIDs, e.nodeID)
		}
	}
	rs.mu.Unlock()

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

	// Build the newPeers candidate list from FindNode results.
	//
	// When the repSet is already at N_rep we still want topology refresh: try
	// nodes that are XOR-closer than the current farthest repSet member.  This
	// preserves the strategy invariant (store at the N_rep XOR-closest reachable
	// nodes) without exhausting the full FindNode list indiscriminately.
	//
	// In both cases we skip known-Bad peers to avoid wasting 2 s timeouts on
	// nodes the health system has already flagged as unreachable.
	rs.mu.Lock()
	currentSize := len(rs.nodes)
	// Compute the farthest XOR distance currently in the repSet (used when full).
	var farthestDist a2al.NodeID
	hasFarthest := false
	if currentSize >= nRep {
		for _, e := range rs.nodes {
			d := xorNodeID(e.nodeID, rk.storeKey)
			if !hasFarthest || xorGT(d, farthestDist) {
				farthestDist = d
				hasFarthest = true
			}
		}
	}
	availableSlots := repHardCap - currentSize
	rs.mu.Unlock()

	if len(found) > 0 && availableSlots > 0 {
		var newPeers []protocol.NodeInfo
		for _, ni := range found {
			k := infoKey(ni)
			if k == "" {
				continue
			}
			if _, inSet := existing[k]; inSet {
				continue // already a confirmed replica
			}
		var id a2al.NodeID
		copy(id[:], ni.NodeID)
		if !n.PeerAllowContact(id) {
			continue
		}
			if hasFarthest {
				// repSet is full: only try peers closer than our farthest member.
				d := xorNodeID(id, rk.storeKey)
				if !xorGT(farthestDist, d) {
					// d >= farthestDist: this peer is not closer; skip.
					continue
				}
			}
			newPeers = append(newPeers, ni)
		}
		// Respect the hard cap on total attempts.
		if len(newPeers) > availableSlots {
			newPeers = newPeers[:availableSlots]
		}
		if len(newPeers) > 0 {
			n.storeAndRecord(ctx, newPeers, rk, rec, rs)
		}
	}

	// If still below N_rep after all attempts, queue a processReplTask refill.
	// processReplTask uses tabNearestHealthy which may surface candidates not
	// returned by FindNode (e.g. recently-discovered Good peers).
	rs.mu.Lock()
	stillNeed := nRep - len(rs.nodes)
	rs.mu.Unlock()
	if stillNeed > 0 {
		n.enqueueReplication(rk, protocol.SignedRecord{})
	}
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
		// Global back-off gate: skip peers whose retry window has not expired.
		// StoreAt will call recordFailure/recordSuccess internally, so health
		// state is always updated regardless of the outcome.
		if !n.PeerAllowContact(id) {
			continue
		}
		addr, ok := n.lookupPeer(id)
		if !ok {
			continue
		}
		if n.isHairpinAddr(addr) {
			continue
		}

		pctx, cancel := context.WithTimeout(ctx, queryPeerTimeout)
		_, err := n.StoreAt(pctx, addr, rk.storeKey, rec)
		cancel()
		if err != nil {
			n.log.Debug("replication StoreAt failed", "peer", addr, "err", err)
			continue
		}
		n.log.Debug("replication StoreAt ok", "peer", addr)

		k := infoKey(ni)
		rs.mu.Lock()
		if e, exists := rs.nodes[k]; exists {
			// Renewal confirmed: update liveness state but leave probe schedule alone.
			e.confirmedAt = time.Now()
			e.failCount = 0
			e.badSince = time.Time{}
		} else {
			rs.nodes[k] = &repNodeEntry{
				nodeID:         id,
				confirmedAt:    time.Now(),
				nextProbeAt:    time.Now().Add(probeInitDelay),
				nextProbeDelay: probeInitDelay,
			}
		}
		repSetEnforceHardCap(rs, rk.storeKey)
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
		n.tabAdd(tabNI, routing.EntryMeta{VerifiedAt: time.Now()})
	}
}

// repSetEnforceHardCap removes the XOR-farthest node when |repSet| > repHardCap.
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
			n.probeRepNode(ctx, rk, rs, e)
		}
	}

	// Run routing table maintenance in the same heartbeat (no extra goroutine).
	n.runRoutingMaintenance(ctx)
}

// Per-cycle resource limits for the routing maintenance loop.
// The loop fires every probeTickInterval (15 s); these caps bound the total
// PING time per cycle to roughly:
//   max = (maintPendingPerCycle + maintStalePerCycle) × 3 s = 45 s
// In practice most PINGs complete in < 100 ms (LAN/good-WAN), so a typical
// cycle finishes well within the 15 s tick.  Nodes not probed this cycle
// remain in pending/main and will be re-evaluated next cycle.
const (
	maintPendingPerCycle = 5  // max pending-list PINGs per heartbeat
	maintStalePerCycle   = 10 // max stale-unverified main-bucket PINGs per heartbeat
	maintRefillPerCycle  = 2  // max FindNode refill queries launched per heartbeat
)

// runRoutingMaintenance performs one pass of routing table upkeep:
//  1. PINGs a capped batch of pending-list nodes; promotes successful ones.
//  2. PINGs a capped batch of stale unverified main-bucket nodes; removes failures.
//  3. Launches at most maintRefillPerCycle background FindNode queries for
//     under-filled buckets, prioritising higher-CPL (closer-to-self) buckets.
//
// Called by runHealthProbes every probeTickInterval (15 s).
// All three steps are strictly rate-limited to prevent blocking repSet probing
// and to avoid sending a FindNode storm during startup or after large network churn.
func (n *Node) runRoutingMaintenance(ctx context.Context) {
	now := time.Now()
	freshCutoff := now.Add(-verifiedFreshWindow)
	staleCutoff := now.Add(-verifiedFreshWindow) // same threshold: 30 min unverified → probe

	n.tabMu.Lock()
	work := n.table.CollectMaintenanceWork(now, freshCutoff, staleCutoff)
	n.tabMu.Unlock()

	// 1. PING pending entries — at most maintPendingPerCycle per heartbeat.
	// Remainder stays in the pending list and is retried next cycle.
	pending := work.PendingToProbe
	if len(pending) > maintPendingPerCycle {
		pending = pending[:maintPendingPerCycle]
	}
	for _, ni := range pending {
		if ctx.Err() != nil {
			return
		}
		var id a2al.NodeID
		if len(ni.NodeID) != len(id) {
			continue
		}
		copy(id[:], ni.NodeID)
		addr, ok := n.lookupPeer(id)
		if !ok {
			// No dial address yet: try to use the IP:Port from NodeInfo.
			if len(ni.IP) > 0 && ni.Port != 0 {
				addr = &net.UDPAddr{IP: append([]byte(nil), ni.IP...), Port: int(ni.Port)}
				n.BindPeerAddr(id, addr)
			} else {
				n.tabMu.Lock()
				n.table.MarkPendingFailed(id)
				n.tabMu.Unlock()
				continue
			}
		}
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, err := n.PingIdentity(pctx, addr)
		cancel()
		if err == nil {
			// PingIdentity → recordSuccess → UpdateVerifiedAt already ran.
			// Now move the entry from pending to the main bucket.
			n.tabMu.Lock()
			n.table.MarkPendingVerified(id, routing.EntryMeta{VerifiedAt: time.Now()}, time.Now())
			n.tabMu.Unlock()
		} else {
			// Probe failure: undo the failCount++ that PingIdentity's recordFailure
			// applied.  Pending nodes have no prior communication history; their
			// failure must not push them into PeerHealthBad.
			n.recordProbeFailure(id)
			n.tabMu.Lock()
			n.table.MarkPendingFailed(id)
			n.tabMu.Unlock()
		}
	}

	// 2. PING stale unverified main-bucket entries — at most maintStalePerCycle.
	stale := work.StaleToProbe
	if len(stale) > maintStalePerCycle {
		stale = stale[:maintStalePerCycle]
	}
	for _, ni := range stale {
		if ctx.Err() != nil {
			return
		}
		var id a2al.NodeID
		if len(ni.NodeID) != len(id) {
			continue
		}
		copy(id[:], ni.NodeID)
		addr, ok := n.lookupPeer(id)
		if !ok {
			if len(ni.IP) > 0 && ni.Port != 0 {
				addr = &net.UDPAddr{IP: append([]byte(nil), ni.IP...), Port: int(ni.Port)}
				n.BindPeerAddr(id, addr)
			} else {
				// No address available: treat as failed, remove from main bucket.
				n.tabMu.Lock()
				n.table.Remove(id)
				n.tabMu.Unlock()
				continue
			}
		}
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, err := n.PingIdentity(pctx, addr)
		cancel()
		if err != nil {
			// Probe failure: undo failCount increment (same reasoning as pending).
			n.recordProbeFailure(id)
			n.tabMu.Lock()
			n.table.Remove(id)
			n.tabMu.Unlock()
		}
		// Success: PingIdentity → recordSuccess → UpdateVerifiedAt handled it.
	}

	// 3. Refill under-filled buckets — at most maintRefillPerCycle FindNode queries.
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

// probeRepNode probes one replica node with PING, updating its probe schedule.
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
func (n *Node) probeRepNode(ctx context.Context, rk repKey, rs *repSet, e *repNodeEntry) {
	addr, ok := n.lookupPeer(e.nodeID)
	if !ok {
		// Address unknown: count as a miss and retry soon.
		rs.mu.Lock()
		e.failCount++
		e.nextProbeAt = time.Now().Add(probeInitDelay)
		rs.mu.Unlock()
		return
	}

	pctx, cancel := context.WithTimeout(ctx, queryPeerTimeout)
	_, err := n.PingIdentity(pctx, addr)
	cancel()

	if err != nil {
		// PingIdentity called recordFailure internally (penalty++, backoff
		// extended).  Since this is a dedicated health probe — not a "real"
		// communication — undo the increment and halve the remaining back-off
		// instead of growing it, giving the node a chance to recover.
		n.recordProbeFailure(e.nodeID)
	}

	if err == nil {
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

	// Failure path.
	rs.mu.Lock()
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

	default:
		// Still accumulating failures; fast retry.
		e.nextProbeAt = time.Now().Add(probeInitDelay)
		rs.mu.Unlock()
	}
}

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
