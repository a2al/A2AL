// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package routing

import (
	"encoding/hex"
	"net"
	"sort"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// PingFunc probes whether a candidate entry is still alive (spec Step 5).
type PingFunc func(protocol.NodeInfo) bool

// Table is a 256-bucket Kademlia routing table (Phase 1: single LRU zone per bucket).
type Table struct {
	self a2al.NodeID
	ping PingFunc
	b    [256]bucket
}

// NewTable constructs an empty table for the local node. ping may be nil (treated as always true on eviction probe).
func NewTable(self a2al.NodeID, ping PingFunc) *Table {
	return &Table{self: self, ping: ping}
}

// Self returns the local NodeID.
func (t *Table) Self() a2al.NodeID { return t.self }

// Add inserts or refreshes a peer.  Returns false if the peer is self, invalid,
// or rejected (full bucket with a responsive LRU peer for direct contacts; added
// to the pending list for hearsay contacts).
//
// meta.VerifiedAt should be the current time for direct-contact entries; leave
// zero for nodes learned from third-party FIND_NODE responses.
// addedAt is passed through to the bucket entry so the routing layer does not
// need to call time.Now().
func (t *Table) Add(n protocol.NodeInfo, meta EntryMeta, addedAt time.Time) bool {
	if len(n.NodeID) != len(t.self) {
		return false
	}
	var peer a2al.NodeID
	copy(peer[:], n.NodeID)
	if peer == t.self {
		return false
	}
	bi := BucketIndex(t.self, peer)
	if bi < 0 {
		return false
	}
	return t.b[bi].addOrTouch(cloneNodeInfo(n), meta, addedAt, t.ping)
}

// UpdateVerifiedAt updates the VerifiedAt timestamp for an existing main-bucket
// entry.  Called by the dht layer after a successful outbound RPC.
// No-op if the node is not currently in the main bucket.
func (t *Table) UpdateVerifiedAt(id a2al.NodeID, verifiedAt time.Time) {
	bi := BucketIndex(t.self, id)
	if bi < 0 {
		return
	}
	t.b[bi].updateVerifiedAt(id, verifiedAt)
}

// GetEntryMeta returns the EntryMeta for a main-bucket entry.
// Returns false if the node is not in the main bucket.
func (t *Table) GetEntryMeta(id a2al.NodeID) (EntryMeta, bool) {
	bi := BucketIndex(t.self, id)
	if bi < 0 {
		return EntryMeta{}, false
	}
	i := t.b[bi].indexByID(id)
	if i < 0 {
		return EntryMeta{}, false
	}
	return t.b[bi].nodes[i].meta, true
}

// MarkPendingVerified attempts to promote a pending entry to the main bucket
// using meta (typically VerifiedAt=now after a successful PING).
// Returns true if the entry was moved; false if the main bucket is full
// (the entry remains in pending and the caller may retry after a slot opens).
func (t *Table) MarkPendingVerified(id a2al.NodeID, meta EntryMeta, addedAt time.Time) bool {
	bi := BucketIndex(t.self, id)
	if bi < 0 {
		return false
	}
	return t.b[bi].promotePending(id, meta, addedAt)
}

// MarkPendingFailed removes a pending entry (called after a failed PING).
func (t *Table) MarkPendingFailed(id a2al.NodeID) {
	bi := BucketIndex(t.self, id)
	if bi < 0 {
		return
	}
	t.b[bi].removePending(id)
}

func cloneNodeInfo(n protocol.NodeInfo) protocol.NodeInfo {
	return protocol.NodeInfo{
		Address: append([]byte(nil), n.Address...),
		NodeID:  append([]byte(nil), n.NodeID...),
		IP:      append([]byte(nil), n.IP...),
		Port:    n.Port,
	}
}

// Remove deletes a peer by NodeID if present.
func (t *Table) Remove(id a2al.NodeID) {
	for i := range t.b {
		t.b[i].remove(id)
	}
}

// NearestN returns up to n peers with smallest XOR distance to target
// (excluding self). Results sorted closest-first.  Includes all main-bucket
// entries regardless of verification status.
func (t *Table) NearestN(target a2al.NodeID, n int) []protocol.NodeInfo {
	if n <= 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []protocol.NodeInfo
	for i := range t.b {
		for _, entry := range t.b[i].nodes {
			node := entry.info
			if len(node.NodeID) != len(target) {
				continue
			}
			var nid a2al.NodeID
			copy(nid[:], node.NodeID)
			if nid == t.self {
				continue
			}
			key := string(node.NodeID)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, node)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		var ai, aj a2al.NodeID
		copy(ai[:], out[i].NodeID)
		copy(aj[:], out[j].NodeID)
		return LessXORDistance(ai, aj, target)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// NearestNVerified returns up to n main-bucket peers that have been directly
// verified (VerifiedAt != zero), sorted by freshness then XOR distance.
// Verified-Fresh entries (VerifiedAt.After(cutoff)) are returned before
// Verified-Stale entries.  Unverified (VerifiedAt.IsZero()) entries are excluded.
//
// cutoff is provided by the caller; the routing layer does not call time.Now().
func (t *Table) NearestNVerified(target a2al.NodeID, n int, cutoff time.Time) []protocol.NodeInfo {
	if n <= 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var fresh, stale []protocol.NodeInfo
	for i := range t.b {
		for _, entry := range t.b[i].nodes {
			if entry.meta.VerifiedAt.IsZero() {
				continue // unverified: skip
			}
			node := entry.info
			if len(node.NodeID) != len(target) {
				continue
			}
			var nid a2al.NodeID
			copy(nid[:], node.NodeID)
			if nid == t.self {
				continue
			}
			key := string(node.NodeID)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			if entry.meta.VerifiedAt.After(cutoff) {
				fresh = append(fresh, node)
			} else {
				stale = append(stale, node)
			}
		}
	}
	less := func(a, b protocol.NodeInfo) bool {
		var ai, bi a2al.NodeID
		copy(ai[:], a.NodeID)
		copy(bi[:], b.NodeID)
		return LessXORDistance(ai, bi, target)
	}
	sort.Slice(fresh, func(i, j int) bool { return less(fresh[i], fresh[j]) })
	sort.Slice(stale, func(i, j int) bool { return less(stale[i], stale[j]) })

	out := make([]protocol.NodeInfo, 0, len(fresh)+len(stale))
	out = append(out, fresh...)
	out = append(out, stale...)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// BucketIndexOf returns BucketIndex(t.self, peer).
func (t *Table) BucketIndexOf(peer a2al.NodeID) int {
	return BucketIndex(t.self, peer)
}

// AllPeers returns every distinct peer in the main bucket table (unordered). Excludes self.
func (t *Table) AllPeers() []protocol.NodeInfo {
	var out []protocol.NodeInfo
	seen := make(map[string]struct{})
	for bi := range t.b {
		for _, entry := range t.b[bi].nodes {
			node := entry.info
			if len(node.NodeID) != len(t.self) {
				continue
			}
			var nid a2al.NodeID
			copy(nid[:], node.NodeID)
			if nid == t.self {
				continue
			}
			key := string(node.NodeID)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, cloneNodeInfo(node))
		}
	}
	return out
}

// Len returns the total number of stored peers in main buckets.
func (t *Table) Len() int {
	c := 0
	for i := range t.b {
		c += len(t.b[i].nodes)
	}
	return c
}

// Contains reports whether id is present in any main bucket.
func (t *Table) Contains(id a2al.NodeID) bool {
	bi := BucketIndex(t.self, id)
	if bi < 0 {
		return false
	}
	return t.b[bi].indexByID(id) >= 0
}

// PeerBucketLen returns the number of entries in the main bucket for peer's CPL slot.
func (t *Table) PeerBucketLen(peer a2al.NodeID) int {
	bi := BucketIndex(t.self, peer)
	if bi < 0 {
		return 0
	}
	return len(t.b[bi].nodes)
}

// OldestInBucket returns the LRU entry in the main bucket that would hold peer.
func (t *Table) OldestInBucket(peer a2al.NodeID) (protocol.NodeInfo, bool) {
	bi := BucketIndex(t.self, peer)
	if bi < 0 || len(t.b[bi].nodes) == 0 {
		return protocol.NodeInfo{}, false
	}
	return t.b[bi].nodes[0].info, true
}

// PeerDebugRow is a JSON-friendly routing row (spec §3.6).
type PeerDebugRow struct {
	Bucket        int    `json:"bucket"`
	XORDistToSelf string `json:"xor_distance_to_self_hex"`
	AddressHex    string `json:"address_hex"`
	NodeIDHex     string `json:"node_id_hex"`
	IP            string `json:"ip"`
	Port          uint16 `json:"port"`
	VerifiedAgo   string `json:"verified_ago,omitempty"` // human-readable age of VerifiedAt; empty if unverified
}

// EstimatedNetworkSize estimates the total number of nodes using bucket density.
// For a bucket at CPL c with m nodes the estimate is m×2^(c+1).
// Includes all main-bucket entries (verified and unverified).
// For a freshness-filtered estimate with confidence, use EstimatedNetworkSizeFiltered.
func (t *Table) EstimatedNetworkSize() int {
	est, _ := t.EstimatedNetworkSizeFiltered(time.Time{}) // zero cutoff: count all non-zero VerifiedAt
	if est > 0 {
		return est
	}
	// Fallback: count all nodes (original behavior) if no verified nodes at all.
	for c := len(t.b) - 1; c >= 0; c-- {
		m := len(t.b[c].nodes)
		if m == 0 {
			continue
		}
		shift := c + 1
		if shift >= 62 {
			shift = 62
		}
		return m * (1 << shift)
	}
	return 0
}

// EstimatedNetworkSizeFiltered estimates network size using only fresh verified
// nodes (VerifiedAt.After(cutoff)).  It scans up to 5 non-empty verified buckets
// from the highest CPL downward, computes m_i × 2^(c_i+1) for each, and returns
// the median estimate together with a confidence score in [0, 1] where 1 means
// 5 or more valid sample buckets were available.
//
// cutoff is provided by the caller; pass time.Time{} to count all verified nodes
// regardless of age.
func (t *Table) EstimatedNetworkSizeFiltered(cutoff time.Time) (estimate int, confidence float64) {
	var estimates []int
	for c := len(t.b) - 1; c >= 0 && len(estimates) < 5; c-- {
		var m int
		for _, e := range t.b[c].nodes {
			if e.meta.VerifiedAt.IsZero() {
				continue
			}
			if !cutoff.IsZero() && !e.meta.VerifiedAt.After(cutoff) {
				continue
			}
			m++
		}
		if m == 0 {
			continue
		}
		shift := c + 1
		if shift >= 62 {
			shift = 62
		}
		estimates = append(estimates, m*(1<<shift))
	}
	if len(estimates) == 0 {
		return 0, 0
	}
	sort.Ints(estimates)
	mid := len(estimates) / 2
	estimate = estimates[mid]
	confidence = float64(len(estimates)) / 5.0
	return
}

// MaintenanceWork holds work items collected by CollectMaintenanceWork for the
// dht layer's routing maintenance loop.
type MaintenanceWork struct {
	// PendingToProbe contains nodes in pending lists that need a PING to be
	// verified and potentially promoted to the main bucket.
	PendingToProbe []protocol.NodeInfo

	// StaleToProbe contains main-bucket entries that have VerifiedAt.IsZero()
	// and have been in the table long enough to warrant a probe.
	StaleToProbe []protocol.NodeInfo

	// BucketsToRefill holds bucket indices where the number of Verified-Fresh
	// nodes is below K/2.  The dht layer should issue FindNode(random-in-bucket)
	// for each.
	BucketsToRefill []int
}

// CollectMaintenanceWork scans all buckets and returns work items for the
// routing maintenance loop.
//
//   - now: current time (used for pending expiry)
//   - freshCutoff: entries with VerifiedAt.After(freshCutoff) are "fresh"
//   - staleCutoff: unverified main-bucket entries added before staleCutoff need probing
//
// As a side effect this call expires pending entries older than pendingTTL.
func (t *Table) CollectMaintenanceWork(now, freshCutoff, staleCutoff time.Time) MaintenanceWork {
	var work MaintenanceWork
	for bi := range t.b {
		b := &t.b[bi]

		// Remove pending entries that have been waiting too long.
		b.expirePending(now)

		// Collect pending entries for PING.
		for _, pe := range b.pending {
			work.PendingToProbe = append(work.PendingToProbe, pe.info)
		}

		// Collect stale unverified main-bucket entries for PING.
		for _, e := range b.nodes {
			if e.meta.VerifiedAt.IsZero() && e.addedAt.Before(staleCutoff) {
				work.StaleToProbe = append(work.StaleToProbe, e.info)
			}
		}

		// Refill logic with outcome-aware back-off.
		//
		// State machine (all state lives in the bucket struct):
		//
		//   healthy   (verifiedFreshCount >= K/2):
		//     Mark refillWasHealthy=true.  No refill needed.
		//
		//   unhealthy (verifiedFreshCount < K/2) after being healthy:
		//     Reset futileCount to 0 (give a fresh attempt at normal cadence).
		//     This ensures back-off accumulated in a small-network phase never
		//     persists into a phase where the network has grown.
		//
		//   unhealthy, repeated misses:
		//     futileCount drives the cooldown via refillFutileCooldowns:
		//       0→30s  1→2min  2→10min  3+→15min
		//     futileCount is incremented by RecordRefillOutcome when the FindNode
		//     that was launched for this bucket did not improve verifiedFreshCount.
		if freshCount := b.verifiedFreshCount(freshCutoff); len(b.nodes) > 0 {
			if freshCount >= K/2 {
				// Bucket healthy: remember so the next decline gets a free reset.
				b.refillWasHealthy = true
			} else {
				if b.refillWasHealthy {
					// Healthy → Unhealthy transition: reset futile counter so the
					// first re-attempt fires at normal cadence (30 s).
					b.futileCount = 0
					b.refillWasHealthy = false
				}
				cooldown := refillFutileCooldown(b.futileCount)
				if now.Sub(b.lastRefillAt) >= cooldown {
					work.BucketsToRefill = append(work.BucketsToRefill, bi)
					b.lastRefillAt = now
					// futileCount is updated by RecordRefillOutcome after the
					// FindNode goroutine completes; we do not touch it here.
				}
			}
		}
	}
	return work
}

// DebugPeerRows returns a flat list of peers with bucket index and XOR distance.
// Caller must serialise table access if concurrent.
func (t *Table) DebugPeerRows() []PeerDebugRow {
	var out []PeerDebugRow
	now := time.Now()
	for bi := range t.b {
		for _, entry := range t.b[bi].nodes {
			node := entry.info
			var nid a2al.NodeID
			copy(nid[:], node.NodeID)
			if nid == t.self {
				continue
			}
			d := a2al.Distance(nid, t.self)
			row := PeerDebugRow{
				Bucket:        bi,
				XORDistToSelf: hex.EncodeToString(d[:]),
				AddressHex:    hex.EncodeToString(node.Address),
				NodeIDHex:     hex.EncodeToString(node.NodeID),
				IP:            formatIP(node.IP),
				Port:          node.Port,
			}
			if !entry.meta.VerifiedAt.IsZero() {
				row.VerifiedAgo = now.Sub(entry.meta.VerifiedAt).Round(time.Second).String()
			}
			out = append(out, row)
		}
	}
	return out
}

// refillFutileCooldown returns the minimum wait before the next refill attempt
// given the number of consecutive futile attempts so far.
func refillFutileCooldown(futileCount int) time.Duration {
	idx := futileCount
	if idx >= len(refillFutileCooldowns) {
		idx = len(refillFutileCooldowns) - 1
	}
	return refillFutileCooldowns[idx]
}

// BucketDiscoveryCount returns the total number of distinct peers known to
// bucket bi, counting both main-bucket entries (verified or stale) and
// pending-list entries (unverified hearsay awaiting a probe).
//
// This is the metric the dht layer uses before/after a refill FindNode to
// decide whether the query actually discovered new peers.  verifiedFreshCount
// would be the wrong choice here: FindNode results enter the table as hearsay
// (VerifiedAt = 0) via absorbNodeInfo, so they cannot influence
// verifiedFreshCount until a later PING promotes them — by which point the
// outcome record is long since written.
//
// Caller must hold the table lock.
func (t *Table) BucketDiscoveryCount(bi int) int {
	if bi < 0 || bi >= len(t.b) {
		return 0
	}
	return len(t.b[bi].nodes) + len(t.b[bi].pending)
}

// RecordRefillOutcome updates the futile-attempt counter for bucket bi based on
// whether a recent FindNode improved its verifiedFreshCount.
//   - improved=true:  reset futileCount to 0 (back to normal cadence)
//   - improved=false: increment futileCount (longer wait before next attempt)
//
// Called by the dht layer after a maintenance FindNode goroutine completes.
// Caller must hold the table write lock.
func (t *Table) RecordRefillOutcome(bi int, improved bool) {
	if bi < 0 || bi >= len(t.b) {
		return
	}
	b := &t.b[bi]
	if improved {
		b.futileCount = 0
	} else {
		b.futileCount++
	}
}

func formatIP(ip []byte) string {
	if len(ip) == 4 {
		return net.IPv4(ip[0], ip[1], ip[2], ip[3]).String()
	}
	if len(ip) == 16 {
		return net.IP(append([]byte(nil), ip...)).String()
	}
	return ""
}
