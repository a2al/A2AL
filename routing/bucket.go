// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package routing

import (
	"bytes"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

const (
	K          = 16
	pendingCap = 5
	pendingTTL = 2 * time.Hour
)

// refillFutileCooldowns maps the number of consecutive futile FindNode attempts
// for a bucket to the minimum wait before the next attempt.
//
//	futileCount=0: normal cadence; first attempt is immediate after election
//	futileCount=1: one miss → wait 2 min before retrying
//	futileCount=2: two misses → wait 10 min
//	futileCount=3+: accept the network is sparse; back off to 15 min and stay there
//
// A "futile" attempt is one where the verifiedFreshCount did not improve after
// the FindNode completed.  The counter resets to zero when the bucket improves
// (via RecordRefillOutcome) or when a healthy→unhealthy transition occurs.
var refillFutileCooldowns = [...]time.Duration{
	30 * time.Second, // futileCount=0
	2 * time.Minute,  // futileCount=1
	10 * time.Minute, // futileCount=2
	15 * time.Minute, // futileCount=3+ (cap)
}

// EntryMeta holds routing-quality metadata for a routing table entry.
// Values are supplied by the dht layer; the routing layer only stores and
// reads them.  The routing layer never calls time.Now() directly.
type EntryMeta struct {
	// VerifiedAt is the last moment at which we had direct-contact evidence
	// for this node (inbound message or successful outbound RPC).
	// Zero value means the node has never been directly verified by us.
	VerifiedAt time.Time

	// LearnedFrom is the NodeID of the peer that told us about this node via a
	// FIND_NODE response.  Zero value means we discovered the node directly
	// (i.e., it contacted us or we contacted it successfully).
	LearnedFrom a2al.NodeID
}

// bucketEntry is the internal representation of one routing table slot.
type bucketEntry struct {
	info    protocol.NodeInfo
	meta    EntryMeta
	addedAt time.Time // when this entry was first created in the table
}

// pendingEntry holds a hearsay node that is waiting to be verified before
// being admitted to the main K-bucket.
type pendingEntry struct {
	info        protocol.NodeInfo
	learnedFrom a2al.NodeID
	arrivedAt   time.Time
}

type bucket struct {
	nodes   []bucketEntry  // main K-bucket; oldest (LRU) at [0], MRU at [len-1]
	pending []pendingEntry // hearsay nodes awaiting verification; capacity pendingCap

	// Refill back-off state.  All fields are managed exclusively by
	// CollectMaintenanceWork and RecordRefillOutcome; nothing else should write them.
	lastRefillAt     time.Time
	refillWasHealthy bool // true when bucket was last seen with verifiedFreshCount >= K/2
	futileCount      int  // consecutive FindNode attempts that yielded no improvement
}

func (b *bucket) indexByID(id a2al.NodeID) int {
	for i, e := range b.nodes {
		if len(e.info.NodeID) == len(id) && bytes.Equal(e.info.NodeID, id[:]) {
			return i
		}
	}
	return -1
}

func (b *bucket) pendingIndexByID(id a2al.NodeID) int {
	for i, e := range b.pending {
		if len(e.info.NodeID) == len(id) && bytes.Equal(e.info.NodeID, id[:]) {
			return i
		}
	}
	return -1
}

// addOrTouch inserts or refreshes an entry.
//
// If the entry already exists in the main bucket it is moved to MRU.
// For direct-contact entries (!meta.VerifiedAt.IsZero()), the stored IP:Port
// is also refreshed and VerifiedAt is updated if the new value is newer.
//
// If the bucket is full:
//   - hearsay (meta.VerifiedAt.IsZero()): node is added to the pending list
//     (FIFO; drops oldest when at capacity).  Returns false.
//   - direct contact: ping is called on the LRU entry.  If it responds,
//     the newcomer is dropped; if not, LRU is evicted and the newcomer admitted.
//     Returns true only if the node was admitted.
//
// addedAt is provided by the caller so the routing layer never calls time.Now().
func (b *bucket) addOrTouch(n protocol.NodeInfo, meta EntryMeta, addedAt time.Time, ping PingFunc) bool {
	var nid a2al.NodeID
	if len(n.NodeID) != len(nid) {
		return false
	}
	copy(nid[:], n.NodeID)

	// Already in main bucket: touch (move to MRU) and update meta.
	if i := b.indexByID(nid); i >= 0 {
		// Update VerifiedAt only if the new timestamp is strictly newer.
		if !meta.VerifiedAt.IsZero() && meta.VerifiedAt.After(b.nodes[i].meta.VerifiedAt) {
			b.nodes[i].meta.VerifiedAt = meta.VerifiedAt
		}
		// Only update IP:Port from direct contact to prevent hearsay from
		// overwriting a verified address with potentially stale third-party data.
		if !meta.VerifiedAt.IsZero() && len(n.IP) > 0 && n.Port != 0 {
			b.nodes[i].info.IP = append([]byte(nil), n.IP...)
			b.nodes[i].info.Port = n.Port
		}
		b.touch(i)
		return true
	}

	// Bucket has space: insert directly.
	if len(b.nodes) < K {
		b.nodes = append(b.nodes, bucketEntry{info: n, meta: meta, addedAt: addedAt})
		return true
	}

	// Bucket is full.
	if meta.VerifiedAt.IsZero() {
		// Hearsay: never trigger LRU eviction.  Use the pending list instead.
		b.addToPending(n, meta.LearnedFrom, addedAt)
		return false
	}

	// Direct contact: give LRU node a chance to respond.
	oldest := b.nodes[0]
	if ping == nil || ping(oldest.info) {
		// LRU is alive (or no ping func): keep it, drop the newcomer.
		return false
	}
	// LRU silent: evict it, insert newcomer.
	copy(b.nodes[0:], b.nodes[1:])
	b.nodes = b.nodes[:len(b.nodes)-1]
	b.nodes = append(b.nodes, bucketEntry{info: n, meta: meta, addedAt: addedAt})
	return true
}

// addToPending adds n to the pending list.  If the list is already at
// pendingCap, the oldest entry is dropped (FIFO).  Duplicate NodeIDs are
// silently ignored.
func (b *bucket) addToPending(n protocol.NodeInfo, learnedFrom a2al.NodeID, now time.Time) {
	var nid a2al.NodeID
	if len(n.NodeID) == len(nid) {
		copy(nid[:], n.NodeID)
	}
	if b.pendingIndexByID(nid) >= 0 {
		return // already queued
	}
	if len(b.pending) >= pendingCap {
		// FIFO: discard oldest
		copy(b.pending[0:], b.pending[1:])
		b.pending = b.pending[:len(b.pending)-1]
	}
	b.pending = append(b.pending, pendingEntry{info: n, learnedFrom: learnedFrom, arrivedAt: now})
}

// touch moves entry i to the MRU position (end of slice).
func (b *bucket) touch(i int) {
	if i < 0 || i >= len(b.nodes) {
		return
	}
	e := b.nodes[i]
	copy(b.nodes[i:], b.nodes[i+1:])
	b.nodes[len(b.nodes)-1] = e
}

// remove deletes the entry with the given NodeID from the main bucket.
func (b *bucket) remove(id a2al.NodeID) bool {
	i := b.indexByID(id)
	if i < 0 {
		return false
	}
	copy(b.nodes[i:], b.nodes[i+1:])
	b.nodes = b.nodes[:len(b.nodes)-1]
	return true
}

// updateVerifiedAt updates the VerifiedAt timestamp for an existing main-bucket
// entry if the new timestamp is strictly newer.
func (b *bucket) updateVerifiedAt(id a2al.NodeID, t time.Time) {
	i := b.indexByID(id)
	if i < 0 {
		return
	}
	if t.After(b.nodes[i].meta.VerifiedAt) {
		b.nodes[i].meta.VerifiedAt = t
	}
}

// expirePending removes pending entries whose arrivedAt is older than pendingTTL.
func (b *bucket) expirePending(now time.Time) {
	cutoff := now.Add(-pendingTTL)
	out := b.pending[:0]
	for _, e := range b.pending {
		if e.arrivedAt.After(cutoff) {
			out = append(out, e)
		}
	}
	b.pending = out
}

// removePending removes the pending entry with the given NodeID (e.g. after a
// failed PING).
func (b *bucket) removePending(id a2al.NodeID) bool {
	i := b.pendingIndexByID(id)
	if i < 0 {
		return false
	}
	copy(b.pending[i:], b.pending[i+1:])
	b.pending = b.pending[:len(b.pending)-1]
	return true
}

// promotePending moves the pending entry with id into the main bucket using the
// supplied meta (typically VerifiedAt = time.Now() after a successful PING).
// Returns false if the main bucket is full (caller should retry later).
func (b *bucket) promotePending(id a2al.NodeID, meta EntryMeta, addedAt time.Time) bool {
	i := b.pendingIndexByID(id)
	if i < 0 {
		return false
	}
	if len(b.nodes) >= K {
		// No space yet; leave entry in pending so the next maintenance cycle
		// can retry after a slot opens up.
		return false
	}
	pe := b.pending[i]
	copy(b.pending[i:], b.pending[i+1:])
	b.pending = b.pending[:len(b.pending)-1]
	b.nodes = append(b.nodes, bucketEntry{info: pe.info, meta: meta, addedAt: addedAt})
	return true
}

// verifiedFreshCount returns the number of main-bucket entries whose VerifiedAt
// is strictly after cutoff.
func (b *bucket) verifiedFreshCount(cutoff time.Time) int {
	n := 0
	for _, e := range b.nodes {
		if e.meta.VerifiedAt.After(cutoff) {
			n++
		}
	}
	return n
}
