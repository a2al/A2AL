// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"errors"
	"net"
	"sort"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)

const (
	DefaultAlpha = 3

	// DefaultStagger is the inter-launch delay between successive RPCs within
	// a single query batch (spec §3.2 "交错发射").  A peer that responds
	// within this window prevents the next candidate from being contacted,
	// saving bandwidth and avoiding unnecessary pressure on slow peers.
	// Phase 1 fixed value; future versions derive from RTT median × 0.5.
	DefaultStagger = 200 * time.Millisecond

	// queryPeerTimeout is the per-peer deadline inside iterative queries.
	// UDP responses from reachable peers typically arrive in <200ms even across
	// continents. 2s gives 10× margin.
	queryPeerTimeout = 2 * time.Second
)

// Query runs iterative FIND_NODE / FIND_VALUE (spec Step 8).
type Query struct {
	n       *Node
	Alpha   int
	Stagger time.Duration
}

// NewQuery builds a querier with default α=3 and small stagger between parallel RPCs.
func NewQuery(n *Node) *Query {
	if n == nil {
		return nil
	}
	return &Query{n: n, Alpha: DefaultAlpha, Stagger: DefaultStagger}
}

func infoKey(ni protocol.NodeInfo) string {
	if len(ni.NodeID) != len(a2al.NodeID{}) {
		return ""
	}
	return string(ni.NodeID)
}

func cloneNI(ni protocol.NodeInfo) protocol.NodeInfo {
	return protocol.NodeInfo{
		Address: append([]byte(nil), ni.Address...),
		NodeID:  append([]byte(nil), ni.NodeID...),
		IP:      append([]byte(nil), ni.IP...),
		Port:    ni.Port,
	}
}

func sortedByDistance(c map[string]protocol.NodeInfo, target a2al.NodeID) []protocol.NodeInfo {
	out := make([]protocol.NodeInfo, 0, len(c))
	for _, ni := range c {
		out = append(out, ni)
	}
	sort.Slice(out, func(i, j int) bool {
		var ai, aj a2al.NodeID
		copy(ai[:], out[i].NodeID)
		copy(aj[:], out[j].NodeID)
		return routing.LessXORDistance(ai, aj, target)
	})
	return out
}

func (q *Query) alpha() int {
	if q.Alpha <= 0 {
		return DefaultAlpha
	}
	return q.Alpha
}

func (q *Query) stagger() time.Duration {
	if q.Stagger < 0 {
		return 0
	}
	return q.Stagger
}

// FindNode runs iterative FIND_NODE until k-closest known nodes are exhausted or all have been queried.
// Candidates are seeded from tabNearestHealthy (Good peers first).  Within each
// batch, peers known to be Bad are skipped (tried last as fallback).  The
// collection loop returns as soon as the first peer responds, allowing the
// next round to start without waiting for slow/unreachable peers.
func (q *Query) FindNode(ctx context.Context, target a2al.NodeID) ([]protocol.NodeInfo, error) {
	if q.n == nil {
		return nil, errors.New("dht: nil node")
	}
	alpha := q.alpha()
	stagger := q.stagger()

	candidates := make(map[string]protocol.NodeInfo)
	queried := make(map[string]struct{})

	for _, ni := range q.n.tabNearestHealthy(target, routing.K) {
		if k := infoKey(ni); k != "" {
			candidates[k] = cloneNI(ni)
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		list := sortedByDistance(candidates, target)
		if len(list) == 0 {
			break
		}
		kClosest := list
		if len(kClosest) > routing.K {
			kClosest = kClosest[:routing.K]
		}

		allDone := true
		for _, ni := range kClosest {
			if _, ok := queried[infoKey(ni)]; !ok {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}

		batch := q.buildBatch(kClosest, queried, alpha)
		if len(batch) == 0 {
			break
		}

		// Launch with stagger; ch is buffered so goroutines never block.
		ch := make(chan []protocol.NodeInfo, len(batch))
		for i := range batch {
			ni := batch[i]
			key := infoKey(ni)
			queried[key] = struct{}{}
			var peerID a2al.NodeID
			copy(peerID[:], ni.NodeID)
			addr, _ := q.n.lookupPeer(peerID)
			d := time.Duration(i) * stagger
			go func(addr net.Addr, delay time.Duration) {
				if delay > 0 {
					t := time.NewTimer(delay)
					select {
					case <-t.C:
					case <-ctx.Done():
						t.Stop()
						ch <- nil
						return
					}
				}
				peerCtx, peerCancel := context.WithTimeout(ctx, queryPeerTimeout)
				defer peerCancel()
				nodes, err := q.n.FindNode(peerCtx, addr, target)
				if err != nil {
					ch <- nil
					return
				}
				ch <- nodes
			}(addr, d)
		}

		// Collect responses; advance to next round on first successful response.
		received := 0
		for received < len(batch) {
			nodes := <-ch
			received++
			for _, x := range nodes {
				k := infoKey(x)
				if k == "" {
					continue
				}
				candidates[k] = cloneNI(x)
				q.n.absorbNodeInfo(x)
			}
			if len(nodes) > 0 {
				// Got a real response; remaining goroutines drain into buffered ch.
				break
			}
		}
	}

	out := sortedByDistance(candidates, target)
	if len(out) > routing.K {
		out = out[:routing.K]
	}
	return out, nil
}

// buildBatch selects up to alpha unqueried candidates, preferring non-Bad peers.
// If only Bad peers remain, they are included as a fallback.
func (q *Query) buildBatch(kClosest []protocol.NodeInfo, queried map[string]struct{}, alpha int) []protocol.NodeInfo {
	var batch []protocol.NodeInfo
	var badFallback []protocol.NodeInfo
	for _, ni := range kClosest {
		key := infoKey(ni)
		if key == "" {
			continue
		}
		if _, ok := queried[key]; ok {
			continue
		}
		var peerID a2al.NodeID
		copy(peerID[:], ni.NodeID)
		if peerID == q.n.nid {
			queried[key] = struct{}{}
			continue
		}
		addr, ok := q.n.lookupPeer(peerID)
		if !ok {
			continue
		}
		if q.n.isHairpinAddr(addr) {
			queried[key] = struct{}{}
			continue
		}
		if q.n.PeerHealthOf(peerID) == PeerHealthBad {
			if len(badFallback) < alpha {
				badFallback = append(badFallback, ni)
			}
			continue
		}
		batch = append(batch, ni)
		if len(batch) >= alpha {
			break
		}
	}
	// If no non-Bad candidates, use Bad as last resort.
	if len(batch) == 0 {
		return badFallback
	}
	return batch
}

// ErrNoEndpoint is returned when iterative FIND_VALUE does not yield a valid endpoint record.
var ErrNoEndpoint = errors.New("dht: no endpoint record")

// ErrNoMatchingRecords is returned when FindRecords finds nothing for the filter.
var ErrNoMatchingRecords = errors.New("dht: no matching records")

func filterRecordsAuth(n *Node, targetKey a2al.NodeID, recs []protocol.SignedRecord, now time.Time) []protocol.SignedRecord {
	var out []protocol.SignedRecord
	for _, r := range recs {
		if err := protocol.VerifySignedRecord(r, now); err != nil {
			continue
		}
		if n.auth != nil {
			if err := n.auth(targetKey, r, now); err != nil {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func aggregateDedupeKey(r protocol.SignedRecord) string {
	c := protocol.RecordCategory(r.RecType)
	if c == protocol.CategoryUnknown {
		c = protocol.CategorySovereign
	}
	switch c {
	case protocol.CategoryTopic:
		return "t:" + string(r.Pubkey)
	case protocol.CategoryMailbox:
		return "m:" + string(r.Pubkey) + "\x00" + string(r.Payload)
	default: // sovereign
		return "s:" + string(r.Address) + "\x00" + string([]byte{r.RecType})
	}
}

func mergeAggregate(into map[string]protocol.SignedRecord, recs []protocol.SignedRecord) {
	for _, r := range recs {
		k := aggregateDedupeKey(r)
		prev, ok := into[k]
		if !ok || protocol.RecordIsNewer(r, prev) {
			into[k] = r
		}
	}
}

// FindRecords runs iterative FIND_VALUE (recType 0 = all). Returns on first batch that yields matching records after auth.
func (q *Query) FindRecords(ctx context.Context, target a2al.NodeID, recType uint8) ([]protocol.SignedRecord, error) {
	if q.n == nil {
		return nil, errors.New("dht: nil node")
	}
	now := time.Now()
	if local := q.n.store.GetAll(target, recType, now); len(local) > 0 {
		out := filterRecordsAuth(q.n, target, local, now)
		if len(out) > 0 {
			return out, nil
		}
	}
	alpha := q.alpha()
	stagger := q.stagger()
	candidates := make(map[string]protocol.NodeInfo)
	queried := make(map[string]struct{})
	for _, ni := range q.n.tabNearestHealthy(target, routing.K) {
		if k := infoKey(ni); k != "" {
			candidates[k] = cloneNI(ni)
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		list := sortedByDistance(candidates, target)
		if len(list) == 0 {
			return nil, ErrNoMatchingRecords
		}
		kClosest := list
		if len(kClosest) > routing.K {
			kClosest = kClosest[:routing.K]
		}
		allDone := true
		for _, ni := range kClosest {
			if _, ok := queried[infoKey(ni)]; !ok {
				allDone = false
				break
			}
		}
		if allDone {
			return nil, ErrNoMatchingRecords
		}
		batch := q.buildBatch(kClosest, queried, alpha)
		if len(batch) == 0 {
			return nil, ErrNoMatchingRecords
		}
		type fvRes struct {
			recs  []protocol.SignedRecord
			nodes []protocol.NodeInfo
		}
		ch := make(chan fvRes, len(batch))
		for i := range batch {
			ni := batch[i]
			key := infoKey(ni)
			queried[key] = struct{}{}
			var peerID a2al.NodeID
			copy(peerID[:], ni.NodeID)
			addr, _ := q.n.lookupPeer(peerID)
			d := time.Duration(i) * stagger
			go func(addr net.Addr, delay time.Duration) {
				if delay > 0 {
					t := time.NewTimer(delay)
					select {
					case <-t.C:
					case <-ctx.Done():
						t.Stop()
						ch <- fvRes{}
						return
					}
				}
				peerCtx, peerCancel := context.WithTimeout(ctx, queryPeerTimeout)
				defer peerCancel()
				recs, nodes, err := q.n.FindValueWithNodes(peerCtx, addr, target, recType)
				if err != nil {
					ch <- fvRes{}
					return
				}
				ch <- fvRes{recs: recs, nodes: nodes}
			}(addr, d)
		}
		var batchMerged []protocol.SignedRecord
		for received := 0; received < len(batch); received++ {
			r := <-ch
			now := time.Now()
			batchMerged = append(batchMerged, filterRecordsAuth(q.n, target, r.recs, now)...)
			for _, x := range r.nodes {
				k := infoKey(x)
				if k == "" {
					continue
				}
				candidates[k] = cloneNI(x)
				q.n.absorbNodeInfo(x)
			}
			if len(batchMerged) > 0 {
				// Got records; remaining goroutines drain into buffered ch.
				break
			}
		}
		if len(batchMerged) > 0 {
			return batchMerged, nil
		}
	}
}

// AggregateRecords queries until the k-closest set is exhausted, merges and deduplicates (Phase 4 Topic/Mailbox).
// If the local store already holds valid records the network query is skipped — this fast-path is
// correct for the common case where the querying node is itself a publisher or a replication target
// (same a2ald, small network). Bad peers are skipped (with fallback) and a per-batch timeout
// prevents slow stragglers from stalling the whole traversal.
func (q *Query) AggregateRecords(ctx context.Context, target a2al.NodeID, recType uint8) ([]protocol.SignedRecord, error) {
	if q.n == nil {
		return nil, errors.New("dht: nil node")
	}
	merged := make(map[string]protocol.SignedRecord)
	now := time.Now()
	mergeAggregate(merged, filterRecordsAuth(q.n, target, q.n.store.GetAll(target, recType, now), now))
	// Fast path: local store already has results — return immediately without
	// querying the network. Same rationale as FindRecords local-first shortcut.
	if len(merged) > 0 {
		out := make([]protocol.SignedRecord, 0, len(merged))
		for _, r := range merged {
			out = append(out, r)
		}
		return out, nil
	}
	alpha := q.alpha()
	stagger := q.stagger()
	candidates := make(map[string]protocol.NodeInfo)
	queried := make(map[string]struct{})
	for _, ni := range q.n.tabNearestHealthy(target, routing.K) {
		if k := infoKey(ni); k != "" {
			candidates[k] = cloneNI(ni)
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		list := sortedByDistance(candidates, target)
		if len(list) == 0 {
			break
		}
		kClosest := list
		if len(kClosest) > routing.K {
			kClosest = kClosest[:routing.K]
		}
		allDone := true
		for _, ni := range kClosest {
			if _, ok := queried[infoKey(ni)]; !ok {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}
		batch := q.buildBatch(kClosest, queried, alpha)
		if len(batch) == 0 {
			break
		}
		type fvRes struct {
			recs  []protocol.SignedRecord
			nodes []protocol.NodeInfo
		}
		ch := make(chan fvRes, len(batch))
		for i := range batch {
			ni := batch[i]
			key := infoKey(ni)
			queried[key] = struct{}{}
			var peerID a2al.NodeID
			copy(peerID[:], ni.NodeID)
			addr, _ := q.n.lookupPeer(peerID)
			d := time.Duration(i) * stagger
			go func(addr net.Addr, delay time.Duration) {
				if delay > 0 {
					t := time.NewTimer(delay)
					select {
					case <-t.C:
					case <-ctx.Done():
						t.Stop()
						ch <- fvRes{}
						return
					}
				}
				peerCtx, peerCancel := context.WithTimeout(ctx, queryPeerTimeout)
				defer peerCancel()
				recs, nodes, err := q.n.FindValueWithNodes(peerCtx, addr, target, recType)
				if err != nil {
					ch <- fvRes{}
					return
				}
				ch <- fvRes{recs: recs, nodes: nodes}
			}(addr, d)
		}
		// Per-batch timeout: last stagger delay + queryPeerTimeout.
		batchDeadline := time.Duration(len(batch)-1)*stagger + queryPeerTimeout
		batchTimer := time.NewTimer(batchDeadline)
		received := 0
	batchLoop:
		for received < len(batch) {
			select {
			case r := <-ch:
				now := time.Now()
				mergeAggregate(merged, filterRecordsAuth(q.n, target, r.recs, now))
				for _, x := range r.nodes {
					k := infoKey(x)
					if k == "" {
						continue
					}
					candidates[k] = cloneNI(x)
					q.n.absorbNodeInfo(x)
				}
				received++
			case <-batchTimer.C:
				break batchLoop
			case <-ctx.Done():
				batchTimer.Stop()
				if len(merged) == 0 {
					return nil, ctx.Err()
				}
				goto aggregateDone
			}
		}
		batchTimer.Stop()
	}
aggregateDone:
	if len(merged) == 0 {
		return nil, ErrNoMatchingRecords
	}
	out := make([]protocol.SignedRecord, 0, len(merged))
	for _, r := range merged {
		out = append(out, r)
	}
	return out, nil
}

// Resolve runs iterative FIND_VALUE for target NodeID and returns a verified endpoint record.
func (q *Query) Resolve(ctx context.Context, target a2al.NodeID) (*protocol.EndpointRecord, error) {
	recs, err := q.FindRecords(ctx, target, protocol.RecTypeEndpoint)
	if err != nil {
		if errors.Is(err, ErrNoMatchingRecords) {
			return nil, ErrNoEndpoint
		}
		return nil, err
	}
	now := time.Now()
	for _, rec := range recs {
		if rec.RecType != protocol.RecTypeEndpoint {
			continue
		}
		if err := protocol.VerifySignedRecord(rec, now); err != nil {
			continue
		}
		er, err := protocol.ParseEndpointRecord(rec)
		if err == nil {
			return &er, nil
		}
	}
	return nil, ErrNoEndpoint
}
