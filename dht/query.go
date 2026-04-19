// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)

const (
	// DefaultAlpha is exported for callers that inspect it; the slot engine uses
	// queryAlpha internally.
	DefaultAlpha = 5

	// DefaultStagger is retained for API compatibility but is not used by the
	// slot-based engine.
	DefaultStagger = 200 * time.Millisecond

	// queryPeerTimeout is the per-peer deadline for individual RPCs.
	queryPeerTimeout = 2 * time.Second

	// queryAlpha is the concurrent-slot count for the good (known-reachable) track.
	queryAlpha = 5

	// queryGamma is the concurrent-slot count for the unknown track.
	queryGamma = 3

	// queryBeta is the concurrent-slot count for the bad-node track.
	queryBeta = 3

	// querySlotStagger is the inter-slot delay used only when filling the initial
	// good-track burst, smoothing the UDP send spike.
	querySlotStagger = 50 * time.Millisecond

	// queryUnknownInterval is the cadence at which unknown-track slots are launched.
	// Unknown peers have 2 s timeouts; spacing them at 200 ms limits wasted bandwidth
	// while still probing them in parallel with the good track.
	queryUnknownInterval = 200 * time.Millisecond

	// queryBadInterval is the minimum time between successive bad-track slot launches.
	// Keeps bad-node probing intentionally slow and opportunistic.
	queryBadInterval = time.Second
)

// track constants identify which candidate pool a slotRes came from.
const (
	trackGood    = 0
	trackUnknown = 1
	trackBad     = 2
)

// Query runs iterative FIND_NODE / FIND_VALUE (spec Step 8).
type Query struct {
	n       *Node
	Alpha   int           // retained for API compatibility; slot engine uses queryAlpha
	Stagger time.Duration // retained for API compatibility; slot engine uses querySlotStagger
}

// NewQuery builds a querier backed by n.
func NewQuery(n *Node) *Query {
	if n == nil {
		return nil
	}
	return &Query{n: n, Alpha: DefaultAlpha, Stagger: DefaultStagger}
}

// ── Utility helpers ───────────────────────────────────────────────────────────

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

// ── Slot-based query engine ───────────────────────────────────────────────────

// slotRes carries the outcome of one in-flight RPC slot.
type slotRes struct {
	nodes []protocol.NodeInfo
	recs  []protocol.SignedRecord
	track int // trackGood | trackUnknown | trackBad
}

// reachCandItem is a candidate with pre-computed XOR distance (good or unknown track).
type reachCandItem struct {
	ni   protocol.NodeInfo
	dist a2al.NodeID // XOR(nodeID, target)
}

// badCandItem is a bad-track candidate.  Health fields are snapshotted at
// insertion time for stable, lock-free sorting.
type badCandItem struct {
	ni            protocol.NodeInfo
	dist          a2al.NodeID
	lastFailure   time.Time
	totalAttempts int
}

// xorLT reports whether XOR distance a is strictly less than b (a is closer).
func xorLT(a, b a2al.NodeID) bool {
	for i := range a {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}

// insertReach inserts item into cands, keeping the slice sorted by XOR
// distance ascending (closest to target first).
func insertReach(cands []reachCandItem, item reachCandItem) []reachCandItem {
	idx := sort.Search(len(cands), func(i int) bool {
		return !xorLT(cands[i].dist, item.dist)
	})
	cands = append(cands, reachCandItem{})
	copy(cands[idx+1:], cands[idx:])
	cands[idx] = item
	return cands
}

// badLess defines the priority order for bad-track candidates:
//
//  1. XOR distance ascending (closest first — most likely to hold the record)
//  2. lastFailure ascending (tried least recently = oldest failure first)
//  3. totalAttempts ascending (fewest lifetime attempts first)
func badLess(a, b badCandItem) bool {
	if a.dist != b.dist {
		return xorLT(a.dist, b.dist)
	}
	if !a.lastFailure.Equal(b.lastFailure) {
		return a.lastFailure.Before(b.lastFailure)
	}
	return a.totalAttempts < b.totalAttempts
}

// insertBad inserts item into cands maintaining badLess order.
func insertBad(cands []badCandItem, item badCandItem) []badCandItem {
	idx := sort.Search(len(cands), func(i int) bool {
		return !badLess(cands[i], item)
	})
	cands = append(cands, badCandItem{})
	copy(cands[idx+1:], cands[idx:])
	cands[idx] = item
	return cands
}

// runIterQuery is the slot-based iterative query engine shared by FindNode,
// FindRecords, and AggregateRecords.
//
// Three independent tracks run in a single-goroutine event loop:
//
//	Good track  (PeerHealthGood,    queryAlpha=5 slots, 50 ms stagger on initial burst):
//	  Primary track.  A hit on this track causes immediate return to the caller;
//	  unknown and bad in-flight slots drain in a background goroutine.
//	  Termination: all slots idle AND candidate queue empty (or hit threshold reached).
//
//	Unknown track (PeerHealthUnknown, queryGamma=3 slots, 1 slot/200 ms):
//	  Secondary track.  Runs concurrently with the good track but in its own slot
//	  pool — it cannot steal good-track slots or delay good-track results.
//	  The query only waits for this track when the good track exhausted with no hit.
//	  A hit here causes the same immediate-return behaviour.
//
//	Bad track   (PeerHealthBad,     queryBeta=3 slots, 1 slot/s):
//	  Opportunistic probing.  Never blocks the caller; results are drained in the
//	  background goroutine after the good+unknown tracks finish.
//
// Parameters:
//
//	findValue=false  → use FindNode RPC (records always nil in output)
//	findValue=true   → use FindValueWithNodes RPC
//	hitThreshold=0   → exhaust good+unknown tracks (AggregateRecords mode)
//	hitThreshold>0   → return immediately once that many distinct records are collected
func (q *Query) runIterQuery(
	ctx context.Context,
	target a2al.NodeID,
	findValue bool,
	recType uint8,
	hitThreshold int,
) (outRecs []protocol.SignedRecord, outNodes []protocol.NodeInfo, err error) {
	n := q.n

	// ── Candidate pools ───────────────────────────────────────────────────
	// All three pools are owned exclusively by the main goroutine; no mutexes
	// are required because every read/write occurs in the main event loop.
	var goodCands []reachCandItem    // PeerHealthGood
	var unknownCands []reachCandItem // PeerHealthUnknown
	var badCands []badCandItem       // PeerHealthBad

	// In-flight slot counts — incremented here, decremented when resultCh receives.
	goodInFlight, unknownInFlight, badInFlight := 0, 0, 0

	// queried prevents the same peer from being contacted by multiple tracks.
	queried := make(map[string]struct{})
	tryMark := func(k string) bool {
		if _, ok := queried[k]; ok {
			return false
		}
		queried[k] = struct{}{}
		return true
	}

	// addCand classifies ni and appends it to the appropriate pool.
	// Must be called from the main goroutine only.
	addCand := func(ni protocol.NodeInfo) {
		k := infoKey(ni)
		if k == "" {
			return
		}
		var id a2al.NodeID
		copy(id[:], ni.NodeID)
		if id == n.nid {
			return
		}
		addr, ok := n.lookupPeer(id)
		if !ok {
			return
		}
		if n.isHairpinAddr(addr) {
			return
		}
		if !tryMark(k) {
			return
		}
		dist := xorNodeID(id, target)
		switch n.PeerHealthOf(id) {
		case PeerHealthGood:
			goodCands = insertReach(goodCands, reachCandItem{ni: cloneNI(ni), dist: dist})
		case PeerHealthBad:
			lf, ta := n.peerHealthForSort(id)
			badCands = insertBad(badCands, badCandItem{
				ni: cloneNI(ni), dist: dist, lastFailure: lf, totalAttempts: ta,
			})
		default: // Unknown
			unknownCands = insertReach(unknownCands, reachCandItem{ni: cloneNI(ni), dist: dist})
		}
	}

	// Seed candidate pools from the local routing table.
	// Use tabNearest so Bad peers are also seeded into the bad track;
	// tabNearestHealthy truncates at K and can silently drop all Bad peers.
	for _, ni := range n.tabNearest(target, routing.K) {
		n.absorbNodeInfo(ni)
		addCand(ni)
	}

	// ── Accumulators ──────────────────────────────────────────────────────
	hitMerged := make(map[string]protocol.SignedRecord)

	// For AggregateRecords (hitThreshold==0) seed hitMerged with locally-cached
	// records so they appear in the output alongside network results even when
	// no remote node returns them.  The fast path is intentionally removed for
	// AggregateRecords: the network query always runs to discover new publishers.
	if findValue && hitThreshold == 0 {
		now := time.Now()
		for _, rec := range filterRecordsAuth(n, target, n.store.GetAll(target, recType, now), now) {
			hitMerged[aggregateDedupeKey(rec)] = rec
		}
	}

	hitReached := false
	allSeen := make(map[string]protocol.NodeInfo)

	// ── RPC helpers ───────────────────────────────────────────────────────
	// Buffered channel: holds results from all in-flight goroutines without blocking.
	resultCh := make(chan slotRes, queryAlpha+queryGamma+queryBeta+4)

	doRPC := func(ni protocol.NodeInfo, track int) {
		var id a2al.NodeID
		copy(id[:], ni.NodeID)
		addr, ok := n.lookupPeer(id)
		if !ok {
			resultCh <- slotRes{track: track}
			return
		}
		pctx, cancel := context.WithTimeout(ctx, queryPeerTimeout)
		defer cancel()
		if findValue {
			recs, nodes, rpcErr := n.FindValueWithNodes(pctx, addr, target, recType)
			if rpcErr != nil {
				resultCh <- slotRes{track: track}
				return
			}
			resultCh <- slotRes{recs: recs, nodes: nodes, track: track}
		} else {
			nodes, rpcErr := n.FindNode(pctx, addr, target)
			if rpcErr != nil {
				resultCh <- slotRes{track: track}
				return
			}
			resultCh <- slotRes{nodes: nodes, track: track}
		}
	}

	launchGood := func(ni protocol.NodeInfo, delay time.Duration) {
		goodInFlight++
		go func(ni protocol.NodeInfo, delay time.Duration) {
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					resultCh <- slotRes{track: trackGood}
					return
				}
			}
			doRPC(ni, trackGood)
		}(ni, delay)
	}

	launchUnknown := func(ni protocol.NodeInfo) {
		unknownInFlight++
		go func() { doRPC(ni, trackUnknown) }()
	}

	launchBad := func(ni protocol.NodeInfo) {
		badInFlight++
		go func() { doRPC(ni, trackBad) }()
	}

	// Initial fill of good slots with stagger to smooth the UDP burst.
	// Subsequent refills happen at the top of the main loop (delay=0).
	{
		fill := min(queryAlpha, len(goodCands))
		for i := 0; i < fill; i++ {
			item := goodCands[0]
			goodCands = goodCands[1:]
			launchGood(item.ni, time.Duration(i)*querySlotStagger)
		}
	}

	unknownTicker := time.NewTicker(queryUnknownInterval)
	defer unknownTicker.Stop()
	badTicker := time.NewTicker(queryBadInterval)
	defer badTicker.Stop()

	processResult := func(r slotRes) {
		for _, ni := range r.nodes {
			n.absorbNodeInfo(ni)
			if k := infoKey(ni); k != "" {
				allSeen[k] = cloneNI(ni)
			}
			addCand(ni)
		}
		if !findValue || len(r.recs) == 0 {
			return
		}
		now := time.Now()
		for _, rec := range filterRecordsAuth(n, target, r.recs, now) {
			dk := aggregateDedupeKey(rec)
			if prev, ok := hitMerged[dk]; !ok || protocol.RecordIsNewer(rec, prev) {
				hitMerged[dk] = rec
			}
		}
		if hitThreshold > 0 && len(hitMerged) >= hitThreshold {
			hitReached = true
		}
	}

	// ── Main event loop ───────────────────────────────────────────────────
	// Exit conditions:
	//   hitReached=true  → immediate return (background drain handles in-flight)
	//   goodDone && unknownDone → all reachable candidates exhausted (bad is background)
mainLoop:
	for {
		// Eagerly fill good slots.  Handles both normal slot refill and the case
		// where processResult → addCand grew goodCands from an incoming result.
		for !hitReached && goodInFlight < queryAlpha && len(goodCands) > 0 {
			item := goodCands[0]
			goodCands = goodCands[1:]
			launchGood(item.ni, 0)
		}

		goodDone := goodInFlight == 0 && len(goodCands) == 0
		unknownDone := unknownInFlight == 0 && len(unknownCands) == 0

		if hitReached || (goodDone && unknownDone) {
			break mainLoop
		}
		if ctx.Err() != nil {
			break mainLoop
		}

		select {
		case <-ctx.Done():
			break mainLoop

		case r := <-resultCh:
			switch r.track {
			case trackGood:
				goodInFlight--
			case trackUnknown:
				unknownInFlight--
			case trackBad:
				badInFlight--
			}
			processResult(r)

		case <-unknownTicker.C:
			// Launch one unknown slot when capacity allows and no hit yet.
			if !hitReached && unknownInFlight < queryGamma && len(unknownCands) > 0 {
				item := unknownCands[0]
				unknownCands = unknownCands[1:]
				launchUnknown(item.ni)
			}

		case <-badTicker.C:
			// Launch one bad-track slot opportunistically.
			if !hitReached && badInFlight < queryBeta && len(badCands) > 0 {
				item := badCands[0]
				badCands = badCands[1:]
				launchBad(item.ni)
			}
		}
	}

	// Background drain for any in-flight goroutines that are still running.
	// This covers: (a) early return when hitReached=true, (b) bad-track slots
	// still running when good+unknown tracks finish.
	totalInFlight := goodInFlight + unknownInFlight + badInFlight
	if totalInFlight > 0 {
		go func(total int) {
			deadline := time.NewTimer(queryPeerTimeout + 500*time.Millisecond)
			defer deadline.Stop()
			for drained := 0; drained < total; {
				select {
				case r := <-resultCh:
					drained++
					for _, ni := range r.nodes {
						n.absorbNodeInfo(ni)
					}
					if findValue {
						for _, rec := range r.recs {
							_ = n.LocalStorePut(target, rec)
						}
					}
				case <-deadline.C:
					return
				}
			}
		}(totalInFlight)
	}

	// Build outputs.
	outRecs = make([]protocol.SignedRecord, 0, len(hitMerged))
	for _, r := range hitMerged {
		outRecs = append(outRecs, r)
	}

	outNodes = sortedByDistance(allSeen, target)
	if len(outNodes) > routing.K {
		outNodes = outNodes[:routing.K]
	}

	if findValue && len(outRecs) == 0 {
		return nil, outNodes, ErrNoMatchingRecords
	}
	return outRecs, outNodes, nil
}

// ── Public query methods ──────────────────────────────────────────────────────

// FindNode runs iterative FIND_NODE until the good+unknown candidate pools are
// exhausted.  Returns the K XOR-closest nodes discovered.
func (q *Query) FindNode(ctx context.Context, target a2al.NodeID) ([]protocol.NodeInfo, error) {
	if q.n == nil {
		return nil, errors.New("dht: nil node")
	}
	_, nodes, err := q.runIterQuery(ctx, target, false, 0, 0)
	if err != nil && !errors.Is(err, ErrNoMatchingRecords) {
		return nodes, err
	}
	return nodes, nil
}

// ErrNoEndpoint is returned when iterative FIND_VALUE does not yield a valid
// endpoint record.
var ErrNoEndpoint = errors.New("dht: no endpoint record")

// ErrNoMatchingRecords is returned when FindRecords / AggregateRecords find
// nothing for the filter.
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

// FindRecords runs iterative FIND_VALUE (recType 0 = all).
// Returns on the first valid record found (optimistic strategy).
// Local store is checked first; if a valid cached record exists the network is
// not queried.  The cache is transparently invalidated by the host layer when a
// subsequent connection attempt using the cached data fails.
func (q *Query) FindRecords(ctx context.Context, target a2al.NodeID, recType uint8) ([]protocol.SignedRecord, error) {
	if q.n == nil {
		return nil, errors.New("dht: nil node")
	}
	now := time.Now()
	if local := q.n.store.GetAll(target, recType, now); len(local) > 0 {
		if out := filterRecordsAuth(q.n, target, local, now); len(out) > 0 {
			return out, nil
		}
	}
	recs, _, err := q.runIterQuery(ctx, target, true, recType, 1)
	return recs, err
}

// AggregateRecords queries the network until the good+unknown candidate pools are
// exhausted, then merges and deduplicates all discovered records (Phase 4
// Topic/Mailbox).  Unlike FindRecords, there is no local-cache fast path: the
// network query always runs so that newly-joined publishers are discovered.
// Locally-cached records are seeded into the result set and merged with network
// results.
func (q *Query) AggregateRecords(ctx context.Context, target a2al.NodeID, recType uint8) ([]protocol.SignedRecord, error) {
	if q.n == nil {
		return nil, errors.New("dht: nil node")
	}
	// hitThreshold=0 → exhaust all good+unknown candidates.
	// Local store records are seeded into hitMerged at runIterQuery start.
	recs, _, err := q.runIterQuery(ctx, target, true, recType, 0)
	return recs, err
}

// Resolve runs iterative FIND_VALUE for target NodeID and returns a verified
// endpoint record.
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
