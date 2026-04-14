// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)


// storeStagger is the inter-launch delay between successive StoreAt RPCs.
// Staggering avoids blasting all targets simultaneously while still
// advancing quickly when early targets respond promptly.
// Phase 1 fixed value; future versions will derive from RTT median × 0.5.
const storeStagger = 200 * time.Millisecond

// BootstrapAddrs connects to seed nodes by raw network addresses (ip:port only). For each address it sends PING, extracts the peer's identity from the PONG, registers the peer, then runs FIND_NODE(self) to widen the routing table. This is the recommended bootstrap entry point — callers do not need to know the seed's Address or NodeID in advance.
func (n *Node) BootstrapAddrs(ctx context.Context, addrs []net.Addr) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	n.Start()

	type pingResult struct {
		addr net.Addr
		ok   bool
	}
	ch := make(chan pingResult, len(addrs))
	for _, a := range addrs {
		a := a
		go func() {
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			pi, err := n.PingIdentity(pctx, a)
			if err != nil {
				n.log.Debug("bootstrap ping failed", "addr", a, "err", err)
				ch <- pingResult{addr: a}
				return
			}
			n.log.Debug("bootstrap ping ok", "addr", a, "peer", pi.NodeID)
			ch <- pingResult{addr: a, ok: true}
		}()
	}
	contacted := 0
	for range addrs {
		if (<-ch).ok {
			contacted++
		}
	}

	if contacted == 0 && len(addrs) > 0 {
		return errors.New("dht: all bootstrap seeds unreachable")
	}
	if contacted > 0 {
		q := NewQuery(n)
		peers, err := q.FindNode(ctx, n.nid)
		if err != nil {
			n.log.Debug("bootstrap FindNode(self) failed", "err", err)
		} else {
			n.log.Debug("bootstrap FindNode(self) done", "peers_found", len(peers))
		}
	}
	return nil
}

// BootstrapSeed is a known dial address plus wire NodeInfo (legacy; prefer BootstrapAddrs).
type BootstrapSeed struct {
	Addr net.Addr
	Info protocol.NodeInfo
}

// Bootstrap registers seeds with pre-known identity and runs FIND_NODE(self). For seeds where only ip:port is known, use BootstrapAddrs instead.
func (n *Node) Bootstrap(ctx context.Context, seeds []BootstrapSeed) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	n.Start()
	for _, s := range seeds {
		n.AddContact(s.Addr, s.Info)
	}
	if len(seeds) == 0 {
		return nil
	}
	q := NewQuery(n)
	_, err := q.FindNode(ctx, n.nid)
	return err
}

// StartWithBootstrap starts the receive loop then bootstraps with raw addresses.
func (n *Node) StartWithBootstrap(ctx context.Context, addrs []net.Addr) error {
	n.Start()
	return n.BootstrapAddrs(ctx, addrs)
}

// PublishEndpointRecord stores the record locally then replicates it to the
// closest reachable peers using staggered StoreAt.
//
// Concurrently:
//   - Staggered StoreAt to tabNearestHealthy candidates (Good first).
//     Returns success as soon as 1 store succeeds; remaining attempts
//     continue in background within ctx lifetime.
//   - FindNode(key) to discover XOR-closer peers.  After it completes,
//     any newly discovered closer Good/Unknown peers receive an additional
//     background StoreAt.
func (n *Node) PublishEndpointRecord(ctx context.Context, rec protocol.SignedRecord) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	if err := n.store.Put(a2al.NodeID{}, rec, time.Now()); err != nil {
		return err
	}

	var pubAddr a2al.Address
	copy(pubAddr[:], rec.Address)
	key := a2al.NodeIDFromAddress(pubAddr)

	candidates := n.tabNearestHealthy(key, routing.K)
	successCh := make(chan struct{}, 1)

	// Staggered StoreAt goroutine: launch one store every storeStagger,
	// signalling successCh on the first acknowledged store.
	go func() {
		n.staggeredStoreAt(ctx, candidates, a2al.NodeID{}, rec, 1, successCh)
	}()

	// Parallel FindNode to discover closer peers, then store to any newcomers.
	go func() {
		q := NewQuery(n)
		found, err := q.FindNode(ctx, key)
		if err != nil || ctx.Err() != nil {
			return
		}
		n.log.Debug("publish FindNode done", "peers_found", len(found))
		// Collect peers that are XOR-closer and not already in candidates.
		existing := make(map[string]struct{}, len(candidates))
		for _, ni := range candidates {
			existing[infoKey(ni)] = struct{}{}
		}
		var extra []protocol.NodeInfo
		for _, ni := range found {
			if k := infoKey(ni); k != "" {
				if _, seen := existing[k]; !seen {
					extra = append(extra, ni)
				}
			}
		}
		if len(extra) > 0 {
			n.staggeredStoreAt(ctx, extra, a2al.NodeID{}, rec, 0, nil)
		}
	}()

	// Wait for the first successful store or context expiry.
	select {
	case <-successCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// staggeredStoreAt sends STORE to peers one at a time with a storeStagger
// interval between launches. It stops early when storedGoal > 0 and that
// many stores have succeeded. Signals successCh (if non-nil) on the first
// success.  Does not block the caller — intended to be run in a goroutine.
func (n *Node) staggeredStoreAt(
	ctx context.Context,
	peers []protocol.NodeInfo,
	storeKey a2al.NodeID,
	rec protocol.SignedRecord,
	storedGoal int,
	successCh chan<- struct{},
) {
	stored := 0
	notified := false
	for i, ni := range peers {
		if ctx.Err() != nil {
			return
		}
		if storedGoal > 0 && stored >= storedGoal {
			return
		}

		// Stagger: skip delay for the very first candidate.
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
		addr, ok := n.lookupPeer(id)
		if !ok {
			continue
		}
		if n.isHairpinAddr(addr) {
			n.log.Debug("publish StoreAt skip: NAT hairpin", "peer", addr)
			continue
		}

		peerCtx, peerCancel := context.WithTimeout(ctx, queryPeerTimeout)
		_, err := n.StoreAt(peerCtx, addr, storeKey, rec)
		peerCancel()
		if err != nil {
			n.log.Debug("publish StoreAt failed", "peer", addr, "err", err)
			continue
		}
		n.log.Debug("publish StoreAt ok", "peer", addr)
		stored++
		if successCh != nil && !notified {
			notified = true
			select {
			case successCh <- struct{}{}:
			default:
			}
		}
	}

	// If we exhausted all candidates without success and goal > 0, signal failure.
	// (successCh left empty; caller's ctx.Done will fire instead.)
}

// publishKeyedRecord stores rec at storeKey locally then replicates to the
// k-closest reachable peers using staggered StoreAt + parallel FindNode.
// Used for mailbox and topic records where stronger replication (N≥3) is
// preferred over single-store availability.
func (n *Node) publishKeyedRecord(ctx context.Context, storeKey a2al.NodeID, rec protocol.SignedRecord) error {
	if err := n.store.Put(storeKey, rec, time.Now()); err != nil {
		return err
	}

	const keyedStoreGoal = 3 // aim for 3 successful stores

	candidates := n.tabNearestHealthy(storeKey, routing.K)
	successCh := make(chan int, 1) // sends final stored count

	// Staggered StoreAt to current candidates; notify after storedGoal reached.
	storeResultCh := make(chan struct{}, 1)
	go func() {
		n.staggeredStoreAt(ctx, candidates, storeKey, rec, keyedStoreGoal, storeResultCh)
		// Signal completion regardless.
		select {
		case storeResultCh <- struct{}{}:
		default:
		}
	}()

	// Parallel FindNode to discover closer peers.
	go func() {
		q := NewQuery(n)
		found, err := q.FindNode(ctx, storeKey)
		if err != nil || ctx.Err() != nil {
			return
		}
		existing := make(map[string]struct{}, len(candidates))
		for _, ni := range candidates {
			existing[infoKey(ni)] = struct{}{}
		}
		var extra []protocol.NodeInfo
		for _, ni := range found {
			if k := infoKey(ni); k != "" {
				if _, seen := existing[k]; !seen {
					extra = append(extra, ni)
				}
			}
		}
		if len(extra) > 0 {
			n.staggeredStoreAt(ctx, extra, storeKey, rec, 0, nil)
		}
		select {
		case successCh <- 0:
		default:
		}
	}()

	// Wait for first store success or context expiry.
	// background FindNode goroutine drains via its own successCh.
	select {
	case <-storeResultCh:
		return nil
	case <-ctx.Done():
		_ = successCh
		return ctx.Err()
	}
}

// PublishMailboxRecord stores the mailbox record at storeKey (recipient NodeID) locally and
// replicates to every k-closest reachable peer via FIND_NODE + STORE (spec §4.4).
func (n *Node) PublishMailboxRecord(ctx context.Context, storeKey a2al.NodeID, rec protocol.SignedRecord) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	if protocol.RecordCategory(rec.RecType) != protocol.CategoryMailbox {
		return errors.New("dht: not a mailbox record")
	}
	return n.publishKeyedRecord(ctx, storeKey, rec)
}

// PublishTopicRecord stores the topic record at storeKey (SHA-256("topic:"+topic)) locally and
// replicates to every k-closest reachable peer (spec §5.4).
func (n *Node) PublishTopicRecord(ctx context.Context, storeKey a2al.NodeID, rec protocol.SignedRecord) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	if protocol.RecordCategory(rec.RecType) != protocol.CategoryTopic {
		return errors.New("dht: not a topic record")
	}
	return n.publishKeyedRecord(ctx, storeKey, rec)
}
