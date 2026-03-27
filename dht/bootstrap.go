// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dht

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)

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

// PublishEndpointRecord stores the record locally and pushes it to up to three closest reachable peers via FIND_NODE + STORE.
// Storing locally ensures the node is always discoverable (even as the first node in the network).
func (n *Node) PublishEndpointRecord(ctx context.Context, rec protocol.SignedRecord) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	// Always store locally first so the record is discoverable regardless of routing table state.
	if err := n.store.Put(a2al.NodeID{}, rec, time.Now()); err != nil {
		return err
	}

	var pubAddr a2al.Address
	copy(pubAddr[:], rec.Address)
	key := a2al.NodeIDFromAddress(pubAddr)
	q := NewQuery(n)
	peers, err := q.FindNode(ctx, key)
	if err != nil {
		n.log.Debug("publish FindNode failed", "err", err)
		return err
	}
	n.log.Debug("publish FindNode done", "peers_found", len(peers))
	nearest := n.tabNearest(key, routing.K)
	if len(nearest) == 0 {
		n.log.Debug("publish: no peers, local-only")
		return nil
	}
	limit := 3
	if len(nearest) < limit {
		limit = len(nearest)
	}
	var (
		mu      sync.Mutex
		stored  int
		lastErr error
		wg      sync.WaitGroup
	)
	for i := 0; i < limit; i++ {
		var id a2al.NodeID
		copy(id[:], nearest[i].NodeID)
		addr, ok := n.lookupPeer(id)
		if !ok {
			n.log.Debug("publish StoreAt skip: no addr", "peer", id)
			continue
		}
		if n.isHairpinAddr(addr) {
			n.log.Debug("publish StoreAt skip: NAT hairpin", "peer", addr)
			continue
		}
		wg.Add(1)
		go func(addr net.Addr) {
			defer wg.Done()
			peerCtx, peerCancel := context.WithTimeout(ctx, queryPeerTimeout)
			defer peerCancel()
			if _, err := n.StoreAt(peerCtx, addr, a2al.NodeID{}, rec); err != nil {
				n.log.Debug("publish StoreAt failed", "peer", addr, "err", err)
				mu.Lock()
				lastErr = err
				mu.Unlock()
			} else {
				n.log.Debug("publish StoreAt ok", "peer", addr)
				mu.Lock()
				stored++
				mu.Unlock()
			}
		}(addr)
	}
	wg.Wait()
	n.log.Debug("publish done", "stored", stored, "attempted", limit)
	if stored > 0 {
		return nil
	}
	return lastErr
}

// publishKeyedRecord stores rec at storeKey locally then replicates to every
// k-closest reachable peer via FIND_NODE + STORE. Used by both mailbox and
// topic publish paths.
func (n *Node) publishKeyedRecord(ctx context.Context, storeKey a2al.NodeID, rec protocol.SignedRecord) error {
	if err := n.store.Put(storeKey, rec, time.Now()); err != nil {
		return err
	}
	q := NewQuery(n)
	if _, err := q.FindNode(ctx, storeKey); err != nil {
		return err
	}
	peers := n.tabNearest(storeKey, routing.K)
	var (
		mu      sync.Mutex
		stored  int
		lastErr error
		wg      sync.WaitGroup
	)
	for i := 0; i < len(peers); i++ {
		var id a2al.NodeID
		copy(id[:], peers[i].NodeID)
		if id == n.nid {
			continue
		}
		addr, ok := n.lookupPeer(id)
		if !ok {
			continue
		}
		if n.isHairpinAddr(addr) {
			n.log.Debug("publish keyed StoreAt skip: NAT hairpin", "peer", addr)
			continue
		}
		wg.Add(1)
		go func(addr net.Addr) {
			defer wg.Done()
			peerCtx, peerCancel := context.WithTimeout(ctx, queryPeerTimeout)
			defer peerCancel()
			if _, err := n.StoreAt(peerCtx, addr, storeKey, rec); err != nil {
				mu.Lock()
				lastErr = err
				mu.Unlock()
			} else {
				mu.Lock()
				stored++
				mu.Unlock()
			}
		}(addr)
	}
	wg.Wait()
	if stored > 0 {
		return nil
	}
	return lastErr
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
