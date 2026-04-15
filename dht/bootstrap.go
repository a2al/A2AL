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
)

// storeStagger is the inter-launch delay between successive StoreAt RPCs.
// Staggering avoids blasting all targets simultaneously while still
// advancing quickly when early targets respond promptly.
// Phase 1 fixed value; future versions will derive from RTT median × 0.5.
const storeStagger = 200 * time.Millisecond

// BootstrapAddrs connects to seed nodes by raw network addresses (ip:port only).
// For each address it sends PING, extracts the peer's identity from the PONG,
// registers the peer, then runs FIND_NODE(self) to widen the routing table.
// This is the recommended bootstrap entry point — callers do not need to know
// the seed's Address or NodeID in advance.
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

// Bootstrap registers seeds with pre-known identity and runs FIND_NODE(self).
// For seeds where only ip:port is known, use BootstrapAddrs instead.
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

// PublishEndpointRecord stores the record locally and immediately returns
// (过程一). Replication to remote peers is handled asynchronously by
// scheduleReplicate → renewBackground (FindNode + staggered StoreAt).
func (n *Node) PublishEndpointRecord(ctx context.Context, rec protocol.SignedRecord) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	if err := n.store.Put(a2al.NodeID{}, rec, time.Now()); err != nil {
		return err
	}
	var pubAddr a2al.Address
	copy(pubAddr[:], rec.Address)
	n.scheduleReplicate(a2al.NodeIDFromAddress(pubAddr), rec)
	return nil
}

// publishKeyedRecord stores rec at storeKey locally and immediately returns.
// Replication is handled asynchronously (same as PublishEndpointRecord).
// Used for mailbox and topic records.
func (n *Node) publishKeyedRecord(ctx context.Context, storeKey a2al.NodeID, rec protocol.SignedRecord) error {
	if err := n.store.Put(storeKey, rec, time.Now()); err != nil {
		return err
	}
	n.scheduleReplicate(storeKey, rec)
	return nil
}

// PublishMailboxRecord stores the mailbox record at storeKey (recipient NodeID)
// locally and replicates to k-closest reachable peers asynchronously.
func (n *Node) PublishMailboxRecord(ctx context.Context, storeKey a2al.NodeID, rec protocol.SignedRecord) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	if protocol.RecordCategory(rec.RecType) != protocol.CategoryMailbox {
		return errors.New("dht: not a mailbox record")
	}
	return n.publishKeyedRecord(ctx, storeKey, rec)
}

// PublishTopicRecord stores the topic record at storeKey
// (SHA-256("topic:"+topic)) locally and replicates asynchronously.
func (n *Node) PublishTopicRecord(ctx context.Context, storeKey a2al.NodeID, rec protocol.SignedRecord) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	if protocol.RecordCategory(rec.RecType) != protocol.CategoryTopic {
		return errors.New("dht: not a topic record")
	}
	return n.publishKeyedRecord(ctx, storeKey, rec)
}


// tabNeighbours returns the k-closest healthy routing table peers to target.
// Convenience wrapper used by tests and the query engine.
func (n *Node) tabNeighbours(target a2al.NodeID, k int) []protocol.NodeInfo {
	return n.tabNearestHealthy(target, k)
}
