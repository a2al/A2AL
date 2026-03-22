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

// BootstrapAddrs connects to seed nodes by raw network addresses (ip:port only). For each address it sends PING, extracts the peer's identity from the PONG, registers the peer, then runs FIND_NODE(self) to widen the routing table. This is the recommended bootstrap entry point — callers do not need to know the seed's Address or NodeID in advance.
func (n *Node) BootstrapAddrs(ctx context.Context, addrs []net.Addr) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	n.Start()
	contacted := 0
	for _, addr := range addrs {
		if _, err := n.PingIdentity(ctx, addr); err == nil {
			contacted++
		}
	}
	if contacted == 0 && len(addrs) > 0 {
		return errors.New("dht: all bootstrap seeds unreachable")
	}
	if contacted > 0 {
		q := NewQuery(n)
		if _, err := q.FindNode(ctx, n.nid); err != nil {
			return err
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
	n.store.Put(rec, time.Now())

	var pubAddr a2al.Address
	copy(pubAddr[:], rec.Address)
	key := a2al.NodeIDFromAddress(pubAddr)
	q := NewQuery(n)
	if _, err := q.FindNode(ctx, key); err != nil {
		return err
	}
	peers := n.tabNearest(key, routing.K)
	if len(peers) == 0 {
		return nil // local-only publish; no peers yet
	}
	limit := 3
	if len(peers) < limit {
		limit = len(peers)
	}
	var lastErr error
	for i := 0; i < limit; i++ {
		var id a2al.NodeID
		copy(id[:], peers[i].NodeID)
		addr, ok := n.lookupPeer(id)
		if !ok {
			continue
		}
		if _, err := n.StoreAt(ctx, addr, rec); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
