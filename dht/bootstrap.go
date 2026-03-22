package dht

import (
	"context"
	"errors"
	"net"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)

// BootstrapSeed is a known dial address plus wire NodeInfo (spec Step 9).
type BootstrapSeed struct {
	Addr net.Addr
	Info protocol.NodeInfo
}

// Bootstrap registers seeds and runs FIND_NODE(self) to widen the routing table.
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

// StartWithBootstrap starts the receive loop then bootstraps.
func (n *Node) StartWithBootstrap(ctx context.Context, seeds []BootstrapSeed) error {
	n.Start()
	return n.Bootstrap(ctx, seeds)
}

// PublishEndpointRecord runs FIND_NODE toward the record key and STOREs at up to three closest dialable peers.
func (n *Node) PublishEndpointRecord(ctx context.Context, rec protocol.SignedRecord) error {
	if n == nil {
		return errors.New("dht: nil node")
	}
	var pubAddr a2al.Address
	copy(pubAddr[:], rec.Address)
	key := a2al.NodeIDFromAddress(pubAddr)
	q := NewQuery(n)
	if _, err := q.FindNode(ctx, key); err != nil {
		return err
	}
	peers := n.tabNearest(key, routing.K)
	if len(peers) == 0 {
		return errors.New("dht: no peers to publish")
	}
	limit := 3
	if len(peers) < limit {
		limit = len(peers)
	}
	var lastErr error
	stored := false
	for i := 0; i < limit; i++ {
		var id a2al.NodeID
		copy(id[:], peers[i].NodeID)
		addr, ok := n.lookupPeer(id)
		if !ok {
			continue
		}
		ok, err := n.StoreAt(ctx, addr, rec)
		if err != nil {
			lastErr = err
			continue
		}
		if ok {
			stored = true
		}
	}
	if stored {
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("dht: publish rejected or unroutable")
}
