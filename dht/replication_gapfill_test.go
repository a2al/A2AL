// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/a2al/a2al"
	acrypto "github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

func symNATRecord(t *testing.T, signal string) (a2al.NodeID, protocol.SignedRecord) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := acrypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sr, err := protocol.SignEndpointRecord(priv, addr, protocol.EndpointPayload{
		Endpoints: []string{"quic://10.0.0.1:4242"},
		NatType:   protocol.NATSymmetric,
		Signal:    signal,
	}, 1, uint64(time.Now().Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	return a2al.NodeIDFromAddress(addr), sr
}

func TestPickGapFillPeers_tracks(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("gapfill")
	defer tr.Close()
	n := newTestNode(t, tr, &mockPunch{})
	n.Start()
	defer n.Close()

	var key a2al.NodeID
	key[31] = 1
	rs := makeRepSet(key)

	_, directID, directEP := makeSignedEndpointRecord(t, "")
	n.LocalStorePut(directID, directEP)
	n.BindPeerAnchor(directID, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4121})
	directNI := protocol.NodeInfo{NodeID: append([]byte(nil), directID[:]...)}

	natID, natEP := symNATRecord(t, "ws://sig/ice")
	n.LocalStorePut(natID, natEP)
	natNI := protocol.NodeInfo{NodeID: append([]byte(nil), natID[:]...)}

	direct, nat := n.pickGapFillPeers(key, rs, []protocol.NodeInfo{directNI}, []protocol.NodeInfo{natNI}, nil)
	if len(direct) != 1 || len(nat) != 1 {
		t.Fatalf("direct=%d nat=%d, want 1 each", len(direct), len(nat))
	}
}

func TestPickGapFillPeers_punchBudget(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("gapfill-budget")
	defer tr.Close()
	n := newTestNode(t, tr, &mockPunch{})
	n.Start()
	defer n.Close()

	rs := makeRepSet(a2al.NodeID{})
	var pool []protocol.NodeInfo
	for i := 0; i < gapFillPunchBudget+2; i++ {
		nid, sr := symNATRecord(t, "ws://sig/ice")
		n.LocalStorePut(nid, sr)
		pool = append(pool, protocol.NodeInfo{NodeID: append([]byte(nil), nid[:]...)})
	}
	_, nat := n.pickGapFillPeers(a2al.NodeID{}, rs, nil, pool, nil)
	if len(nat) != gapFillPunchBudget {
		t.Fatalf("nat=%d, want %d", len(nat), gapFillPunchBudget)
	}
}

// TestPickGapFillPeers_qualityDisplacement verifies that when the direct track
// is full (directNeed=0) but punched members exist, one direct candidate that
// is XOR-closer than the farthest punched member is included for quality
// displacement.  This covers re-admission of a node that was evicted and later
// recovered as a directly-reachable peer.
func TestPickGapFillPeers_qualityDisplacement(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("gapfill-quality")
	defer tr.Close()
	n := newTestNode(t, tr, &mockPunch{})
	n.Start()
	defer n.Close()

	var key a2al.NodeID // zero key

	// Fill the direct track to capacity: nRep direct nodes at distances 50..57.
	rs := makeRepSet(key)
	rs.storeKey = key
	for i := 0; i < nRep; i++ {
		var id a2al.NodeID
		id[31] = byte(50 + i)
		rs.nodes[nodeIDKey(id)] = &repNodeEntry{nodeID: id, isPunched: false}
	}
	// Add 2 punched members at distances 100 and 101 (farther than all direct nodes).
	var p1, p2 a2al.NodeID
	p1[31] = 100
	p2[31] = 101
	rs.nodes[nodeIDKey(p1)] = &repNodeEntry{nodeID: p1, isPunched: true}
	rs.nodes[nodeIDKey(p2)] = &repNodeEntry{nodeID: p2, isPunched: true}

	// Quality candidate: NodeID at XOR distance 1 from key (closer than punched
	// nodes at 100/101).  Bind an anchor so reachProfile returns ReachPublic
	// (prefersICEOverColdUDP = false) — simulating a reclassified-as-direct node.
	var closeID a2al.NodeID
	closeID[31] = 1
	n.BindPeerAnchor(closeID, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 4121})
	qualityNI := protocol.NodeInfo{NodeID: append([]byte(nil), closeID[:]...)}

	existing := make(map[string]struct{})
	for k := range rs.nodes {
		existing[k] = struct{}{}
	}

	direct, _ := n.pickGapFillPeers(key, rs,
		[]protocol.NodeInfo{qualityNI}, // directPool: only the quality candidate
		nil,                            // xorPool: not testing NAT track here
		existing,
	)

	if len(direct) != 1 {
		t.Fatalf("direct=%d, want 1 (quality-displacement candidate should be included when XOR-closer than worst punched member)", len(direct))
	}
}
