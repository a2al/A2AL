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
