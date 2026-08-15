// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"net"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

func TestRememberQUICSkipsStable(t *testing.T) {
	n := newHealthTestNode(t)
	logicalAddr, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	anchor := addrV4(4242) // matches makeSignedEndpointRecord quic://10.0.0.1:4242
	n.BindPeerAddr(peerID, anchor)

	iceFrom := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 54321, Zone: "wlan0"}
	dec := &protocol.DecodedMessage{
		Header:     protocol.Header{MsgType: protocol.MsgFindNode},
		SenderAddr: logicalAddr,
	}

	n.remember(iceFrom, inboundChannelQUIC, dec)

	got, ok := n.lookupPeer(peerID)
	if !ok {
		t.Fatal("expected prior live anchor to remain")
	}
	if got.String() != anchor.String() {
		t.Fatalf("lookupPeer = %v, want anchor %v (QUIC must not overwrite live)", got, anchor)
	}
}

func TestRememberQUICSkipsAnchor(t *testing.T) {
	n := newHealthTestNode(t)
	logicalAddr, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	anchor := addrV4(4242)
	n.BindPeerAnchor(peerID, anchor)

	iceFrom := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 54321, Zone: "wlan0"}
	dec := &protocol.DecodedMessage{
		Header:     protocol.Header{MsgType: protocol.MsgFindNode},
		SenderAddr: logicalAddr,
	}

	n.remember(iceFrom, inboundChannelQUIC, dec)

	got, ok := n.lookupPeer(peerID)
	if !ok {
		t.Fatal("expected prior anchor to remain")
	}
	if got.String() != anchor.String() {
		t.Fatalf("lookupPeer = %v, want anchor %v (QUIC must not overwrite anchor)", got, anchor)
	}
}

func TestAdaptNodeInfoPrefersEndpointOverPollutedStable(t *testing.T) {
	n := newHealthTestNode(t)
	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	polluted := &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: 65090, Zone: "eth0"}
	n.BindPeerAddr(peerID, polluted)

	ni := protocol.NodeInfo{
		NodeID: append([]byte(nil), peerID[:]...),
		IP:     net.IPv4(1, 2, 3, 4).To4(),
		Port:   9999,
	}
	got := n.adaptNodeInfoForAsker(ni, peerID, true)
	if got.Port != 4242 {
		t.Fatalf("adapt port = %d, want endpoint anchor 4242", got.Port)
	}
	if !net.IP(got.IP).Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("adapt IP = %v, want 10.0.0.1 from endpoint", net.IP(got.IP))
	}
}

func TestAdaptNodeInfoPrefersRoutingOverPollutedStable(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID a2al.NodeID
	peerID[0] = 0xAB

	polluted := addrV4(65090)
	n.BindPeerAddr(peerID, polluted)

	ni := protocol.NodeInfo{
		NodeID: append([]byte(nil), peerID[:]...),
		IP:     net.IPv4(203, 0, 113, 7).To4(),
		Port:   4121,
	}
	got := n.adaptNodeInfoForAsker(ni, peerID, true)
	if got.Port != 4121 || !net.IP(got.IP).Equal(net.IPv4(203, 0, 113, 7)) {
		t.Fatalf("adapt = %v:%d, want routing table 203.0.113.7:4121", net.IP(got.IP), got.Port)
	}
}

func TestAdaptNodeInfoStableFallbackWhenNoEndpointOrRouting(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID a2al.NodeID
	peerID[0] = 0xCD

	stable := addrV4(5001)
	n.BindPeerAddr(peerID, stable)

	ni := protocol.NodeInfo{NodeID: append([]byte(nil), peerID[:]...)}
	got := n.adaptNodeInfoForAsker(ni, peerID, true)
	if got.Port != 5001 {
		t.Fatalf("adapt port = %d, want stable fallback 5001", got.Port)
	}
}

// TestAdaptNodeInfoV6AskerGetsV6 verifies that a v6 asker is not handed a v4
// address that is stored in the routing-table NodeInfo.  The peer is dual-stack
// (v4 in ni.IP, v6 in peerAddrs); the adapted result must use the v6 address.
func TestAdaptNodeInfoV6AskerGetsV6(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID a2al.NodeID
	peerID[0] = 0xEF

	v4addr := addrV4(4121)
	v6addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4121}
	n.BindPeerAddr(peerID, v4addr)
	n.BindPeerAddr(peerID, v6addr)

	// ni.IP carries v4 (as stored from a v4-exchange NodeInfo).
	ni := protocol.NodeInfo{
		NodeID: append([]byte(nil), peerID[:]...),
		IP:     net.IPv4(10, 0, 0, 1).To4(),
		Port:   4121,
	}
	got := n.adaptNodeInfoForAsker(ni, peerID, false) // v6 asker
	if net.IP(got.IP).To4() != nil {
		t.Fatalf("v6 asker received v4 address %v; want v6", net.IP(got.IP))
	}
	if !net.IP(got.IP).Equal(v6addr.IP) {
		t.Fatalf("got IP %v, want %v", net.IP(got.IP), v6addr.IP)
	}
}
