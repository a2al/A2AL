// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"net"
	"testing"
	"time"

	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
	"github.com/a2al/a2al/transport"
)

func TestAddrAuthority_AnchorWinsOverLive(t *testing.T) {
	pa := &peerAddrs{}
	anchor := addrV4(4121)
	live := addrV4(57691)

	if !pa.tryAnchor(anchor) {
		t.Fatal("tryAnchor failed")
	}
	pa.tryLive(live, rankHearsay)

	if got := pa.preferred(); got.String() != anchor.String() {
		t.Fatalf("preferred = %v, want anchor %v", got, anchor)
	}
}

func TestAddrAuthority_HearsayCannotOverwriteVerifiedLive(t *testing.T) {
	pa := &peerAddrs{}
	verified := addrV4(4121)
	hearsay := addrV4(57691)

	if !pa.tryLive(hearsay, rankHearsay) {
		t.Fatal("hearsay should fill empty live slot")
	}
	if !pa.tryLive(verified, rankVerified) {
		t.Fatal("verified should upgrade hearsay live")
	}
	if pa.tryLive(hearsay, rankHearsay) {
		t.Fatal("hearsay must not overwrite verified live")
	}
	if got := pa.preferred(); got.String() != verified.String() {
		t.Fatalf("preferred = %v, want verified %v", got, verified)
	}
}

func TestAddrAuthority_HearsayCannotTouchAnchor(t *testing.T) {
	pa := &peerAddrs{}
	anchor := addrV4(4121)
	hearsay := addrV4(57691)

	pa.tryAnchor(anchor)
	pa.tryLive(hearsay, rankHearsay)

	if got := pa.preferred(); got.String() != anchor.String() {
		t.Fatalf("preferred = %v, want anchor %v", got, anchor)
	}
}

func TestAddrAuthority_VerifiedUpgradesHearsayLive(t *testing.T) {
	pa := &peerAddrs{}
	hearsay := addrV4(57691)
	verified := addrV4(4121)

	pa.tryLive(hearsay, rankHearsay)
	pa.tryLive(verified, rankVerified)

	if got := pa.preferred(); got.String() != verified.String() {
		t.Fatalf("preferred = %v, want verified %v", got, verified)
	}
}

func TestBindPeerAnchorSurvivesHearsayAbsorb(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID [32]byte
	peerID[0] = 0x01

	anchor := &net.UDPAddr{IP: net.IPv4(34, 97, 51, 15), Port: 4121}
	n.BindPeerAnchor(peerID, anchor)

	ni := protocol.NodeInfo{
		NodeID: append([]byte(nil), peerID[:]...),
		IP:     net.IPv4(34, 97, 51, 15).To4(),
		Port:   57691,
	}
	n.absorbNodeInfo(ni, [32]byte{})

	got, ok := n.lookupPeer(peerID)
	if !ok {
		t.Fatal("lookupPeer failed")
	}
	if got.String() != anchor.String() {
		t.Fatalf("lookupPeer = %v, want anchor %v", got, anchor)
	}
}

func TestTabAdd_NonUDPDirectFrom_DoesNotWriteAnchor(t *testing.T) {
	n := newHealthTestNode(t)
	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	netw := transport.NewMemNetwork()
	memTr, err := netw.NewTransport("mem-peer")
	if err != nil {
		t.Fatal(err)
	}
	defer memTr.Close()

	ni := protocol.NodeInfo{
		NodeID: append([]byte(nil), peerID[:]...),
		IP:     net.IPv4(127, 0, 0, 1).To4(),
		Port:   0,
	}
	n.tabAdd(ni, routing.EntryMeta{VerifiedAt: time.Now()}, memTr.LocalAddr())

	got, ok := n.lookupPeer(peerID)
	if ok && got.String() == "10.0.0.1:4242" {
		t.Fatalf("non-UDP tabAdd must not bind endpoint anchor, got %v", got)
	}
}

func TestTabAdd_UDPDirectFrom_BindsEndpointAnchor(t *testing.T) {
	n := newHealthTestNode(t)
	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	udpFrom := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 57691}
	ni := protocol.NodeInfo{
		NodeID: append([]byte(nil), peerID[:]...),
		IP:     append([]byte(nil), udpFrom.IP...),
		Port:   uint16(udpFrom.Port),
	}
	n.tabAdd(ni, routing.EntryMeta{VerifiedAt: time.Now()}, udpFrom)

	got, ok := n.lookupPeer(peerID)
	if !ok {
		t.Fatal("expected anchor dial address")
	}
	want := "10.0.0.1:4242"
	if got.String() != want {
		t.Fatalf("lookupPeer = %v, want endpoint anchor %s", got, want)
	}
}
