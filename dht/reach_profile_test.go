// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"net"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)

func TestReachProfile_PublicWithAnchorAndSignal(t *testing.T) {
	n := newHealthTestNode(t)
	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}
	n.BindPeerAnchor(peerID, addrV4(4121))

	if got := n.reachProfile(peerID); got != ReachPublic {
		t.Fatalf("reachProfile = %v, want ReachPublic", got)
	}
}

func TestReachProfile_SymmetricNAT(t *testing.T) {
	n := newHealthTestNode(t)
	ks := newMemKS(t)
	now := uint64(time.Now().Unix())
	sr, err := protocol.SignEndpointRecord(ks.priv, ks.addr, protocol.EndpointPayload{
		Endpoints: []string{"quic://10.0.0.1:65090"},
		NatType:   protocol.NATSymmetric,
		Signal:    "wss://signal.example.com",
	}, 1, now, 3600)
	if err != nil {
		t.Fatal(err)
	}
	peerID := a2al.NodeIDFromAddress(ks.addr)
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	if got := n.reachProfile(peerID); got != ReachNAT {
		t.Fatalf("reachProfile = %v, want ReachNAT", got)
	}
}

func TestOutboundPlan_PublicPrefersAnchorOverLastInbound(t *testing.T) {
	n := newHealthTestNode(t)
	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}
	anchor := addrV4(4121)
	n.BindPeerAnchor(peerID, anchor)
	n.setLastInbound(peerID, addrV4(57691))
	n.SetLearnedPathFirst(true)

	plan := n.outboundPlan(peerID, nil, false)
	if plan.reason != "l0_public_anchor" {
		t.Fatalf("reason = %q, want l0_public_anchor", plan.reason)
	}
	if plan.addr.String() != anchor.String() {
		t.Fatalf("addr = %v, want anchor %v", plan.addr, anchor)
	}
}

func TestShouldDeferICE_PublicDoesNotSkipColdUDP(t *testing.T) {
	n := newHealthTestNode(t)
	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}
	n.BindPeerAnchor(peerID, addrV4(4121))

	n.recordFailure(peerID, addrV4(57691))

	if n.shouldDeferICEForFamily(peerID, false) {
		t.Fatal("public peer must not defer ICE over cold UDP anchor")
	}
}

func TestRecordSuccess_UpgradesLiveVerified(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID [32]byte
	peerID[0] = 0x42

	hearsay := addrV4(57691)
	n.bindPeerLive(peerID, hearsay, rankHearsay)

	verified := addrV4(4121)
	n.recordSuccess(peerID, verified, time.Millisecond)

	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(peerID)]
	n.peerMu.Unlock()
	if pa == nil || pa.v4.live == nil {
		t.Fatal("expected live slot")
	}
	if pa.v4.liveRank != rankVerified {
		t.Fatalf("liveRank = %v, want Verified", pa.v4.liveRank)
	}
	if pa.v4.live.String() != verified.String() {
		t.Fatalf("live = %v, want %v", pa.v4.live, verified)
	}
}

func TestPublicStableDialAddr_PrefersAnchorOverLive(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID [32]byte
	peerID[0] = 0x43

	anchor := addrV4(4121)
	live := addrV4(57691)
	n.BindPeerAnchor(peerID, anchor)
	n.bindPeerLive(peerID, live, rankVerified)

	got := n.publicStableDialAddr(peerID, false)
	if got == nil || got.String() != anchor.String() {
		t.Fatalf("publicStableDialAddr = %v, want anchor %v", got, anchor)
	}
}

func TestReachProfile_UnknownWithoutEvidence(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID [32]byte
	peerID[0] = 0x44

	if got := n.reachProfile(peerID); got != ReachUnknown {
		t.Fatalf("reachProfile = %v, want ReachUnknown", got)
	}
}

func TestReachProfile_PublicFromAdvertisedEndpoint(t *testing.T) {
	n := newHealthTestNode(t)
	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	if got := n.reachProfile(peerID); got != ReachPublic {
		t.Fatalf("reachProfile = %v, want ReachPublic from endpoint", got)
	}
}

func TestReachProfile_NATSignalWithoutStableQUIC(t *testing.T) {
	n := newHealthTestNode(t)
	ks := newMemKS(t)
	now := uint64(time.Now().Unix())
	sr, err := protocol.SignEndpointRecord(ks.priv, ks.addr, protocol.EndpointPayload{
		NatType: protocol.NATRestricted,
		Signal:  "wss://signal.example.com",
	}, 1, now, 3600)
	if err != nil {
		t.Fatal(err)
	}
	peerID := a2al.NodeIDFromAddress(ks.addr)
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	if got := n.reachProfile(peerID); got != ReachNAT {
		t.Fatalf("reachProfile = %v, want ReachNAT for signal-only endpoint", got)
	}
}

func TestBootstrapCandidateAddrs_SkipsEphemeral(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID [32]byte
	peerID[0] = 0x55

	anchor := addrV4(4121)
	ephemeral := addrV4(57691)
	n.BindPeerAnchor(peerID, anchor)
	n.bindPeerLive(peerID, ephemeral, rankVerified)
	n.peers[nodeIDKey(peerID)].v4.tryEphemeral(ephemeral)

	ni := protocol.NodeInfo{
		NodeID: append([]byte(nil), peerID[:]...),
		IP:     net.IPv4(10, 0, 0, 1).To4(),
		Port:   57691,
	}
	n.tabMu.Lock()
	n.table.Add(ni, routing.EntryMeta{VerifiedAt: time.Now()}, time.Now())
	n.tabMu.Unlock()

	addrs := n.BootstrapCandidateAddrs(8)
	if len(addrs) != 1 {
		t.Fatalf("BootstrapCandidateAddrs = %v, want 1 entry", addrs)
	}
	if addrs[0].String() != anchor.String() {
		t.Fatalf("bootstrap addr = %v, want anchor %v", addrs[0], anchor)
	}
}

func TestRememberStoreSuccess_RegistersAddrToID(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID [32]byte
	peerID[0] = 0x66

	dial := addrV4(4242)
	n.rememberStoreSuccess(peerID, dial)

	got, ok := n.lookupPeerID(dial)
	if !ok || got != peerID {
		t.Fatalf("lookupPeerID(%v) = %v, ok=%v, want %v", dial, got, ok, peerID)
	}
}
