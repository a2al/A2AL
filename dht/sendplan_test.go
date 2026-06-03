// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/transport"
)

type mockPunchHasConn struct {
	mockPunch
	hasConn atomic.Bool
}

func (m *mockPunchHasConn) HasConn(_ a2al.NodeID) bool {
	return m.hasConn.Load()
}

func TestDeliverFlagOffMatchesLegacy(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, _ := netw.NewTransport("del-a")
	trB, _ := netw.NewTransport("del-b")
	defer trA.Close()
	defer trB.Close()

	mock := &mockPunch{sendOK: false}
	nodeA := newTestNode(t, trA, mock)
	nodeA.Start()
	defer nodeA.Close()

	bAddr := trB.LocalAddr()
	var bID a2al.NodeID
	bID[0] = 0xCD
	nodeA.BindPeerAddr(bID, bAddr)

	payload := []byte("legacy-path")
	_, err := nodeA.deliver(context.Background(), bID, bAddr, payload)
	if err != nil {
		t.Fatal(err)
	}

	pkt, _, err := trB.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt) != string(payload) {
		t.Fatalf("got %q want %q", pkt, payload)
	}
}

func TestOutboundPlanPrefersHasConn(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, _ := netw.NewTransport("qc-a")
	defer trA.Close()

	mock := &mockPunchHasConn{mockPunch: mockPunch{sendOK: true}}
	mock.hasConn.Store(true)
	nodeA := newTestNode(t, trA, mock)
	nodeA.SetLearnedPathFirst(true)

	var peerID a2al.NodeID
	peerID[0] = 0x11

	plan := nodeA.outboundPlan(peerID, nil, false)
	if plan.transport != sendTransportQUIC || plan.reason != "has_conn" {
		t.Fatalf("plan = %+v, want QUIC has_conn", plan)
	}

	_, err := nodeA.deliver(context.Background(), peerID, nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&mock.sendCalls) != 1 {
		t.Fatalf("SendTo calls = %d, want 1", mock.sendCalls)
	}
}

func TestOutboundPlanLastInbound(t *testing.T) {
	nodeA := newHealthTestNode(t)
	nodeA.SetLearnedPathFirst(true)

	var peerID a2al.NodeID
	peerID[0] = 0x22
	inbound := addrV4(55106)
	nodeA.setLastInbound(peerID, inbound)

	plan := nodeA.outboundPlan(peerID, inbound, false)
	if plan.transport != sendTransportUDP || plan.reason != "last_inbound" {
		t.Fatalf("plan = %+v, want last_inbound UDP", plan)
	}
	if plan.addr.String() != inbound.String() {
		t.Fatalf("plan.addr = %v, want %v", plan.addr, inbound)
	}
}

func TestOutboundPlanSkipsHairpinLastInbound(t *testing.T) {
	nodeA := newHealthTestNode(t)
	nodeA.SetLearnedPathFirst(true)
	nodeA.SetSelfExtIP(net.IPv4(47, 74, 189, 180))

	var peerID a2al.NodeID
	peerID[0] = 0x22
	hairpin := &net.UDPAddr{IP: net.IPv4(47, 74, 189, 180), Port: 65090}
	stable := addrV4(4121)
	nodeA.setLastInbound(peerID, hairpin)
	nodeA.BindPeerAddr(peerID, stable)

	plan := nodeA.outboundPlan(peerID, stable, false)
	if plan.reason == "last_inbound" {
		t.Fatalf("plan = %+v, hairpin lastInbound must not be selected", plan)
	}
	if plan.reason != "l0_health_aware" && plan.reason != "l0_stable" {
		t.Fatalf("plan = %+v, want L0 fallback past hairpin lastInbound", plan)
	}
}

func TestDeliverUsesL0PastHairpinLastInbound(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, _ := netw.NewTransport("hp-del-a")
	trB, _ := netw.NewTransport("hp-del-b")
	defer trA.Close()
	defer trB.Close()

	nodeA := newTestNode(t, trA, nil)
	nodeA.SetLearnedPathFirst(true)
	nodeA.SetSelfExtIP(net.IPv4(47, 74, 189, 180))

	var peerID a2al.NodeID
	peerID[0] = 0x99
	nodeA.BindPeerAddr(peerID, trB.LocalAddr())

	hairpin := &net.UDPAddr{IP: net.IPv4(47, 74, 189, 180), Port: 65090}
	nodeA.setLastInbound(peerID, hairpin)

	plan := nodeA.outboundPlan(peerID, hairpin, false)
	if plan.reason == "last_inbound" {
		t.Fatalf("plan = %+v, must not use hairpin lastInbound", plan)
	}

	payload := []byte("l0-past-hairpin")
	_, err := nodeA.deliver(context.Background(), peerID, hairpin, payload)
	if err != nil {
		t.Fatal(err)
	}
	pkt, _, err := trB.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt) != string(payload) {
		t.Fatalf("got %q want %q", pkt, payload)
	}
}

// TestReplyViaIsFaithfulToInboundSource verifies that a UDP-channel reply
// goes back to the exact datagram source, never to the peer's remembered anchor
// or advertised endpoint. This is the request/response invariant: the reverse
// path is proven reachable by the inbound packet, so no outbound path selection
// (anchor / health-aware / skip-cold) may redirect the reply.
func TestReplyViaIsFaithfulToInboundSource(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, _ := netw.NewTransport("rep-faithful-a")
	trSrc, _ := netw.NewTransport("rep-faithful-src")    // actual inbound source
	trAnchor, _ := netw.NewTransport("rep-faithful-anch") // stale remembered addr
	defer trA.Close()
	defer trSrc.Close()
	defer trAnchor.Close()

	nodeA := newTestNode(t, trA, nil)
	nodeA.SetLearnedPathFirst(true)

	peerAddr, peerID, _ := makeSignedEndpointRecord(t, "wss://signal.example.com")
	// The peer's remembered/anchor address points at trAnchor, NOT the source
	// the request actually arrived from. A faithful reply must ignore it.
	nodeA.BindPeerAddr(peerID, trAnchor.LocalAddr())

	req := &protocol.DecodedMessage{
		Header:     protocol.Header{MsgType: protocol.MsgPing, TxID: []byte{1, 2, 3, 4}},
		SenderAddr: peerAddr,
	}
	raw := []byte("faithful-reply")
	if err := nodeA.replyVia(trSrc.LocalAddr(), inboundChannelUDP, req, raw); err != nil {
		t.Fatal(err)
	}
	pkt, _, err := trSrc.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt) != string(raw) {
		t.Fatalf("got %q want %q", pkt, raw)
	}
}

func TestDeliverViaHasConnSetsViaQUICMeta(t *testing.T) {
	netw := transport.NewMemNetwork()
	trA, _ := netw.NewTransport("meta-a")
	defer trA.Close()

	mock := &mockPunchHasConn{mockPunch: mockPunch{sendOK: true}}
	mock.hasConn.Store(true)
	nodeA := newTestNode(t, trA, mock)
	nodeA.SetLearnedPathFirst(true)

	var peerID a2al.NodeID
	peerID[0] = 0x33
	meta, err := nodeA.deliver(context.Background(), peerID, addrV4(4121), []byte("q"))
	if err != nil {
		t.Fatal(err)
	}
	if !meta.viaQUIC {
		t.Fatal("expected viaQUIC meta for HasConn deliver")
	}
}

func TestOutboundPlanFamilyHintIgnoresOtherFamily(t *testing.T) {
	nodeA := newHealthTestNode(t)
	nodeA.SetLearnedPathFirst(true)

	var peerID a2al.NodeID
	peerID[0] = 0x77

	v4Inbound := addrV4(55106)
	v6Inbound := addrV6(55107)
	nodeA.setLastInbound(peerID, v4Inbound)
	nodeA.setLastInbound(peerID, v6Inbound)

	key := nodeIDKey(peerID)
	nodeA.healthMu.Lock()
	e := nodeA.health[key]
	e.v6.lastInboundAt = e.v4.lastInboundAt.Add(time.Second)
	nodeA.healthMu.Unlock()

	plan := nodeA.outboundPlan(peerID, addrV4(4121), false)
	if plan.reason != "last_inbound" || plan.addr.String() != v4Inbound.String() {
		t.Fatalf("expected v4 last_inbound, got %+v", plan)
	}
}

func TestOutboundPlanV6SkipColdDoesNotDeferV4(t *testing.T) {
	nodeA := newHealthTestNode(t)
	nodeA.SetLearnedPathFirst(true)

	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := nodeA.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	stableV4 := addrV4(4121)
	nodeA.BindPeerAddr(peerID, stableV4)

	key := nodeIDKey(peerID)
	nodeA.healthMu.Lock()
	e := &peerHealthEntry{}
	e.v6.skipColdUDP = true
	nodeA.health[key] = e
	nodeA.healthMu.Unlock()

	plan := nodeA.outboundPlan(peerID, stableV4, false)
	if plan.transport == sendTransportDeferICE {
		t.Fatalf("v6 skipCold must not defer v4-targeted plan, got %+v", plan)
	}
}

func TestOutboundPlanReplansAfterHasConnLost(t *testing.T) {
	nodeA := newHealthTestNode(t)
	nodeA.SetLearnedPathFirst(true)

	mock := &mockPunchHasConn{mockPunch: mockPunch{sendOK: true}}
	mock.hasConn.Store(true)
	nodeA.punch = mock

	var peerID a2al.NodeID
	peerID[0] = 0x88
	inbound := addrV4(55106)
	nodeA.setLastInbound(peerID, inbound)

	plan := nodeA.outboundPlan(peerID, inbound, false)
	if plan.transport != sendTransportQUIC {
		t.Fatalf("first plan = %+v, want QUIC", plan)
	}

	mock.hasConn.Store(false)
	plan = nodeA.outboundPlan(peerID, inbound, false)
	if plan.reason != "last_inbound" || plan.addr.String() != inbound.String() {
		t.Fatalf("replanned to %+v, want last_inbound via %v", plan, inbound)
	}
}

func TestMaybeWaitRepSetPunchBypassesBackoff(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetLearnedPathFirst(true)
	mock := &mockPunch{}
	n.punch = mock

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

	stable := addrV4(4121)
	n.BindPeerAddr(peerID, stable)

	key := nodeIDKey(peerID)
	n.healthMu.Lock()
	e := &peerHealthEntry{}
	e.v4.everUsed = true
	e.v4.skipColdUDP = true
	e.v4.nextRetryAt = time.Now().Add(time.Minute) // below punchMinBackoff gate
	n.health[key] = e
	n.healthMu.Unlock()

	rs := &repSet{
		nodes: map[string]*repNodeEntry{
			nodeIDKey(peerID): {nodeID: peerID},
		},
	}
	n.maybeWaitRepSetPunch(context.Background(), peerID, rs, stable)

	if atomic.LoadInt32(&mock.punchCalls) != 1 {
		t.Fatalf("punchCalls = %d, want 1 (bypassBackoff for repSet)", mock.punchCalls)
	}
}

func TestLogDeliverPlanIfChanged_SkipsRoutineReasons(t *testing.T) {
	nodeA := newHealthTestNode(t)
	var peerID a2al.NodeID
	peerID[0] = 0x99
	addr := addrV4(4121)
	key := nodeIDKey(peerID)

	for _, reason := range []string{"last_inbound", "l0_stable", "l0_health_aware", "has_conn"} {
		plan := sendPlan{transport: sendTransportUDP, addr: addr, reason: reason}
		nodeA.logDeliverPlanIfChanged(peerID, plan, addr)
	}

	nodeA.deliverPlanLogMu.Lock()
	_, ok := nodeA.deliverPlanLogged[key]
	nodeA.deliverPlanLogMu.Unlock()
	if ok {
		t.Fatal("routine plan reasons must not be recorded")
	}
}

func TestLogDeliverPlanIfChanged_SuppressesStableBlockingPlan(t *testing.T) {
	nodeA := newHealthTestNode(t)
	var peerID a2al.NodeID
	peerID[0] = 0xAA
	plan := sendPlan{transport: sendTransportDeferICE, reason: "skip_cold_ice"}

	nodeA.logDeliverPlanIfChanged(peerID, plan, nil)
	key := nodeIDKey(peerID)
	nodeA.deliverPlanLogMu.Lock()
	sig, ok := nodeA.deliverPlanLogged[key]
	nodeA.deliverPlanLogMu.Unlock()
	if !ok || sig != sendPlanLogSig(plan) {
		t.Fatalf("first blocking plan not recorded: ok=%v sig=%q", ok, sig)
	}

	nodeA.logDeliverPlanIfChanged(peerID, plan, nil)
	nodeA.deliverPlanLogMu.Lock()
	sig2 := nodeA.deliverPlanLogged[key]
	nodeA.deliverPlanLogMu.Unlock()
	if sig2 != sig {
		t.Fatalf("stable blocking plan should not update signature: %q -> %q", sig, sig2)
	}
}

func TestLogDeliverPlanIfChanged_LogsBlockingReasonTransition(t *testing.T) {
	nodeA := newHealthTestNode(t)
	var peerID a2al.NodeID
	peerID[0] = 0xAC
	addr := addrV4(4121)

	nodeA.logDeliverPlanIfChanged(peerID, sendPlan{transport: sendTransportDeferICE, reason: "skip_cold_ice"}, addr)
	nodeA.logDeliverPlanIfChanged(peerID, sendPlan{transport: sendTransportUDP, reason: "l0_no_addr"}, nil)

	key := nodeIDKey(peerID)
	nodeA.deliverPlanLogMu.Lock()
	sig := nodeA.deliverPlanLogged[key]
	nodeA.deliverPlanLogMu.Unlock()
	if sig != sendPlanLogSig(sendPlan{transport: sendTransportUDP, reason: "l0_no_addr"}) {
		t.Fatalf("logged sig = %q, want l0_no_addr sig", sig)
	}
}

func TestLogDeliverPlanIfChanged_AlwaysLogsNoAddr(t *testing.T) {
	nodeA := newHealthTestNode(t)
	var peerID a2al.NodeID
	peerID[0] = 0xAB
	plan := sendPlan{transport: sendTransportUDP, reason: "l0_no_addr"}

	nodeA.logDeliverPlanIfChanged(peerID, plan, nil)
	nodeA.logDeliverPlanIfChanged(peerID, plan, nil)

	key := nodeIDKey(peerID)
	nodeA.deliverPlanLogMu.Lock()
	_, ok := nodeA.deliverPlanLogged[key]
	nodeA.deliverPlanLogMu.Unlock()
	if !ok {
		t.Fatal("l0_no_addr should be recorded")
	}
}

func TestDeliverPlanWorthLogging(t *testing.T) {
	if !deliverPlanWorthLogging("skip_cold_ice") || !deliverPlanWorthLogging("l0_no_addr") {
		t.Fatal("blocking reasons should be worth logging")
	}
	for _, reason := range []string{"has_conn", "last_inbound", "l0_health_aware", "l0_stable", ""} {
		if deliverPlanWorthLogging(reason) {
			t.Fatalf("routine reason %q should not be worth logging", reason)
		}
	}
}

// TestOutboundPlanWarmPrefersVerifiedLive verifies that warm=true causes
// outboundPlan to prefer a recently-verified live address over the anchor
// for ReachPublic peers.
func TestOutboundPlanWarmPrefersVerifiedLive(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetLearnedPathFirst(true)

	var peerID a2al.NodeID
	peerID[0] = 0xAB

	anchor := addrV4(4121)
	live := addrV4(55200) // different port = different path from anchor

	// Register anchor so reachProfile returns ReachPublic.
	n.BindPeerAnchor(peerID, anchor)

	// Register a fresh verified-live address (mimics a successful RPC).
	n.peerMu.Lock()
	key := nodeIDKey(peerID)
	if n.peers[key] == nil {
		n.peers[key] = &peerAddrs{}
	}
	n.peers[key].v4.tryLive(live, rankVerified)
	n.peerMu.Unlock()

	// cold: should use anchor
	coldPlan := n.outboundPlan(peerID, nil, false)
	if coldPlan.reason != "l0_public_anchor" {
		t.Fatalf("cold plan reason = %q, want l0_public_anchor", coldPlan.reason)
	}

	// warm: should prefer verified live
	warmPlan := n.outboundPlan(peerID, nil, true)
	if warmPlan.reason != "l1_warm_live" {
		t.Fatalf("warm plan reason = %q, want l1_warm_live", warmPlan.reason)
	}
	if warmPlan.addr.String() != live.String() {
		t.Fatalf("warm plan addr = %v, want live %v", warmPlan.addr, live)
	}
}

// TestOutboundPlanWarmFallsBackToAnchorWhenNoLive verifies that warm=true
// falls back to anchor when no fresh verified live is available.
func TestOutboundPlanWarmFallsBackToAnchorWhenNoLive(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetLearnedPathFirst(true)

	var peerID a2al.NodeID
	peerID[0] = 0xAC

	anchor := addrV4(4121)
	n.BindPeerAnchor(peerID, anchor)

	// No live address set — warm should fall back to anchor.
	plan := n.outboundPlan(peerID, nil, true)
	if plan.reason != "l0_public_anchor" {
		t.Fatalf("warm plan reason = %q, want l0_public_anchor (no live available)", plan.reason)
	}
	if plan.addr.String() != anchor.String() {
		t.Fatalf("warm plan addr = %v, want anchor %v", plan.addr, anchor)
	}
}

// TestOutboundPlanWarmPrefersLastInboundOverAnchor verifies that warm=true
// uses fresh lastInbound (non-hairpin) before anchor when no verified live.
func TestOutboundPlanWarmPrefersLastInboundOverAnchor(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetLearnedPathFirst(true)

	var peerID a2al.NodeID
	peerID[0] = 0xAD

	anchor := addrV4(4121)
	inbound := addrV4(55300)
	n.BindPeerAnchor(peerID, anchor)
	n.setLastInbound(peerID, inbound)

	plan := n.outboundPlan(peerID, nil, true)
	if plan.reason != "l1_warm_inbound" {
		t.Fatalf("warm plan reason = %q, want l1_warm_inbound", plan.reason)
	}
	if plan.addr.String() != inbound.String() {
		t.Fatalf("warm plan addr = %v, want inbound %v", plan.addr, inbound)
	}
}

func TestDeliverPathLabel(t *testing.T) {
	if got := deliverPathLabel(deliverMeta{viaQUIC: true, reason: "has_conn"}); got != "quic/has_conn" {
		t.Fatalf("got %q", got)
	}
	if got := deliverPathLabel(deliverMeta{reason: "l0_public_anchor"}); got != "udp/l0_public_anchor" {
		t.Fatalf("got %q", got)
	}
	if got := deliverPathLabel(deliverMeta{}); got != "udp" {
		t.Fatalf("got %q", got)
	}
}
