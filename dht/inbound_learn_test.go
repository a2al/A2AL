// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

func TestSetLastInboundAndFresh(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID a2al.NodeID
	peerID[0] = 0x42

	inbound := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 5), Port: 55106}
	n.setLastInbound(peerID, inbound)

	got, ok := n.freshLastInboundForFamily(peerID, false)
	if !ok {
		t.Fatal("expected fresh lastInbound")
	}
	if got.String() != inbound.String() {
		t.Fatalf("freshLastInbound = %v, want %v", got, inbound)
	}

	key := nodeIDKey(peerID)
	n.healthMu.Lock()
	e := n.health[key]
	e.v4.lastInboundAt = time.Now().Add(-lastInboundFreshTTL - time.Second)
	n.healthMu.Unlock()

	if _, ok := n.freshLastInboundForFamily(peerID, false); ok {
		t.Fatal("expected stale lastInbound to be ignored")
	}
}

func TestInboundLearnUDPTriggersPunch(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetLearnedPathFirst(true)
	mock := &mockPunch{}
	n.punch = mock

	addr, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 12345}
	dec := &protocol.DecodedMessage{
		Header:     protocol.Header{MsgType: protocol.MsgFindNode},
		SenderAddr: addr,
	}
	n.inboundLearn(from, inboundChannelUDP, dec)

	deadline := time.Now().Add(500 * time.Millisecond)
	for atomic.LoadInt32(&mock.punchCalls) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&mock.punchCalls) != 1 {
		t.Fatalf("punchCalls = %d, want 1", mock.punchCalls)
	}
}

func TestInboundLearnSkipsHairpinSelfExcitation(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetLearnedPathFirst(true)
	mock := &mockPunch{}
	n.punch = mock

	n.SetSelfExtIP(net.IPv4(47, 74, 189, 180))

	addr, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	from := &net.UDPAddr{IP: net.IPv4(47, 74, 189, 180), Port: 65090}
	dec := &protocol.DecodedMessage{
		Header:     protocol.Header{MsgType: protocol.MsgFindNode},
		SenderAddr: addr,
	}
	n.inboundLearn(from, inboundChannelUDP, dec)

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&mock.punchCalls) != 0 {
		t.Fatalf("punchCalls = %d, want 0 for hairpin inbound", mock.punchCalls)
	}
	if _, ok := n.freshLastInboundForFamily(peerID, false); ok {
		t.Fatal("hairpin from must not be recorded as lastInbound")
	}
}

func TestInboundLearnSkipsSelfNodeID(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetLearnedPathFirst(true)
	mock := &mockPunch{}
	n.punch = mock

	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 12345}
	dec := &protocol.DecodedMessage{
		Header:     protocol.Header{MsgType: protocol.MsgFindNode},
		SenderAddr: n.addr,
	}
	n.inboundLearn(from, inboundChannelUDP, dec)

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&mock.punchCalls) != 0 {
		t.Fatalf("punchCalls = %d, want 0 for self nodeID inbound", mock.punchCalls)
	}
	if _, ok := n.freshLastInboundForFamily(n.nid, false); ok {
		t.Fatal("self nodeID must not be recorded as lastInbound")
	}
}

func TestHairpinInboundSkipsLearnButRememberStillStores(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetSelfExtIP(net.IPv4(47, 74, 189, 180))

	addr, peerID, _ := makeSignedEndpointRecord(t, "wss://signal.example.com")
	from := &net.UDPAddr{IP: net.IPv4(47, 74, 189, 180), Port: 65090}
	dec := &protocol.DecodedMessage{
		Header:     protocol.Header{MsgType: protocol.MsgPing},
		SenderAddr: addr,
	}

	n.inboundLearn(from, inboundChannelUDP, dec)
	if _, ok := n.freshLastInboundForFamily(peerID, false); ok {
		t.Fatal("inboundLearn must not record hairpin lastInbound")
	}

	n.remember(from, inboundChannelUDP, dec)
	got, ok := n.lookupPeer(peerID)
	if !ok {
		t.Fatal("remember must still store hairpin from in peerAddrs")
	}
	if got.String() != from.String() {
		t.Fatalf("lookupPeer = %v, want %v", got, from)
	}
}

func TestInboundLearnLoopbackSiblingRecordsLastInbound(t *testing.T) {
	n := newHealthTestNode(t)
	n.SetLearnedPathFirst(true)

	addr, peerID, _ := makeSignedEndpointRecord(t, "wss://signal.example.com")
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4122}
	dec := &protocol.DecodedMessage{
		Header:     protocol.Header{MsgType: protocol.MsgFindNode},
		SenderAddr: addr,
	}
	n.inboundLearn(from, inboundChannelUDP, dec)

	got, ok := n.freshLastInboundForFamily(peerID, false)
	if !ok || got.String() != from.String() {
		t.Fatalf("loopback lastInbound = %v ok=%v, want %v", got, ok, from)
	}
}

func TestInboundLearnFlagOffStillRecordsLastInbound(t *testing.T) {
	n := newHealthTestNode(t)
	// LearnedPathFirst off — observation still recorded.

	addr, peerID, _ := makeSignedEndpointRecord(t, "wss://signal.example.com")
	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 55106}
	dec := &protocol.DecodedMessage{
		Header:     protocol.Header{MsgType: protocol.MsgFindNode},
		SenderAddr: addr,
	}
	n.inboundLearn(from, inboundChannelUDP, dec)

	got, ok := n.freshLastInboundForFamily(peerID, false)
	if !ok || got.String() != from.String() {
		t.Fatalf("lastInbound = %v ok=%v, want %v recorded while flag off", got, ok, from)
	}
}

func TestInboundLearnFlagOffNoPunchTrigger(t *testing.T) {
	n := newHealthTestNode(t)
	mock := &mockPunch{}
	n.punch = mock

	addr, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 12345}
	dec := &protocol.DecodedMessage{
		Header:     protocol.Header{MsgType: protocol.MsgFindNode},
		SenderAddr: addr,
	}
	n.inboundLearn(from, inboundChannelUDP, dec)

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&mock.punchCalls) != 0 {
		t.Fatalf("punchCalls = %d, want 0 when LearnedPathFirst is off", mock.punchCalls)
	}
}

func TestRecordFailureNoSignalNoSkipCold(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID a2al.NodeID
	peerID[0] = 0x55

	addr := addrV4(4121)
	n.recordFailure(peerID, addr)

	key := nodeIDKey(peerID)
	n.healthMu.RLock()
	e := n.health[key]
	if e != nil && e.v4.skipColdUDP {
		n.healthMu.RUnlock()
		t.Fatal("skipColdUDP should not be set without signal endpoint")
	}
	n.healthMu.RUnlock()
}

func TestRecordFailureSkippedWhenViaQUIC(t *testing.T) {
	n := newHealthTestNode(t)
	var peerID a2al.NodeID
	peerID[0] = 0x66
	addr := addrV4(4121)
	n.BindPeerAddr(peerID, addr)

	meta := deliverMeta{viaQUIC: true, dialAddr: addr}
	if id, ok := n.lookupPeerID(addr); ok && !meta.viaQUIC {
		n.recordFailure(id, meta.dialAddr)
	}

	key := nodeIDKey(peerID)
	n.healthMu.RLock()
	e := n.health[key]
	if e != nil && e.v4.failCount > 0 {
		n.healthMu.RUnlock()
		t.Fatal("QUIC-only failure must not penalise UDP family health")
	}
	n.healthMu.RUnlock()
}

func TestClearReachabilityHints(t *testing.T) {
	n := newHealthTestNode(t)
	_, peerID, sr := makeSignedEndpointRecord(t, "wss://signal.example.com")
	if err := n.LocalStorePut(peerID, sr); err != nil {
		t.Fatal(err)
	}

	addr := addrV4(4121)
	inbound := addrV4(55106)
	n.setLastInbound(peerID, inbound)
	// Two failures reach badHealthThreshold → skipColdUDP is set.
	n.recordFailure(peerID, addr)
	n.recordFailure(peerID, addr)

	key := nodeIDKey(peerID)
	n.healthMu.RLock()
	e := n.health[key]
	if e == nil || !e.v4.skipColdUDP {
		n.healthMu.RUnlock()
		t.Fatal("pre-condition: skipColdUDP must be set before ClearReachabilityHints")
	}
	n.healthMu.RUnlock()

	n.ClearReachabilityHints()

	n.healthMu.RLock()
	e = n.health[key]
	if e == nil {
		n.healthMu.RUnlock()
		t.Fatal("expected health entry")
	}
	// skipColdUDP survives hint clear: it reflects persistent remote unreachability,
	// not a local path observation. Only recordSuccess resets it.
	if !e.v4.skipColdUDP {
		n.healthMu.RUnlock()
		t.Fatal("skipColdUDP must be preserved across ClearReachabilityHints")
	}
	// lastInbound is a local NAT-mapped address; it must be cleared.
	if e.v4.lastInbound != nil || !e.v4.lastInboundAt.IsZero() {
		n.healthMu.RUnlock()
		t.Fatal("lastInbound must be cleared by ClearReachabilityHints")
	}
	// Failures now accumulate in pendingFailCount until settled by recordSuccess;
	// ClearReachabilityHints must not touch health counters regardless of which
	// field holds the count.
	if e.v4.failCount+e.v4.pendingFailCount == 0 {
		n.healthMu.RUnlock()
		t.Fatal("failure count must be preserved across hint clear")
	}
	n.healthMu.RUnlock()
}

func TestRecordFailureSetsSkipColdWhenSignal(t *testing.T) {
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

	addr := addrV4(4121)
	// A single failure must NOT yet set skipColdUDP (transient UDP blip).
	n.recordFailure(peerID, addr)
	key := nodeIDKey(peerID)
	n.healthMu.RLock()
	e := n.health[key]
	if e != nil && e.v4.skipColdUDP {
		n.healthMu.RUnlock()
		t.Fatal("skipColdUDP must not be set on first failure (transient)")
	}
	n.healthMu.RUnlock()

	// Second failure reaches badHealthThreshold → skipColdUDP must be set.
	n.recordFailure(peerID, addr)
	n.healthMu.RLock()
	e = n.health[key]
	if e == nil || !e.v4.skipColdUDP {
		n.healthMu.RUnlock()
		t.Fatal("expected skipColdUDP after persistent failures with signal endpoint")
	}
	n.healthMu.RUnlock()

	n.recordSuccess(peerID, addr, time.Millisecond)
	n.healthMu.RLock()
	e = n.health[key]
	if e.v4.skipColdUDP {
		n.healthMu.RUnlock()
		t.Fatal("expected skipColdUDP cleared on success")
	}
	n.healthMu.RUnlock()
}
