// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/transport"
)

func TestExecRepProbe_hasConnShortCircuit(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("probe-hasconn")
	defer tr.Close()

	mock := &mockPunchHasConn{}
	mock.hasConn.Store(true)
	n := newTestNode(t, tr, mock)
	n.Start()
	defer n.Close()

	id, sr := symNATRecord(t, "ws://sig/ice")
	n.LocalStorePut(id, sr)

	out := n.execRepProbe(context.Background(), id)
	if !out.iceConnOK {
		t.Fatalf("iceConnOK=false, want short-circuit success")
	}
	if out.probeSkip || out.noAddr || out.err != nil {
		t.Fatalf("unexpected outcome: skip=%v noAddr=%v err=%v", out.probeSkip, out.noAddr, out.err)
	}
	if atomic.LoadInt32(&mock.punchCalls) != 0 {
		t.Fatalf("punchCalls=%d, want 0", mock.punchCalls)
	}
}

func TestExecRepProbe_natWithoutConnPingsUDP(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("probe-nat-udp")
	defer tr.Close()

	mock := &mockPunch{}
	n := newTestNode(t, tr, mock)
	n.Start()
	defer n.Close()

	id, sr := symNATRecord(t, "ws://sig/ice")
	n.LocalStorePut(id, sr)
	n.BindPeerAddr(id, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 4121})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := n.execRepProbe(ctx, id)
	if out.iceConnOK || out.probeSkip || out.punchAttempted {
		t.Fatalf("want UDP probe, got iceOK=%v skip=%v punch=%v", out.iceConnOK, out.probeSkip, out.punchAttempted)
	}
	if out.noAddr {
		t.Fatal("noAddr=true, bound peer should be dialable")
	}
	if out.err == nil {
		t.Fatal("cancelled Ping should fail")
	}
	if atomic.LoadInt32(&mock.punchCalls) != 0 {
		t.Fatalf("punchCalls=%d, want 0 (no probe-entry High punch)", mock.punchCalls)
	}
}

func TestApplyRepProbe_deferredOnceThenGrace(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("probe-defer")
	defer tr.Close()
	n := newTestNode(t, tr, &mockPunch{})

	var id a2al.NodeID
	id[0] = 0x11
	now := time.Now()
	e := &repNodeEntry{
		nodeID:      id,
		confirmedAt: now,
		failCount:   badHealthThreshold - 1,
	}
	rs := makeRepSet(id, e)
	rs.renewEpoch = now.Add(-time.Minute)
	rk := repKey{storeKey: id, publisher: n.nid}
	fail := repProbeExecOutcome{err: errors.New("timeout")}

	n.applyRepProbeOutcome(context.Background(), rk, rs, e, fail)
	if e.probeDeferred != true || e.failCount != 1 || !e.badSince.IsZero() {
		t.Fatalf("first threshold: deferred=%v failCount=%d badSince=%v", e.probeDeferred, e.failCount, e.badSince)
	}
	if _, ok := rs.nodes[nodeIDKey(id)]; !ok {
		t.Fatal("deferred node must stay in repSet")
	}

	n.applyRepProbeOutcome(context.Background(), rk, rs, e, fail)
	if e.probeDeferred != true || e.badSince.IsZero() {
		t.Fatalf("second threshold: deferred=%v badSince=%v, want grace", e.probeDeferred, e.badSince)
	}
	if _, ok := rs.nodes[nodeIDKey(id)]; !ok {
		t.Fatal("grace must not evict")
	}
}

func TestApplyRepProbe_successClearsDeferred(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("probe-ok")
	defer tr.Close()
	n := newTestNode(t, tr, &mockPunch{})

	var id a2al.NodeID
	id[0] = 0x22
	e := &repNodeEntry{
		nodeID:         id,
		failCount:      1,
		probeDeferred:  true,
		nextProbeDelay: probeInitDelay,
	}
	rs := makeRepSet(id, e)
	rk := repKey{storeKey: id, publisher: n.nid}

	n.applyRepProbeOutcome(context.Background(), rk, rs, e, repProbeExecOutcome{})
	if e.failCount != 0 || e.probeDeferred || !e.badSince.IsZero() {
		t.Fatalf("success: failCount=%d deferred=%v badSince=%v", e.failCount, e.probeDeferred, e.badSince)
	}
}

func TestGraceBlocksRenewal_hasConnAllowsStoreAt(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("grace-renew")
	defer tr.Close()

	mock := &mockPunchHasConn{}
	n := newTestNode(t, tr, mock)
	e := &repNodeEntry{badSince: time.Now()}

	if !n.graceBlocksRenewal(e) {
		t.Fatal("grace without HasConn must block renewal")
	}
	mock.hasConn.Store(true)
	if n.graceBlocksRenewal(e) {
		t.Fatal("grace with HasConn must allow StoreAt")
	}
	e.badSince = time.Time{}
	if n.graceBlocksRenewal(e) {
		t.Fatal("healthy replica must not be blocked")
	}
}

func TestRunHealthProbes_graceHasConnProbesEarly(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("grace-probe-early")
	defer tr.Close()

	mock := &mockPunchHasConn{}
	mock.hasConn.Store(true)
	n := newTestNode(t, tr, mock)

	var id a2al.NodeID
	id[0] = 0x33
	e := &repNodeEntry{
		nodeID:      id,
		badSince:    time.Now(),
		failCount:   badHealthThreshold,
		nextProbeAt: time.Now().Add(probeBadDelay),
	}
	rk := repKey{storeKey: id, publisher: n.nid}
	rs := n.getOrCreateRepSet(rk)
	rs.mu.Lock()
	rs.nodes[nodeIDKey(id)] = e
	rs.mu.Unlock()

	n.runHealthProbes(context.Background())
	if !e.badSince.IsZero() || e.failCount != 0 {
		t.Fatalf("HasConn grace probe: badSince=%v failCount=%d", e.badSince, e.failCount)
	}
}

func TestRunHealthProbes_graceWithoutConnWaits(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, _ := netw.NewTransport("grace-probe-wait")
	defer tr.Close()

	n := newTestNode(t, tr, &mockPunch{})
	var id a2al.NodeID
	id[0] = 0x44
	e := &repNodeEntry{
		nodeID:      id,
		badSince:    time.Now(),
		failCount:   badHealthThreshold,
		nextProbeAt: time.Now().Add(probeBadDelay),
	}
	rk := repKey{storeKey: id, publisher: n.nid}
	rs := n.getOrCreateRepSet(rk)
	rs.mu.Lock()
	rs.nodes[nodeIDKey(id)] = e
	rs.mu.Unlock()

	n.runHealthProbes(context.Background())
	if e.badSince.IsZero() || e.failCount != badHealthThreshold {
		t.Fatalf("grace without HasConn must wait: badSince=%v failCount=%d", e.badSince, e.failCount)
	}
}
