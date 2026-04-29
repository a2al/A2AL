// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

// fake_punch.go — in-memory PunchTransport for integration testing.
//
// FakePunchNetwork provides a shared registry of DHT nodes.
// FakePunchTransport wraps it and implements PunchTransport.
//
// # Simulated ICE behaviour
//
//   - Punch(nodeID, …)  : immediately reports success to both sides via
//     OnPunchComplete(…, true).  No real ICE or QUIC is performed.
//   - SendTo(ctx, nodeID, msg): delivers msg synchronously by calling
//     InjectReceived on the remote node.  Returns ok=false when the
//     remote node is not registered (caller falls back to UDP).
//
// # Usage pattern
//
//	punchNet := NewFakePunchNetwork()
//
//	ksA := newMemKS(t)
//	nidA := a2al.NodeIDFromAddress(ksA.addr)
//	ptA := punchNet.NewTransport(nidA, trA.LocalAddr())
//	nodeA, _ := NewNode(Config{…, PunchTransport: ptA})
//	ptA.Bind(nodeA)   // wire transport ↔ node
//
//	// same for nodeB / ptB
//
// After Bind, Punch and SendTo are fully functional.

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// fakePeerEntry holds all information FakePunchNetwork needs for one node.
type fakePeerEntry struct {
	addr        net.Addr     // MemTransport address for InjectReceived delivery
	fakeAddr    *net.UDPAddr // synthesised UDP address passed to OnPunchComplete (valid IP/Port)
	logicalAddr a2al.Address // a2al.Address of the node; set by FakePunchTransport.Bind
	node        *Node        // set by FakePunchTransport.Bind; nil until then
}

// FakePunchNetwork is a shared peer registry for FakePunchTransport.
// Create once and share across all nodes that should be able to "punch" each other.
//
// Each registered node is assigned a unique fake *net.UDPAddr so that
// OnPunchComplete can populate NodeInfo.IP/Port correctly and protocol
// marshalling succeeds.  The actual in-process delivery still uses the
// MemTransport address via InjectReceived.
type FakePunchNetwork struct {
	mu      sync.Mutex
	peers   map[a2al.NodeID]*fakePeerEntry
	counter int32 // atomic; incremented per NewTransport call
}

// NewFakePunchNetwork creates an empty in-memory punch network.
func NewFakePunchNetwork() *FakePunchNetwork {
	return &FakePunchNetwork{peers: make(map[a2al.NodeID]*fakePeerEntry)}
}

// NewTransport registers nodeID at addr and returns a FakePunchTransport for
// that node.  Call Bind(node) on the returned transport after creating the Node
// so that Punch and SendTo can call OnPunchComplete / InjectReceived.
func (fn *FakePunchNetwork) NewTransport(nodeID a2al.NodeID, addr net.Addr) *FakePunchTransport {
	idx := atomic.AddInt32(&fn.counter, 1)
	fakeAddr := &net.UDPAddr{
		IP:   net.IP{127, 0, byte(idx >> 8), byte(idx)},
		Port: 10000 + int(idx),
	}
	fn.mu.Lock()
	fn.peers[nodeID] = &fakePeerEntry{addr: addr, fakeAddr: fakeAddr}
	fn.mu.Unlock()
	return &FakePunchTransport{
		network:      fn,
		selfNID:      nodeID,
		selfAddr:     addr,
		selfFakeAddr: fakeAddr,
	}
}

// FakePunchTransport implements dht.PunchTransport using in-memory delivery.
// Obtain via FakePunchNetwork.NewTransport; call Bind before use.
type FakePunchTransport struct {
	network      *FakePunchNetwork
	selfNID      a2al.NodeID
	selfAddr     net.Addr     // MemTransport address — used as "from" in InjectReceived
	selfFakeAddr *net.UDPAddr // fake UDP address — used in OnPunchComplete for IP/Port

	mu   sync.Mutex
	self *Node // set by Bind
}

// Bind wires the transport to its owning Node.  Must be called after
// NewNode so that OnPunchComplete and InjectReceived are available.
// Also records the node's logical Address so Punch can supply it to
// OnPunchComplete (required to build a valid NodeInfo for routing).
func (t *FakePunchTransport) Bind(node *Node) {
	t.mu.Lock()
	t.self = node
	t.mu.Unlock()

	logicalAddr := node.Address()
	t.network.mu.Lock()
	if pe, ok := t.network.peers[t.selfNID]; ok {
		pe.node = node
		pe.logicalAddr = logicalAddr
	}
	t.network.mu.Unlock()
}

// SendTo implements dht.PunchTransport.
//
// Looks up nodeID in the network.  If found, delivers msg by calling
// InjectReceived on the remote node (from = self.selfAddr, simulating a QUIC
// stream receive on the remote side).  Returns ok=true on success, ok=false
// when the remote is not registered (triggers UDP fallback in the caller).
func (t *FakePunchTransport) SendTo(_ context.Context, nodeID a2al.NodeID, msg []byte) (bool, error) {
	t.network.mu.Lock()
	remote, ok := t.network.peers[nodeID]
	t.network.mu.Unlock()
	if !ok || remote.node == nil {
		return false, nil
	}
	// Deliver synchronously: the remote's InjectReceived processes the message
	// inline (same goroutine).  This is safe because InjectReceived is
	// re-entrant and does not hold any Node-level locks.
	remote.node.InjectReceived(msg, t.selfAddr)
	return true, nil
}

// Punch implements dht.PunchTransport.
//
// Looks up nodeID in the network.  If the remote is registered, simulates
// immediate ICE success on both sides:
//   - Calls self.OnPunchComplete(nodeID, remote.fakeAddr, true)
//   - Calls remote.OnPunchComplete(selfNID, self.fakeAddr, true)
//
// Both calls run in separate goroutines to match the async contract of a
// real ICE scheduler.  The fakeAddr values are synthesised *net.UDPAddr
// entries with valid IP/Port, ensuring NodeInfo can be marshalled correctly
// in FIND_NODE responses.
//
// If the remote is not registered, calls self.OnPunchComplete(nodeID, nil, false)
// to clear isPunching.
func (t *FakePunchTransport) Punch(nodeID a2al.NodeID, _ *protocol.EndpointRecord, _ int) {
	t.mu.Lock()
	selfNode := t.self
	t.mu.Unlock()
	if selfNode == nil {
		return // Bind not called yet; no-op
	}

	t.network.mu.Lock()
	remote, ok := t.network.peers[nodeID]
	selfEntry := t.network.peers[t.selfNID]
	t.network.mu.Unlock()

	if !ok || remote.node == nil {
		// Remote unknown: report failure so isPunching is cleared.
		go selfNode.OnPunchComplete(nodeID, a2al.Address{}, nil, false, false, PunchFailOther)
		return
	}

	remoteNode := remote.node
	remoteFakeAddr := remote.fakeAddr
	remoteLogicalAddr := remote.logicalAddr
	selfFakeAddr := selfEntry.fakeAddr
	selfLogicalAddr := selfEntry.logicalAddr
	selfNID := t.selfNID

	// Simulate ICE success on both sides asynchronously.
	go selfNode.OnPunchComplete(nodeID, remoteLogicalAddr, remoteFakeAddr, true, false, PunchFailNone)
	go remoteNode.OnPunchComplete(selfNID, selfLogicalAddr, selfFakeAddr, true, false, PunchFailNone)
}

// HasConn implements dht.PunchTransport.
// FakePunchTransport does not maintain a pool; SendTo delivers directly via
// InjectReceived so every registered peer is always "connected".
// Returns true when the remote nodeID is registered in the network.
func (t *FakePunchTransport) HasConn(nodeID a2al.NodeID) bool {
	t.network.mu.Lock()
	pe, ok := t.network.peers[nodeID]
	t.network.mu.Unlock()
	return ok && pe.node != nil
}
