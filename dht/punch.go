// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

// Package-level punch helpers: DHT-side state management for ICE hole-punching
// (过程五 / Phase 2+).
//
// Responsibilities of this file:
//   - isPunching deduplication: only one in-flight punch attempt per NodeID
//   - triggerPunch: gate check + isPunching set + delegate to PunchTransport
//   - OnPunchComplete: clear isPunching; routing-table admission is Phase 3+
//
// What this file does NOT do:
//   - No ICE/QUIC logic (that lives in host/dht_punch_pool.go)
//   - No routing-table mutation (Phase 3: AddPunched)
//   - No DHT semantic decisions (not deciding *why* to punch, only *whether*)

import (
	"net"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)

// lookupEndpointRecord returns the most recent endpoint record for nodeID that
// contains a non-empty signal URL, fetched from the local store cache.
//
// Returns nil when:
//   - No endpoint record for nodeID is cached locally.
//   - The cached record has no signal URL (direct-only server nodes).
//
// Called by the punch trigger sites (Phase 6).  The lookup is intentionally
// best-effort: the local store only contains records that were previously
// fetched by Resolve or received via incoming DHT traffic.  Missing records
// simply skip the punch trigger; routing correctness is unaffected.
func (n *Node) lookupEndpointRecord(nodeID a2al.NodeID) *protocol.EndpointRecord {
	recs := n.LocalStoreGet(nodeID, protocol.RecTypeEndpoint)
	for _, sr := range recs {
		er, err := protocol.ParseEndpointRecord(sr)
		if err != nil {
			continue
		}
		if er.Signal == "" {
			continue
		}
		return &er
	}
	return nil
}

// triggerPunch conditionally enqueues an ICE hole-punch attempt for nodeID.
//
// It is a no-op when:
//   - PunchTransport is not configured (n.punch == nil)
//   - A punch is already in flight for this peer (isPunching == true)
//
// Otherwise it sets isPunching = true and calls PunchTransport.Punch, which
// enqueues the attempt in the host-layer scheduler (non-blocking).
//
// Callers: 过程二 (replication maintainer), 过程三 (health probe),
// query engine. All callers provide an *EndpointRecord obtained from the
// local store; triggerPunch does not fetch records itself.
func (n *Node) triggerPunch(nodeID a2al.NodeID, er *protocol.EndpointRecord, priority int) {
	if n.punch == nil {
		return
	}
	key := nodeIDKey(nodeID)

	n.healthMu.Lock()
	h := n.health[key]
	if h != nil && h.isPunching {
		n.healthMu.Unlock()
		return // already in flight — deduplication gate
	}
	if h == nil {
		h = &peerHealthEntry{}
		n.health[key] = h
	}
	h.isPunching = true
	n.healthMu.Unlock()

	// Delegate to the host-layer scheduler. Non-blocking by contract.
	n.punch.Punch(nodeID, er, priority)
}

// OnPunchComplete is the callback invoked by the PunchTransport implementation
// when an ICE attempt for nodeID finishes (success or failure).
//
// peerAddr is the peer's reachable net.Addr as determined by ICE (typically
// the winning candidate pair's remote address). Must be non-nil on success;
// ignored on failure.
//
// success=true: a punched QUIC connection is now available via
// PunchTransport.SendTo. This call admits the node to the routing table's
// punched zone and registers its address in the peers map so that DHT
// messages can be sent back to it.
//
// success=false: ICE failed (peer offline per noagent, or ICE timeout). The
// node remains in its current health state (typically Bad); the next natural
// probe cycle will try again if conditions are met.
//
// This method is safe to call from any goroutine; it uses healthMu/tabMu/peerMu.
func (n *Node) OnPunchComplete(nodeID a2al.NodeID, peerAddr net.Addr, success bool) {
	key := nodeIDKey(nodeID)
	n.healthMu.Lock()
	h := n.health[key]
	if h != nil {
		h.isPunching = false
	}
	n.healthMu.Unlock()

	if !success || peerAddr == nil {
		n.log.Debug("punch complete: failed", "node", nodeID)
		return
	}

	// Build a NodeInfo so the routing layer can place the node in the correct bucket.
	ni := protocol.NodeInfo{
		NodeID: append([]byte(nil), nodeID[:]...),
	}
	if ua, ok := peerAddr.(*net.UDPAddr); ok {
		if ip4 := ua.IP.To4(); ip4 != nil {
			ni.IP = append([]byte(nil), ip4...)
		} else {
			ni.IP = append([]byte(nil), ua.IP.To16()...)
		}
		ni.Port = uint16(ua.Port)
	}

	// Admit to the routing table's punched zone (spare slots only).
	now := time.Now()
	n.tabMu.Lock()
	n.table.AddPunched(ni, routing.EntryMeta{VerifiedAt: now}, now)
	n.tabMu.Unlock()

	// Register the peer address so DHT send functions can route to this peer.
	// Phase 4 will consult PunchTransport.SendTo first; this registration
	// ensures the UDP fallback also has a candidate address.
	n.peerMu.Lock()
	n.peers[key] = peerAddr
	n.peerMu.Unlock()
	n.addrToID.Store(peerAddr.String(), nodeID)

	n.log.Debug("punch complete: success, admitted to routing table", "node", nodeID)

	// Phase 5: exchange routing info with the newly-reachable peer.
	// Runs in a goroutine so OnPunchComplete returns immediately to the
	// host-layer scheduler.
	go n.exchangeAfterPunch(nodeID, peerAddr)
}
