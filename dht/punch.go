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
	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

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
// success=true: a punched QUIC connection is now available via
// PunchTransport.SendTo. Phase 3 (AddPunched) will admit the node to the
// routing table's punched zone when that phase is implemented.
//
// success=false: ICE failed (peer offline per noagent, or ICE timeout). The
// node remains in its current health state (typically Bad); the next natural
// probe cycle will try again if conditions are met.
//
// This method is safe to call from any goroutine; it uses healthMu.
func (n *Node) OnPunchComplete(nodeID a2al.NodeID, success bool) {
	key := nodeIDKey(nodeID)
	n.healthMu.Lock()
	h := n.health[key]
	if h != nil {
		h.isPunching = false
	}
	n.healthMu.Unlock()

	if success {
		// Phase 3 will add routing-table admission here (AddPunched).
		// Phase 4 will make SendTo available for this peer in the send path.
		// For now: isPunching cleared is sufficient — the node will be found
		// Good (its peerHealthEntry updated) by the next successful RPC.
		n.log.Debug("punch complete: success, routing admission pending Phase 3",
			"node", nodeID)
	} else {
		n.log.Debug("punch complete: failed", "node", nodeID)
	}
}
