// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

// punch_exchange.go — post-punch routing-info exchange (§6.1).
//
// Implements three post-punch exchanges in priority order:
//
//  1. 路由拓扑 (mandatory): FIND_NODE(self.nid) exchange — both sides learn
//     about directly-verified peers they didn't know about before.
//
//  2. Observed_addr (§6.1 "顺带", zero-cost): PingIdentity carries the
//     peer's observation of our external IP:port (distributed STUN).
//     Because both sides call exchangeAfterPunch concurrently, each side
//     responds to the other's PING with an observed_addr — zero extra RTTs.
//
//  3. STORE 补发 (§6.1 "按需"): trigger replication for repSets that have
//     room (< nRep confirmed members). processReplTask will find the newly-
//     routable node via the routing table and send STORE if it qualifies.
//
// Anti-poisoning guarantees (§6.2):
//   - The peer applies tabNearestVerified before responding, so it only
//     returns nodes it directly contacted (one-hop, no second-hand data).
//   - We absorb via absorbNodeInfo (VerifiedAt = 0), so they enter the
//     routing table as unverified hearsay — never directly trusted.
//   - We skip the returning node itself (already in the routing table),
//     and skip nodes in PeerHealthBad state.
//
// Side effect: a successful FindNode RPC also calls recordSuccess on the
// peer, upgrading it from "punched" to "verified direct contact", and
// tabAdd with VerifiedAt set clears the isPunched flag (Phase 3 fix).

import (
	"context"
	"net"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// exchangeTimeout is the per-exchange deadline for the post-punch FIND_NODE.
// It is generous enough to survive a high-latency ICE path but short enough
// to not stall the host goroutine if the peer is unexpectedly unreachable.
const exchangeTimeout = 10 * time.Second

// exchangeAfterPunch performs the full post-punch information exchange with
// nodeID at peerAddr.  It runs synchronously; callers must launch it in a
// dedicated goroutine so OnPunchComplete is not blocked.
//
// Three steps are executed in order; failures in later steps do not abort
// earlier ones — all steps are best-effort except the FIND_NODE (step 1).
func (n *Node) exchangeAfterPunch(nodeID a2al.NodeID, peerAddr net.Addr) {
	ctx, cancel := context.WithTimeout(n.ctx, exchangeTimeout)
	defer cancel()

	// ── Step 1: 路由拓扑 (mandatory) ─────────────────────────────────────
	nodes, err := n.FindNode(ctx, peerAddr, n.nid)
	if err != nil {
		n.log.Debug("punch exchange: FindNode failed", "peer", nodeID, "err", err)
		return
	}
	n.log.Debug("punch exchange: absorbing peer nodes", "peer", nodeID, "count", len(nodes))
	absorbed := 0
	for _, ni := range nodes {
		if len(ni.NodeID) != len(n.nid) {
			continue
		}
		var id a2al.NodeID
		copy(id[:], ni.NodeID)
		if id == n.nid {
			continue
		}
		if n.PeerHealthOf(id) == PeerHealthBad {
			continue
		}
		n.absorbNodeInfo(ni, nodeID)
		absorbed++
	}
	n.log.Debug("punch exchange: route absorbed", "peer", nodeID, "count", absorbed)

	// ── Step 2: observed_addr 顺带 (§6.1, zero-cost STUN side-effect) ────
	// PingIdentity sends PING → PONG carries the peer's observed_addr of us.
	// Concurrently, the peer's own exchangeAfterPunch also Pings us; our PONG
	// will carry our observation of the peer's external address.
	// Both sides learn their external IP:port from the other — free STUN.
	if pi, pingErr := n.PingIdentity(ctx, peerAddr); pingErr == nil && pi != nil {
		n.notifyObserved(nodeID, pi.ObservedWire)
		n.log.Debug("punch exchange: observed_addr received", "peer", nodeID,
			"observed_len", len(pi.ObservedWire))
	}

	// ── Step 3: STORE 补发 (§6.1 "按需") ─────────────────────────────────
	// Trigger replication for repSets that have room (< nRep members).
	// processReplTask will find the newly-routable node in the routing table
	// and send STORE if it qualifies by XOR distance.
	n.triggerStoreAfterPunch()
	n.log.Debug("punch exchange: complete", "peer", nodeID)
}

// triggerStoreAfterPunch enqueues a replication task for every locally-owned
// record (repSet) that has fewer than nRep confirmed remote replicas.
//
// After a successful punch the punched node is already in the routing table.
// processReplTask (run asynchronously by the replication maintainer) will
// discover it via tabNearestHealthy and send STORE if it is XOR-close enough.
//
// This is a best-effort optimisation: repSets that are already full will be
// re-evaluated on the next regular renewBackground cycle, not immediately.
func (n *Node) triggerStoreAfterPunch() {
	n.repMu.Lock()
	defer n.repMu.Unlock()
	for rk, rs := range n.repSets {
		rs.mu.Lock()
		hasRec := len(rs.rec.Address) > 0
		need := nRep - len(rs.nodes)
		rs.mu.Unlock()
		if hasRec && need > 0 {
			// Zero SignedRecord signals processReplTask to use the existing record.
			n.enqueueReplication(rk, protocol.SignedRecord{})
		}
	}
}
