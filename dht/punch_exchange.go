// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

// punch_exchange.go — post-punch routing-info exchange (§6.1 "路由拓扑").
//
// After a punch connection is established (OnPunchComplete success), this
// file implements the mandatory FIND_NODE exchange:
//
//  1. We send FIND_NODE(self.nid) to the peer → peer returns up to K
//     nodes it has directly verified as close to our NodeID.
//  2. We absorb those nodes as hearsay candidates (no direct contact yet).
//     The health-probe loop (过程三) will verify or discard them without
//     any special handling here.
//
// Anti-poisoning guarantees (§6.2):
//   - The peer applies tabNearestVerified before responding, so it only
//     returns nodes it directly contacted (one-hop, no second-hand data).
//   - We absorb via absorbNodeInfo (VerifiedAt = 0), so they enter the
//     routing table as unverified hearsay — never directly trusted.
//   - We skip the returning node itself (already in the routing table),
//     and skip nodes in PeerHealthBad state.
//   - Bad nodes from the peer's response are simply dropped; self-healing
//     happens naturally via existing health mechanisms (§6.2 自愈性).
//
// Side effect: a successful FindNode RPC also calls recordSuccess on the
// peer, upgrading it from "punched" to "verified direct contact", and
// tabAdd with VerifiedAt set clears the isPunched flag (Phase 3 fix).

import (
	"context"
	"net"
	"time"

	"github.com/a2al/a2al"
)

// exchangeTimeout is the per-exchange deadline for the post-punch FIND_NODE.
// It is generous enough to survive a high-latency ICE path but short enough
// to not stall the host goroutine if the peer is unexpectedly unreachable.
const exchangeTimeout = 10 * time.Second

// exchangeAfterPunch performs the post-punch FIND_NODE routing-info exchange
// with nodeID at peerAddr.  It runs synchronously; callers must launch it in
// a dedicated goroutine so OnPunchComplete is not blocked.
//
// Steps:
//  1. Send FIND_NODE(self.nid) → peerAddr.
//  2. Absorb the K closest nodes returned by the peer as hearsay.
//
// A timeout or RPC error is logged at Debug level and treated as a
// non-fatal best-effort failure; routing correctness is not affected.
func (n *Node) exchangeAfterPunch(nodeID a2al.NodeID, peerAddr net.Addr) {
	ctx, cancel := context.WithTimeout(n.ctx, exchangeTimeout)
	defer cancel()

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
		// Skip self — we're not a peer to ourselves.
		if id == n.nid {
			continue
		}
		// Skip nodes we already know are unreachable.  They will not benefit
		// from an extra hearsay entry and could delay routing maintenance by
		// re-adding a confirmed dead node to the pending list.
		if n.PeerHealthOf(id) == PeerHealthBad {
			continue
		}
		n.absorbNodeInfo(ni, nodeID)
		absorbed++
	}
	n.log.Debug("punch exchange: done", "peer", nodeID, "absorbed", absorbed)
}
