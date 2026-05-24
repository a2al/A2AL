// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/a2al/a2al"
)

// repSetPunchWait is how long storeAndRecord waits for Mode B after triggering
// ICE for a confirmed repSet neighbor.
const repSetPunchWait = 5 * time.Second

type sendTransport uint8

const (
	sendTransportQUIC sendTransport = iota
	sendTransportUDP
	sendTransportDeferICE
)

type sendPlan struct {
	transport sendTransport
	addr      net.Addr
	reason    string
}

// deliverMeta describes how the most recent deliver attempt was sent. Callers
// use viaQUIC to avoid penalising UDP health when a QUIC-only attempt fails.
type deliverMeta struct {
	viaQUIC  bool
	dialAddr net.Addr
	reason   string // outboundPlan reason; attached to RPC failure logs for troubleshooting
}

// preferredFamilyIsV6 derives the target address family from addrHint, then
// lookupPeerHealthAware, defaulting to v4 (same priority as L0).
func (n *Node) preferredFamilyIsV6(peerID a2al.NodeID, addrHint net.Addr) bool {
	if v6, ok := addrIsV6(addrHint); ok {
		return v6
	}
	if addr, ok := n.lookupPeerHealthAware(peerID); ok {
		if v6, ok := addrIsV6(addr); ok {
			return v6
		}
	}
	return false
}

func (n *Node) outboundPlan(peerID a2al.NodeID, addrHint net.Addr) sendPlan {
	if n.punch != nil && n.punch.HasConn(peerID) {
		return sendPlan{transport: sendTransportQUIC, reason: "has_conn"}
	}

	v6 := n.preferredFamilyIsV6(peerID, addrHint)
	profile := n.reachProfile(peerID)

	if profile.prefersUDPAnchor() {
		if addr := n.publicStableDialAddr(peerID, v6); addr != nil {
			return sendPlan{transport: sendTransportUDP, addr: addr, reason: "l0_public_anchor"}
		}
		// Public-capable peer without a resolvable anchor: skip lastInbound and
		// fall through to L0 health-aware / stable selection below.
	} else if addr, ok := n.freshLastInboundForFamily(peerID, v6); ok && !n.skipColdForPeer(peerID, addr) && !n.isUnusableControlPlaneReachAddr(addr) {
		return sendPlan{transport: sendTransportUDP, addr: addr, reason: "last_inbound"}
	}

	if n.shouldDeferICEForFamily(peerID, v6) {
		return sendPlan{transport: sendTransportDeferICE, reason: "skip_cold_ice"}
	}

	if addr, ok := n.lookupPeerHealthAware(peerID); ok {
		return sendPlan{transport: sendTransportUDP, addr: addr, reason: "l0_health_aware"}
	}
	if addr, ok := n.lookupPeer(peerID); ok {
		return sendPlan{transport: sendTransportUDP, addr: addr, reason: "l0_stable"}
	}
	return sendPlan{transport: sendTransportUDP, reason: "l0_no_addr"}
}

func (n *Node) deliver(ctx context.Context, peerID a2al.NodeID, addrHint net.Addr, raw []byte) (deliverMeta, error) {
	var meta deliverMeta

	if peerID == (a2al.NodeID{}) {
		meta.dialAddr = addrHint
		return meta, n.sendToOrFallbackLegacy(ctx, addrHint, raw)
	}

	if !n.learnedPathFirst.Load() {
		meta.dialAddr = n.legacyDialAddr(peerID, addrHint)
		return meta, n.sendToOrFallbackLegacy(ctx, meta.dialAddr, raw)
	}

	plan := n.outboundPlan(peerID, addrHint)
	meta.reason = plan.reason
	n.logDeliverPlanIfChanged(peerID, plan, addrHint)

	switch plan.transport {
	case sendTransportQUIC:
		meta.viaQUIC = true
		if n.punch != nil {
			sent, err := n.punch.SendTo(ctx, peerID, raw)
			if sent {
				return meta, err
			}
		}
		// HasConn/SendTo race: pool dropped between plan and send. Fall back to
		// L0 in the same attempt so the RPC is not aborted (sendAndWait only
		// retries on timeout, not on deliver error).
		meta.viaQUIC = false
		meta.dialAddr = n.legacyDialAddr(peerID, addrHint)
		return meta, n.sendToOrFallbackLegacy(ctx, meta.dialAddr, raw)

	case sendTransportUDP:
		addr := plan.addr
		if addr == nil {
			addr = addrHint
		}
		if addr == nil {
			addr = n.legacyDialAddr(peerID, addrHint)
		}
		meta.dialAddr = addr
		if plan.reason == "last_inbound" {
			return meta, n.tr.Send(addr, raw)
		}
		return meta, n.sendToOrFallbackLegacy(ctx, addr, raw)

	case sendTransportDeferICE:
		if er := n.lookupEndpointRecord(peerID); er != nil {
			n.triggerPunch(peerID, er, PunchPriorityLowest)
		}
		meta.dialAddr = n.legacyDialAddr(peerID, addrHint)
		return meta, n.sendToOrFallbackLegacy(ctx, meta.dialAddr, raw)

	default:
		meta.dialAddr = n.legacyDialAddr(peerID, addrHint)
		return meta, n.sendToOrFallbackLegacy(ctx, meta.dialAddr, raw)
	}
}

func sendPlanLogSig(plan sendPlan) string {
	addr := ""
	if plan.addr != nil {
		addr = plan.addr.String()
	}
	return fmt.Sprintf("%d|%s|%s", plan.transport, plan.reason, addr)
}

// deliverPlanWorthLogging reports whether an outbound plan reason indicates a
// path-level problem worth logging during normal operation. Routine L0/L1 paths
// are suppressed; see the commented block in logDeliverPlanIfChanged.
func deliverPlanWorthLogging(reason string) bool {
	switch reason {
	case "skip_cold_ice", "l0_no_addr":
		return true
	default:
		return false
	}
}

// logDeliverPlanIfChanged emits dht deliver plan for blocking path problems
// (skip_cold_ice, l0_no_addr). Routine reasons (has_conn, last_inbound,
// l0_health_aware, l0_stable) are commented out below for future restoration.
func (n *Node) logDeliverPlanIfChanged(peerID a2al.NodeID, plan sendPlan, addrHint net.Addr) {
	if !deliverPlanWorthLogging(plan.reason) {
		// Process logs (disabled): routine outbound paths during normal operation.
		// Restore for connectivity debugging.
		//
		// sig := sendPlanLogSig(plan)
		// key := nodeIDKey(peerID)
		// n.deliverPlanLogMu.Lock()
		// prev, seen := n.deliverPlanLogged[key]
		// if seen && prev == sig {
		// 	n.deliverPlanLogMu.Unlock()
		// 	return
		// }
		// n.deliverPlanLogged[key] = sig
		// n.deliverPlanLogMu.Unlock()
		//
		// n.log.Debug("dht deliver plan",
		// 	"peer", peerID,
		// 	"transport", plan.transport,
		// 	"reason", plan.reason,
		// 	"addr", plan.addr,
		// 	"addr_hint", addrHint,
		// )
		return
	}

	sig := sendPlanLogSig(plan)
	key := nodeIDKey(peerID)

	n.deliverPlanLogMu.Lock()
	prev, seen := n.deliverPlanLogged[key]
	if seen && prev == sig {
		n.deliverPlanLogMu.Unlock()
		return
	}
	n.deliverPlanLogged[key] = sig
	n.deliverPlanLogMu.Unlock()

	n.log.Debug("dht deliver plan",
		"peer", peerID,
		"transport", plan.transport,
		"reason", plan.reason,
		"addr", plan.addr,
		"addr_hint", addrHint,
	)
}

func (n *Node) legacyDialAddr(peerID a2al.NodeID, addrHint net.Addr) net.Addr {
	if addr, ok := n.lookupPeerHealthAware(peerID); ok {
		return addr
	}
	if addrHint != nil {
		return addrHint
	}
	if addr, ok := n.lookupPeer(peerID); ok {
		return addr
	}
	return nil
}

// sendToOrFallbackLegacy is the legacy blind-send path. It preserves
// the pre-v2 sendToOrFallback behaviour: HasConn-by-addr lookup then UDP.
func (n *Node) sendToOrFallbackLegacy(ctx context.Context, to net.Addr, raw []byte) error {
	if n.punch != nil && to != nil {
		if nid, ok := n.lookupPeerID(to); ok {
			if sent, err := n.punch.SendTo(ctx, nid, raw); sent {
				return err
			}
		}
	}
	if to == nil {
		return nil
	}
	return n.tr.Send(to, raw)
}

// SetLearnedPathFirst toggles learned-path outbound selection at runtime.
func (n *Node) SetLearnedPathFirst(on bool) {
	n.learnedPathFirst.Store(on)
}

func (n *Node) repSetContains(rs *repSet, id a2al.NodeID) bool {
	rs.mu.Lock()
	_, ok := rs.nodes[nodeIDKey(id)]
	rs.mu.Unlock()
	return ok
}

// maybeWaitRepSetPunch triggers high-priority ICE for confirmed repSet neighbors
// that should not be cold-UDP probed on the target family, then waits for HasConn.
func (n *Node) maybeWaitRepSetPunch(ctx context.Context, id a2al.NodeID, rs *repSet, addrHint net.Addr) {
	if !n.learnedPathFirst.Load() || n.punch == nil {
		return
	}
	if !n.repSetContains(rs, id) {
		return
	}
	if n.punch.HasConn(id) {
		return
	}
	if n.reachProfile(id).prefersUDPAnchor() {
		return
	}
	v6 := n.preferredFamilyIsV6(id, addrHint)
	if !n.shouldDeferICEForFamily(id, v6) {
		return
	}
	er := n.lookupEndpointRecord(id)
	if er == nil {
		return
	}
	n.triggerPunchWithOptions(id, er, PunchPriorityHigh, true)

	waitForHasConn(ctx, func() bool { return n.punch.HasConn(id) }, repSetPunchWait)
}

// waitForHasConn polls until hasConn returns true or timeout elapses.
func waitForHasConn(ctx context.Context, hasConn func() bool, timeout time.Duration) bool {
	if hasConn() {
		return true
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return hasConn()
		}
		if hasConn() {
			return true
		}
		select {
		case <-ctx.Done():
			return hasConn()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return hasConn()
}
