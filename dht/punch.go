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

// punchMinBackoff is the minimum backoff threshold a peer must have accumulated
// before an ICE punch attempt is triggered (§14 抖动防护).
//
// A peer that just went bad (1-2 failures) has a small backoff (<30 s) — it is
// likely a transient UDP blip and ICE would be wasted.  Only when the backoff
// grows to punchMinBackoff (≥5 min) do we know the peer is persistently
// unreachable and ICE is worth trying.
const punchMinBackoff = 5 * time.Minute

// triggerPunch conditionally enqueues an ICE hole-punch attempt for nodeID.
//
// It is a no-op when any of the following hold:
//   - PunchTransport is not configured (n.punch == nil)
//   - An active Mode B connection already exists (HasConn)
//   - A punch is already in flight for this peer (isPunching == true)
//   - The peer's backoff is below punchMinBackoff (§14: anti-jitter gate),
//     unless bypassBackoff is true (repSet / skipCold paths)
//
// Otherwise it sets isPunching = true and calls PunchTransport.Punch, which
// enqueues the attempt in the host-layer scheduler (non-blocking).
func (n *Node) triggerPunch(nodeID a2al.NodeID, er *protocol.EndpointRecord, priority int) {
	n.triggerPunchWithOptions(nodeID, er, priority, false)
}

func (n *Node) triggerPunchWithOptions(nodeID a2al.NodeID, er *protocol.EndpointRecord, priority int, bypassBackoff bool) {
	if n.punch == nil {
		return
	}
	if nodeID == n.nid || (er != nil && er.Address == n.addr) {
		return
	}
	// Already have a live punched connection — no need to re-punch.
	if n.punch.HasConn(nodeID) {
		return
	}

	key := nodeIDKey(nodeID)
	n.healthMu.Lock()
	h := n.health[key]

	// §14 anti-jitter gate: only punch when the peer has been bad long enough.
	// Peers with a small active backoff are likely suffering a transient UDP
	// outage; ICE should not be wasted on them. Zero nextRetryAt (never
	// contacted or recently recovered) always passes through.
	//
	// With dual-family health: skip punch only when ALL active families have a
	// small-but-nonzero backoff. If any active family has a large/zero backoff,
	// ICE is worthwhile. Inactive families (everUsed=false) are excluded so that
	// a v4-only peer's v6 slot (always zero) doesn't suppress the gate check —
	// preserving the same semantics as the old single-family model.
	if h != nil && !bypassBackoff {
		v4Block := h.v4.everUsed && !h.v4.nextRetryAt.IsZero() && time.Until(h.v4.nextRetryAt) < punchMinBackoff
		v6Block := h.v6.everUsed && !h.v6.nextRetryAt.IsZero() && time.Until(h.v6.nextRetryAt) < punchMinBackoff
		v4Active := h.v4.everUsed
		v6Active := h.v6.everUsed
		// Block only when all active families have small backoffs.
		blocked := (!v4Active || v4Block) && (!v6Active || v6Block) && (v4Active || v6Active)
		if blocked {
			n.healthMu.Unlock()
			return
		}
	}

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
// peerLogicalAddr is the peer's a2al.Address (21-byte identity address
// derived from their public key).  Used to populate NodeInfo.Address so that
// the entry can be included in FIND_NODE responses.
//
// peerNetAddr is the peer's reachable net.Addr as determined by ICE (typically
// the winning candidate pair's remote UDP address). Must be non-nil on success.
//
// success=true: a punched QUIC connection is now available via SendTo.
//
// isDirect=true (Phase 8 误分类纠正): the ICE-selected path is host or
// server-reflexive, meaning the remote is directly reachable via plain UDP.
// In this case the node is admitted to the standard routing bucket (tabAdd)
// rather than the punched zone; the Mode B QUIC connection remains in the pool
// until it idle-times-out (5 min per modeBQUICConfig) — no special teardown.
//
// success=false: failReason identifies the cause.  PunchFailNoAgent indicates
// the remote is definitively offline; the health system marks the peer Bad
// permanently until the next probe cycle clears it, skipping further ICE.
//
// Safe to call from any goroutine; uses healthMu/tabMu/peerMu.
func (n *Node) OnPunchComplete(nodeID a2al.NodeID, peerLogicalAddr a2al.Address, peerNetAddr net.Addr, success bool, isDirect bool, failReason PunchFailReason) {
	key := nodeIDKey(nodeID)
	n.healthMu.Lock()
	h := n.health[key]
	if h != nil {
		h.isPunching = false
		if !success && failReason == PunchFailNoAgent {
			// Remote has no ICE callee registered — it is offline or does not
			// support hole-punching. Advance both families' failCount past the
			// bad threshold (ICE is family-agnostic: noagent means the peer is
			// entirely offline, not just on one family).
			if h.v4.failCount < badHealthThreshold {
				h.v4.failCount = badHealthThreshold
				h.v4.everUsed = true
			}
			if h.v6.failCount < badHealthThreshold {
				h.v6.failCount = badHealthThreshold
				h.v6.everUsed = true
			}
			n.log.Debug("punch complete: noagent, peer marked bad", "node", nodeID)
		}
	}
	n.healthMu.Unlock()

	if !success || peerNetAddr == nil {
		if failReason != PunchFailNoAgent {
			n.log.Debug("punch complete: failed", "node", nodeID, "reason", failReason)
		}
		return
	}

	if nodeID == n.nid || peerLogicalAddr == n.addr || n.isUnusableControlPlaneReachAddr(peerNetAddr) {
		n.log.Debug("punch complete: failed", "node", nodeID, "reason", PunchFailOther)
		return
	}

	// Build NodeInfo for routing table admission. Address is required by
	// nodeInfoCheck so the entry can appear in FIND_NODE responses.
	ni := protocol.NodeInfo{
		NodeID:  append([]byte(nil), nodeID[:]...),
		Address: append([]byte(nil), peerLogicalAddr[:]...),
	}
	if ua, ok := peerNetAddr.(*net.UDPAddr); ok {
		if ip4 := ua.IP.To4(); ip4 != nil {
			ni.IP = append([]byte(nil), ip4...)
		} else {
			ni.IP = append([]byte(nil), ua.IP.To16()...)
		}
		ni.Port = uint16(ua.Port)
	}

	now := time.Now()
	meta := routing.EntryMeta{VerifiedAt: now}

	if isDirect {
		// Phase 8: remote is directly reachable — admit as standard direct node.
		// Prefer the peer's self-advertised stable address over the ephemeral ICE
		// pair port: public nodes may bind a different local port for ICE sessions.
		// Only consider endpoints whose IP family matches the winning ICE path;
		// taking a v6 endpoint for a v4 ICE path (or vice-versa) would write an
		// unreachable address into the routing table.
		if peer, ok := peerNetAddr.(*net.UDPAddr); ok {
			recs := n.LocalStoreGet(nodeID, protocol.RecTypeEndpoint)
			for _, sr := range recs {
				if er, err := protocol.ParseEndpointRecord(sr); err == nil {
					if ua := firstEndpointAddrForFamily(&er, peer); ua != nil {
						if ip4 := ua.IP.To4(); ip4 != nil {
							ni.IP = append([]byte(nil), ip4...)
						} else {
							ni.IP = append([]byte(nil), ua.IP.To16()...)
						}
						ni.Port = uint16(ua.Port)
					}
					break
				}
			}
		}
		n.tabAdd(ni, meta, peerNetAddr)
		n.log.Debug("punch complete: reclassified as direct node", "node", nodeID)
	} else {
		// Normal punch: admit to the routing table's punched zone (spare slots only).
		n.tabMu.Lock()
		n.table.AddPunched(ni, meta, now)
		n.tabMu.Unlock()
		n.log.Debug("punch complete: admitted as punched node", "node", nodeID)
	}

	// Register the peer address so DHT send functions can route to this peer.
	// sendToOrFallback consults PunchTransport.SendTo first; this registration
	// ensures the UDP fallback also has a candidate address.
	// isDirect → Live Verified slot; prflx punch → ephemeral slot (TTL-bounded).
	n.peerMu.Lock()
	pa := n.peers[key]
	if pa == nil {
		pa = &peerAddrs{}
		n.peers[key] = pa
	}
	if udp, ok := peerNetAddr.(*net.UDPAddr); ok {
		if isDirect {
			pa.tryLive(udp, rankVerified)
		} else {
			pa.tryEphemeral(udp)
		}
	} else {
		pa.fallback = peerNetAddr
	}
	n.peerMu.Unlock()
	n.addrToID.Store(peerNetAddr.String(), nodeID)

	// Phase 5: exchange routing info with the newly-reachable peer.
	go n.exchangeAfterPunch(nodeID, peerNetAddr)
}

// firstEndpointAddr returns the first quic:// address from an EndpointRecord,
// or nil if none is present or parseable.
func firstEndpointAddr(er *protocol.EndpointRecord) *net.UDPAddr {
	for _, e := range er.Endpoints {
		if len(e) > 7 && e[:7] == "quic://" {
			if a, err := net.ResolveUDPAddr("udp", e[7:]); err == nil {
				return a
			}
		}
	}
	return nil
}

// firstEndpointAddrForFamily returns the first quic:// endpoint whose IP
// family matches peer, or nil. Used when upgrading an ICE ephemeral address to
// the peer's stable self-advertised address: taking an endpoint with the wrong
// family would write an unreachable address into the routing table.
func firstEndpointAddrForFamily(er *protocol.EndpointRecord, peer *net.UDPAddr) *net.UDPAddr {
	wantV4 := peer.IP.To4() != nil
	for _, e := range er.Endpoints {
		if len(e) > 7 && e[:7] == "quic://" {
			ua, err := net.ResolveUDPAddr("udp", e[7:])
			if err != nil {
				continue
			}
			if (ua.IP.To4() != nil) == wantV4 {
				return ua
			}
		}
	}
	return nil
}
