// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"net"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// ReachProfile is a derived node-level reachability classification. It is not
// persisted; it guides probe/outbound/health gating without replacing AddrRank.
type ReachProfile uint8

const (
	ReachUnknown ReachProfile = iota
	ReachNAT                  // symmetric NAT or ICE-dependent peer
	ReachPublic               // stable advertised/public anchor (NatType < Symmetric)
)

func (p ReachProfile) prefersUDPAnchor() bool {
	return p == ReachPublic
}

func (p ReachProfile) prefersICEOverColdUDP() bool {
	return p == ReachNAT
}

// reachProfile derives how a peer should be probed and dialed.
//
//   - ReachNAT: endpoint declares symmetric NAT, or ICE signal without a stable
//     advertised anchor — cold UDP to published ports is unreliable.
//   - ReachPublic: NatType < Symmetric with a known anchor or endpoint quic://
//     address — prefer UDP anchor over ICE-only probe/skip-cold paths.
//   - ReachUnknown: insufficient evidence; existing heuristics apply.
func (n *Node) reachProfile(id a2al.NodeID) ReachProfile {
	erAny := n.lookupEndpointRecordAny(id)
	if erAny != nil && erAny.NatType >= protocol.NATSymmetric {
		return ReachNAT
	}
	if n.peerHasAnchor(id) {
		return ReachPublic
	}
	if erAny != nil && erAny.NatType < protocol.NATSymmetric {
		if n.advertisedStableAddr(id, false) != nil || n.advertisedStableAddr(id, true) != nil {
			return ReachPublic
		}
	}
	if n.lookupEndpointRecord(id) != nil {
		return ReachNAT
	}
	return ReachUnknown
}

// lookupEndpointRecordAny returns the newest cached endpoint record regardless
// of whether a signal URL is present.
func (n *Node) lookupEndpointRecordAny(nodeID a2al.NodeID) *protocol.EndpointRecord {
	recs := n.LocalStoreGet(nodeID, protocol.RecTypeEndpoint)
	for _, sr := range recs {
		if er, err := protocol.ParseEndpointRecord(sr); err == nil {
			return &er
		}
	}
	return nil
}

func (n *Node) peerHasAnchor(id a2al.NodeID) bool {
	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(id)]
	n.peerMu.Unlock()
	if pa == nil {
		return false
	}
	return pa.v4.anchor != nil || pa.v6.anchor != nil
}

func (n *Node) advertisedStableAddr(id a2al.NodeID, v6 bool) *net.UDPAddr {
	ref := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	if v6 {
		ref = &net.UDPAddr{IP: net.IPv6loopback}
	}
	for _, sr := range n.LocalStoreGet(id, protocol.RecTypeEndpoint) {
		er, err := protocol.ParseEndpointRecord(sr)
		if err != nil || er.NatType >= protocol.NATSymmetric {
			continue
		}
		if ua := firstEndpointAddrForFamily(&er, ref); ua != nil {
			return ua
		}
	}
	return nil
}

// publicStableDialAddr returns the best UDP anchor for a public-capable peer on
// the requested family. Used by outbound/probe paths that must not fall back to
// stale live/ephemeral ports when an anchor exists.
func (n *Node) publicStableDialAddr(id a2al.NodeID, v6 bool) net.Addr {
	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(id)]
	n.peerMu.Unlock()
	if pa != nil {
		if v6 && pa.v6.anchor != nil {
			return pa.v6.anchor
		}
		if !v6 && pa.v4.anchor != nil {
			return pa.v4.anchor
		}
		if !v6 && pa.v6.anchor != nil {
			return pa.v6.anchor
		}
		if v6 && pa.v4.anchor != nil {
			return pa.v4.anchor
		}
	}
	if addr := n.advertisedStableAddr(id, v6); addr != nil {
		return addr
	}
	if addr, ok := n.lookupPeerHealthAware(id); ok {
		return addr
	}
	return nil
}

func successDialAddr(peer net.Addr, meta deliverMeta) net.Addr {
	if meta.dialAddr != nil {
		return meta.dialAddr
	}
	return peer
}

// bootstrapDialAddr picks a cold-start dial address for id, never using
// ephemeral punch ports. Prefer anchor/advertised stable addresses for public
// peers before routing-table hearsay.
func (n *Node) bootstrapDialAddr(id a2al.NodeID, ni protocol.NodeInfo) *net.UDPAddr {
	if a := n.publicStableDialAddr(id, false); a != nil {
		if u, ok := a.(*net.UDPAddr); ok {
			return u
		}
	}
	n.peerMu.Lock()
	pa := n.peers[nodeIDKey(id)]
	var stable *net.UDPAddr
	if pa != nil {
		stable = pa.v4.bestStable()
		if stable == nil {
			stable = pa.v6.bestStable()
		}
	}
	n.peerMu.Unlock()
	if stable != nil {
		return stable
	}
	if len(ni.IP) > 0 && ni.Port != 0 {
		return &net.UDPAddr{IP: append([]byte(nil), ni.IP...), Port: int(ni.Port)}
	}
	return nil
}
