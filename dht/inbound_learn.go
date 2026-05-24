// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"net"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// lastInboundFreshTTL is how long an observed inbound UDP source address remains
// eligible for learned-path outbound selection.
const lastInboundFreshTTL = 5 * time.Minute

// inboundChannel identifies which transport delivered an inbound DHT request.
type inboundChannel string

const (
	inboundChannelUDP  inboundChannel = "udp"
	inboundChannelQUIC inboundChannel = "quic"
)

// inboundLearn records inbound reachability evidence before request handlers run.
// lastInbound is always written (passive observation). Outbound consumption and
// punch triggers are gated by LearnedPathFirst.
func (n *Node) inboundLearn(from net.Addr, ch inboundChannel, dec *protocol.DecodedMessage) {
	peerID := a2al.NodeIDFromAddress(dec.SenderAddr)
	hasConn := n.punch != nil && n.punch.HasConn(peerID)

	switch ch {
	case inboundChannelUDP:
		if !n.isControlPlaneSelfExcitation(peerID, from) {
			if udp, ok := from.(*net.UDPAddr); ok {
				n.setLastInbound(peerID, udp)
			}
			// L1 only: upgrade to Mode B when endpoint has Signal.
			if n.learnedPathFirst.Load() && n.punch != nil && !hasConn {
				if er := n.lookupEndpointRecord(peerID); er != nil {
					n.triggerPunch(peerID, er, PunchPriorityLowest)
				}
			}
		}
	case inboundChannelQUIC:
		// Mode B pool state is authoritative; HasConn is read at send time.
	}
}

func (n *Node) setLastInbound(peerID a2al.NodeID, from *net.UDPAddr) {
	if peerID == (a2al.NodeID{}) || from == nil {
		return
	}
	key := nodeIDKey(peerID)
	now := time.Now()
	n.healthMu.Lock()
	e := n.health[key]
	if e == nil {
		e = &peerHealthEntry{}
		n.health[key] = e
	}
	fh := e.familyFor(from)
	fh.lastInbound = cloneUDPAddr(from)
	fh.lastInboundAt = now
	n.healthMu.Unlock()
}

func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	ip := make(net.IP, len(a.IP))
	copy(ip, a.IP)
	return &net.UDPAddr{IP: ip, Port: a.Port, Zone: a.Zone}
}

// addrIsV6 reports whether addr is an IPv6 UDP address.
func addrIsV6(addr net.Addr) (v6 bool, ok bool) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return false, false
	}
	return udp.IP.To4() == nil, true
}

func (n *Node) freshLastInboundForFamily(peerID a2al.NodeID, v6 bool) (net.Addr, bool) {
	key := nodeIDKey(peerID)
	now := time.Now()
	n.healthMu.RLock()
	e := n.health[key]
	if e == nil {
		n.healthMu.RUnlock()
		return nil, false
	}
	fh := &e.v4
	if v6 {
		fh = &e.v6
	}
	if fh.lastInbound == nil || fh.lastInboundAt.IsZero() {
		n.healthMu.RUnlock()
		return nil, false
	}
	if now.Sub(fh.lastInboundAt) > lastInboundFreshTTL {
		n.healthMu.RUnlock()
		return nil, false
	}
	addr := fh.lastInbound
	n.healthMu.RUnlock()
	return addr, true
}

func (n *Node) skipColdForPeer(peerID a2al.NodeID, addr net.Addr) bool {
	key := nodeIDKey(peerID)
	n.healthMu.RLock()
	e := n.health[key]
	if e == nil {
		n.healthMu.RUnlock()
		return false
	}
	fh := e.familyFor(addr)
	skip := fh.skipColdUDP
	n.healthMu.RUnlock()
	return skip
}

// shouldDeferICEForFamily reports whether L1 should prefer ICE over cold stable
// UDP on the given address family (v4 when v6=false).
func (n *Node) shouldDeferICEForFamily(peerID a2al.NodeID, v6 bool) bool {
	if n.reachProfile(peerID).prefersUDPAnchor() {
		return false
	}
	if n.lookupEndpointRecord(peerID) == nil {
		return false
	}
	key := nodeIDKey(peerID)
	n.healthMu.RLock()
	e := n.health[key]
	if e == nil {
		n.healthMu.RUnlock()
		return false
	}
	fh := &e.v4
	if v6 {
		fh = &e.v6
	}
	skip := fh.skipColdUDP
	n.healthMu.RUnlock()
	return skip
}

// clearSkipColdUDP clears skip-cold hints. Caller must hold healthMu.
func (n *Node) clearSkipColdUDP(fh *familyHealth) {
	fh.skipColdUDP = false
	fh.skipColdAt = time.Time{}
}

// ClearReachabilityHints resets learned-path hints after network topology changes.
// PeerHealth backoff and failCount are preserved; only skipCold and lastInbound
// evidence are cleared so stale paths are not preferred on a new network.
func (n *Node) ClearReachabilityHints() {
	n.healthMu.Lock()
	cleared := 0
	for _, e := range n.health {
		for _, fh := range []*familyHealth{&e.v4, &e.v6} {
			if fh.skipColdUDP || fh.lastInbound != nil || !fh.lastInboundAt.IsZero() {
				cleared++
			}
			fh.skipColdUDP = false
			fh.skipColdAt = time.Time{}
			fh.lastInbound = nil
			fh.lastInboundAt = time.Time{}
		}
	}
	n.healthMu.Unlock()
	if cleared > 0 {
		n.log.Info("dht reach hints cleared", "families", cleared)
	}
}
