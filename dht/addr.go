// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"net"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// peerAddrEphemeralTTL is the validity window for hole-punch derived addresses.
// After this period the ephemeral slot is treated as expired and ignored.
const peerAddrEphemeralTTL = 5 * time.Minute

// liveVerifiedFreshWindow is how long a freshly verified live address (written
// by a successful QUIC handshake or punch) takes priority over the peer's
// long-lived anchor (advertised endpoint).  Within this window "my observation"
// beats "their claim"; outside it the anchor is the safer choice.
const liveVerifiedFreshWindow = 5 * time.Minute

// addrRank orders address evidence strength. Higher rank must not be replaced by
// a lower rank in the Live slot; Anchor is a separate slot for self-/operator-
// declared endpoints and is never written from hearsay or ephemeral sources.
type addrRank uint8

const (
	rankHearsay  addrRank = 2
	rankVerified addrRank = 3
)

// familyAddrs holds dial candidates for one IP family (v4 or v6).
//
// Anchor: long-lived advertised/infra address (endpoint quic://, DNS bootstrap).
// Live: operational address from RPC success or hearsay; rank-guarded writes.
// Ephemeral: short-lived ICE prflx (TTL-bounded); never overwrites Anchor/Live.
//
// Freshness: when live is written at rankVerified (e.g. from a successful QUIC
// handshake) liveAt is updated.  preferred() treats a fresh verified live as
// higher priority than anchor — "my recent observation" beats "their claim".
// Once liveVerifiedFreshWindow elapses the anchor is preferred again.
type familyAddrs struct {
	anchor      *net.UDPAddr
	live        *net.UDPAddr
	liveRank    addrRank
	liveAt      time.Time // last time live was written; zero if never
	ephemeral   *net.UDPAddr
	ephemeralAt time.Time
}

func (fa *familyAddrs) tryAnchor(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	fa.anchor = cloneUDPAddr(addr)
	return true
}

func (fa *familyAddrs) tryLive(addr *net.UDPAddr, rank addrRank) bool {
	if addr == nil || rank < rankHearsay {
		return false
	}
	if fa.live != nil && rank < fa.liveRank {
		return false
	}
	fa.live = cloneUDPAddr(addr)
	fa.liveRank = rank
	fa.liveAt = time.Now()
	return true
}

func (fa *familyAddrs) tryEphemeral(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	fa.ephemeral = cloneUDPAddr(addr)
	fa.ephemeralAt = time.Now()
}

// preferred returns the best dial address for this family.
//
// Priority order:
//  1. Fresh verified live  – a QUIC-handshake-confirmed address within
//     liveVerifiedFreshWindow; "my observation" beats the peer's published claim.
//  2. Anchor               – long-lived advertised endpoint; once live ages out
//     this is the stable fallback.
//  3. Stale live           – hearsay or expired-verified; still better than nothing.
//  4. Ephemeral            – hole-punch address within peerAddrEphemeralTTL.
func (fa *familyAddrs) preferred() *net.UDPAddr {
	// Fresh verified live takes priority over anchor.
	if fa.live != nil && fa.liveRank >= rankVerified && !fa.liveAt.IsZero() &&
		time.Since(fa.liveAt) < liveVerifiedFreshWindow {
		return fa.live
	}
	if fa.anchor != nil {
		return fa.anchor
	}
	if fa.live != nil {
		return fa.live
	}
	if fa.ephemeral != nil && time.Since(fa.ephemeralAt) < peerAddrEphemeralTTL {
		return fa.ephemeral
	}
	return nil
}

func (fa *familyAddrs) bestStable() *net.UDPAddr {
	if fa.anchor != nil {
		return fa.anchor
	}
	return fa.live
}

// peerAddrs holds per-family dial addresses for a remote peer.
type peerAddrs struct {
	v4 familyAddrs
	v6 familyAddrs
	// fallback holds a non-UDP dial address (e.g. MemTransport in tests).
	fallback net.Addr
}

func (pa *peerAddrs) familyFor(addr *net.UDPAddr) *familyAddrs {
	if addr.IP.To4() != nil {
		return &pa.v4
	}
	return &pa.v6
}

func (pa *peerAddrs) tryAnchor(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	return pa.familyFor(addr).tryAnchor(addr)
}

func (pa *peerAddrs) tryLive(addr *net.UDPAddr, rank addrRank) bool {
	if addr == nil {
		return false
	}
	return pa.familyFor(addr).tryLive(addr, rank)
}

func (pa *peerAddrs) tryEphemeral(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	pa.familyFor(addr).tryEphemeral(addr)
}

// preferred returns the best dial address available.
// Priority: fallback (non-UDP) → v4 family → v6 family.
func (pa *peerAddrs) preferred() net.Addr {
	if pa.fallback != nil {
		return pa.fallback
	}
	if a := pa.v4.preferred(); a != nil {
		return a
	}
	if a := pa.v6.preferred(); a != nil {
		return a
	}
	return nil
}

// setStable writes addr into the Live slot at Verified rank (legacy/test helper).
func (pa *peerAddrs) setStable(addr *net.UDPAddr) {
	pa.tryLive(addr, rankVerified)
}

// setEphemeral records a hole-punch temporary address in the family ephemeral slot.
func (pa *peerAddrs) setEphemeral(addr *net.UDPAddr) {
	pa.tryEphemeral(addr)
}

// ObservedAddr encodes remote IP:port for PONG / FIND_*_RESP (spec §7.6).
func ObservedAddr(from net.Addr) []byte {
	switch a := from.(type) {
	case *net.UDPAddr:
		b, err := protocol.FormatObservedUDP(a.IP, uint16(a.Port))
		if err == nil {
			return b
		}
	}
	b, _ := protocol.FormatObservedUDP(net.IPv4(127, 0, 0, 1), 0)
	return b
}

func nodeIDKey(id a2al.NodeID) string {
	return string(id[:])
}

func nodeInfoFromMessage(dec *protocol.DecodedMessage, from net.Addr) protocol.NodeInfo {
	nid := a2al.NodeIDFromAddress(dec.SenderAddr)
	ni := protocol.NodeInfo{
		Address: append([]byte(nil), dec.SenderAddr[:]...),
		NodeID:  append([]byte(nil), nid[:]...),
	}
	switch a := from.(type) {
	case *net.UDPAddr:
		if ip4 := a.IP.To4(); ip4 != nil {
			ni.IP = append([]byte(nil), ip4...)
		} else {
			ni.IP = append([]byte(nil), a.IP.To16()...)
		}
		ni.Port = uint16(a.Port)
	default:
		ni.IP = net.IPv4(127, 0, 0, 1).To4()
		ni.Port = 0
	}
	return ni
}
