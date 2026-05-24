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

// peerAddrs holds up to three candidate dial addresses for a remote peer.
//
// stableV4/V6 are set whenever we receive a packet directly from that peer
// on the respective family — they represent persistently reachable endpoints.
// ephemeral is a hole-punch prflx address that is only valid for a limited
// time after the punch completes; it is never included in FIND_NODE responses.
//
// The zero value is valid (no address known).
type peerAddrs struct {
	stableV4    *net.UDPAddr
	stableV6    *net.UDPAddr
	ephemeral   *net.UDPAddr
	ephemeralAt time.Time
	// fallback holds a non-UDP dial address (e.g. MemTransport in tests).
	// When non-nil it is returned by preferred() without family selection.
	fallback net.Addr
}

// preferred returns the best dial address available.
// Priority: fallback (non-UDP) → stableV4 → stableV6 → ephemeral (within TTL).
// Returns nil when no address is available.
func (pa *peerAddrs) preferred() net.Addr {
	if pa.fallback != nil {
		return pa.fallback
	}
	if pa.stableV4 != nil {
		return pa.stableV4
	}
	if pa.stableV6 != nil {
		return pa.stableV6
	}
	if pa.ephemeral != nil && time.Since(pa.ephemeralAt) < peerAddrEphemeralTTL {
		return pa.ephemeral
	}
	return nil
}

// setStable writes addr into the family-matched stable slot.
func (pa *peerAddrs) setStable(addr *net.UDPAddr) {
	if addr.IP.To4() != nil {
		pa.stableV4 = addr
	} else {
		pa.stableV6 = addr
	}
}

// setEphemeral records a hole-punch temporary address.
func (pa *peerAddrs) setEphemeral(addr *net.UDPAddr) {
	pa.ephemeral = addr
	pa.ephemeralAt = time.Now()
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
