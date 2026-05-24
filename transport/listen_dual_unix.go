// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package transport

import "net"

// ListenDualUDP opens a UDP socket that handles both IPv4 and IPv6 traffic.
//
// On non-Windows platforms (Linux, macOS, Android, iOS), a single socket bound
// to [::]:port handles both families: the OS delivers IPv4 packets with an
// IPv4-mapped source address (::ffff:x.x.x.x), which normalizeUDPAddr unwraps
// at the UDPMux read boundary.
//
// Address resolution rules (see resolveListenAddr):
//   - ":port", "0.0.0.0:port"  → single dual-stack socket on [::]:port
//   - "1.2.3.4:port"           → single IPv4-only socket (explicit bind preserved)
//   - "[2001:db8::1]:port"      → single IPv6-only socket
func ListenDualUDP(addr string) (net.PacketConn, error) {
	network, resolved := resolveListenAddr(addr)
	a, err := net.ResolveUDPAddr(network, resolved)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP(network, a)
}
