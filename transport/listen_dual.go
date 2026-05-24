// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package transport

import "net"

// resolveListenAddr interprets a user-supplied listen address and returns
// the appropriate network string and resolved address string for socket creation.
//
// Rules:
//   - Wildcard host ("", "0.0.0.0", "[::]") → ("udp", "[::]:port")  — dual-stack intent
//   - Specific IPv4 address                  → ("udp4", addr)        — IPv4-only socket
//   - Specific IPv6 address                  → ("udp6", addr)        — IPv6-only socket
//   - Unparseable addr                        → ("udp4", addr)        — safe fallback
//
// This function is used by ListenDualUDP on all platforms so that explicit
// IPv4 bindings (e.g. "1.2.3.4:5001") always stay on a single udp4 socket,
// while wildcard bindings are promoted to dual-stack. This preserves existing
// RunNATProbe and candidate-collection semantics for explicit-IP deployments.
func resolveListenAddr(addr string) (network, resolved string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "udp4", addr
	}
	switch host {
	case "", "0.0.0.0":
		return "udp", net.JoinHostPort("::", port)
	case "::":
		return "udp", addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "udp4", addr // hostname — keep as-is, let OS resolve
	}
	if ip.To4() != nil {
		return "udp4", addr // specific IPv4 address → IPv4-only socket
	}
	return "udp6", addr // specific IPv6 address → IPv6-only socket
}

// normalizeUDPAddr unwraps IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to
// their pure IPv4 form. On dual-stack sockets (Linux/macOS), the OS delivers
// IPv4 packets with an IPv4-mapped source address; normalizing at the UDPMux
// read boundary ensures all code above the transport layer always sees plain
// net.IP (4-byte or 16-byte non-mapped), preventing split route-table keys
// and rate-limit bypass.
//
// L2 contract (transport package responsibility):
//   - Every net.Addr returned or forwarded by UDPMux (ReadFrom, WriteToMux,
//     OnObservedAddr callbacks) is guaranteed to already be normalized.
//   - Layers above (DHT, host, natsense) MUST NOT call normalizeUDPAddr
//     themselves. If a caller ever needs to, that indicates a missed
//     normalization point in this package — fix it here, not there.
//   - Callers may safely assume: if IP.To4() != nil then len(IP) == 4;
//     if IP.To4() == nil then len(IP) == 16 and the address is a true IPv6
//     address (not an IPv4-mapped one).
func normalizeUDPAddr(addr net.Addr) net.Addr {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return addr
	}
	if v4 := ua.IP.To4(); v4 != nil && len(ua.IP) == net.IPv6len {
		// IPv4-mapped IPv6 — unwrap to 4-byte IPv4 representation
		return &net.UDPAddr{IP: v4, Port: ua.Port}
	}
	return addr
}
