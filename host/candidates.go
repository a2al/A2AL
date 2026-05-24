// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// isPlausibleWANIP reports whether ip is suitable to publish in an endpoint record
// (not loopback, link-local, private, CGNAT, unspecified, or multicast).
// Works for both IPv4 and IPv6; the CGNAT exclusion (RFC 6598, 100.64/10) applies
// to IPv4 only. For IPv6, GUA (2000::/3) addresses pass; ULA (fc00::/7) and
// link-local (fe80::/10) are rejected by IsPrivate/IsLinkLocalUnicast respectively.
// Transition-mechanism prefixes (Teredo 2001::/32, 6to4 2002::/16) are rejected
// because they embed IPv4 addresses and do not provide native IPv6 connectivity.
func isPlausibleWANIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.IsPrivate() {
		return false
	}
	// RFC 6598 CGNAT — not included in net.IP.IsPrivate as of Go 1.22.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false
	}
	// Reject IPv6 transition-mechanism prefixes that embed IPv4 routing.
	if len(ip) == net.IPv6len && ip.To4() == nil {
		// Teredo: 2001:0000::/32 (RFC 4380)
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00 {
			return false
		}
		// 6to4: 2002::/16 (RFC 3056)
		if ip[0] == 0x20 && ip[1] == 0x02 {
			return false
		}
	}
	return true
}

func dialKeyFromQUICURL(ep string) (string, bool) {
	u, err := url.Parse(ep)
	if err != nil || u.Host == "" || (u.Scheme != "quic" && u.Scheme != "udp") {
		return "", false
	}
	a, err := net.ResolveUDPAddr("udp", u.Host)
	if err != nil {
		return strings.ToLower(u.Host), true
	}
	return a.String(), true
}

func appendCandidateUnique(seen map[string]struct{}, out *[]string, ep string) {
	key, ok := dialKeyFromQUICURL(ep)
	if !ok {
		return
	}
	if _, dup := seen[key]; dup {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, ep)
}

// orderedQUICEndpointStrings builds Phase 2b multi-candidate endpoints (deduped).
//
// Priority order (v4 entries interleave with v6 at each tier — no family sorting):
//
//	① trusted observed_addr  (natsense consensus from DHT peers; all families)
//	② STUN external IPv4     (NAT-mapped address of the shared UDP socket)
//	② STUN external IPv6     (GUA from v6 STUN probe; only on dual-stack hosts)
//	③ QUIC bind IP           (only if already a public WAN IP, v4 or v6)
//	④ outbound probe IP      (routing-table probe; valid only with direct WAN IP)
//	⑤ FallbackHost           (explicit operator override; required for loopback/LAN tests)
//	⑥ UPnP external URL      (IGD port-mapped address, IPv4 only)
//
// extIPv4Snapshot is the result of ensureExternalIP  (STUN "ip:port" or HTTP "ip", IPv4).
// extIPv6Snapshot is the result of ensureExternalIPv6 (STUN "ip:port", IPv6; may be "").
// upnpSnapshot    is the result of ensureUPnP.
// All three are pre-resolved outside this function to avoid holding locks during I/O.
func (h *Host) orderedQUICEndpointStrings(extIPv4Snapshot, extIPv6Snapshot, upnpSnapshot string) ([]string, error) {
	portStr := strconv.Itoa(h.QUICLocalAddr().Port)
	seen := make(map[string]struct{})
	var out []string

	// ① observed_addr consensus (all address families)
	// When DHT and QUIC share the same socket (UDPMux), the natsense-observed
	// port IS the NAT-mapped external port for that socket — use it directly so
	// that instances on the same host but different ports are correctly
	// distinguished.  When DHT and QUIC are on separate sockets, natsense only
	// reflects the DHT port; we fall back to the local QUIC port.
	//
	// For IPv6 GUA entries there is typically no NAT, so the observed port equals
	// the local socket port regardless.  In separate-socket mode (sharedSocket=false)
	// we must still use portStr rather than the observed DHT port.
	sharedSocket := h.DHTLocalAddr().Port == h.QUICLocalAddr().Port
	for _, addr := range h.sense.TrustedUDPAll() {
		observedHost, ps, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(observedHost)
		if ip == nil || !isPlausibleWANIP(ip) {
			continue
		}
		extPort := portStr
		if sharedSocket {
			if p64, err := strconv.ParseUint(ps, 10, 16); err == nil && p64 > 0 {
				extPort = strconv.Itoa(int(p64))
			}
		}
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(observedHost, extPort))
	}

	// ② STUN external IP (IPv4 + IPv6, same tier)
	// STUN returns the NAT-mapped address of an ephemeral probe socket, not the
	// QUIC listener.  We only want the public IP; always pair with the actual
	// QUIC port so we don't publish a stale port that may belong to a different
	// host on the same NAT.  IPv6 has no HTTP fallback service; "" means the
	// host has no IPv6 connectivity or dual-stack is disabled.
	if extIPv4Snapshot != "" {
		ipStr := extIPv4Snapshot
		if host, _, err := net.SplitHostPort(extIPv4Snapshot); err == nil {
			ipStr = host // strip STUN's ephemeral port
		}
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ipStr, portStr))
	}
	if extIPv6Snapshot != "" {
		ipStr := extIPv6Snapshot
		if host, _, err := net.SplitHostPort(extIPv6Snapshot); err == nil {
			ipStr = host
		}
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ipStr, portStr))
	}

	// ③ QUIC bind IP (direct public, v4 or v6 GUA)
	if ua := h.QUICLocalAddr(); ua != nil {
		if ip4 := ua.IP.To4(); ip4 != nil && isPlausibleWANIP(ip4) {
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ip4.String(), portStr))
		} else if ip6 := ua.IP; ip6 != nil && ip6.To4() == nil && isPlausibleWANIP(ip6) {
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ip6.String(), portStr))
		}
	}

	// ④ outbound probe (valid only when machine has a direct WAN IP, v4 or v6)
	if ip := outboundIPv4(); ip != nil {
		if ip4 := ip.To4(); ip4 != nil && isPlausibleWANIP(ip4) {
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ip4.String(), portStr))
		}
	}
	if ip6 := outboundIPv6(); ip6 != nil && isPlausibleWANIP(ip6) {
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ip6.String(), portStr))
	}

	// ⑤ explicit FallbackHost override
	if fh := strings.TrimSpace(h.cfg.FallbackHost); fh != "" {
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(fh, portStr))
	}

	// ⑥ UPnP port-mapped address (IPv4 IGD only)
	if upnpSnapshot != "" {
		appendCandidateUnique(seen, &out, upnpSnapshot)
	}

	if len(out) == 0 {
		return nil, errors.New("a2al/host: cannot determine advertise host; " +
			"ensure internet connectivity for STUN/HTTP probing, or set FallbackHost for local/LAN tests")
	}
	return out, nil
}
