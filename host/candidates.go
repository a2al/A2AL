// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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
// Priority order:
//
//	① trusted observed_addr (natsense consensus from DHT peers)
//	② STUN external ip:port  (NAT-mapped address, most reliable for public internet)
//	③ QUIC bind IP          (only if already a public WAN IP)
//	④ outbound probe IP     (local route to 8.8.8.8; only valid on machines with direct WAN IP)
//	⑤ FallbackHost          (explicit operator override; required for loopback/LAN tests)
//	⑥ UPnP external URL    (IGD port-mapped address)
//	⑦ HTTP public IP        (last resort: ip only → use local port)
//
// extipSnapshot is the result of ensureExternalIP (STUN "ip:port" or HTTP "ip").
// upnpSnapshot is the result of ensureUPnP.
// Both are pre-resolved outside this function to avoid holding locks during I/O.
func (h *Host) orderedQUICEndpointStrings(extipSnapshot, upnpSnapshot string) ([]string, error) {
	portStr := strconv.Itoa(h.QUICLocalAddr().Port)
	seen := make(map[string]struct{})
	var out []string

	// ① observed_addr consensus
	if host, _, ok := h.sense.TrustedUDP(); ok {
		if ip := net.ParseIP(host); ip != nil && isPlausibleWANIP(ip) {
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(host, portStr))
		}
	}

	// ② STUN / HTTP external IP
	if extipSnapshot != "" {
		if strings.Contains(extipSnapshot, ":") {
			// STUN result includes port — use it directly.
			appendCandidateUnique(seen, &out, "quic://"+extipSnapshot)
		} else {
			// HTTP result is IP only — pair with our local listen port.
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(extipSnapshot, portStr))
		}
	}

	// ③ QUIC bind IP (direct public)
	if ua := h.QUICLocalAddr(); ua != nil {
		if ip4 := ua.IP.To4(); ip4 != nil && isPlausibleWANIP(ip4) {
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ip4.String(), portStr))
		}
	}

	// ④ outbound probe (valid only when machine has a direct WAN IP)
	if ip := outboundIP(); ip != nil {
		if ip4 := ip.To4(); ip4 != nil && isPlausibleWANIP(ip4) {
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ip4.String(), portStr))
		}
	}

	// ⑤ explicit FallbackHost override
	if fh := strings.TrimSpace(h.cfg.FallbackHost); fh != "" {
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(fh, portStr))
	}

	// ⑥ UPnP port-mapped address
	if upnpSnapshot != "" {
		appendCandidateUnique(seen, &out, upnpSnapshot)
	}

	if len(out) == 0 {
		return nil, errors.New("a2al/host: cannot determine advertise host; " +
			"ensure internet connectivity for STUN/HTTP probing, or set FallbackHost for local/LAN tests")
	}
	return out, nil
}
