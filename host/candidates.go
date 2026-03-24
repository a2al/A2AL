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
// Order: trusted observed → QUIC bind (public) → outbound probe → FallbackHost → UPnP URL.
// IPv6 candidates will be added here once Host supports dual-stack listeners (see Config doc).
// upnpSnapshot is the result of ensureUPnP (avoid locking around slow IGD calls).
func (h *Host) orderedQUICEndpointStrings(upnpSnapshot string) ([]string, error) {
	portStr := strconv.Itoa(h.QUICLocalAddr().Port)
	seen := make(map[string]struct{})
	var out []string

	if host, _, ok := h.sense.TrustedUDP(); ok {
		if ip := net.ParseIP(host); ip != nil && isPlausibleWANIP(ip) {
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(host, portStr))
		}
	}

	if ua := h.QUICLocalAddr(); ua != nil {
		if ip4 := ua.IP.To4(); ip4 != nil && isPlausibleWANIP(ip4) {
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ip4.String(), portStr))
		}
	}

	if ip := outboundIP(); ip != nil {
		if ip4 := ip.To4(); ip4 != nil && isPlausibleWANIP(ip4) {
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ip4.String(), portStr))
		}
	}

	if fh := strings.TrimSpace(h.cfg.FallbackHost); fh != "" {
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(fh, portStr))
	}

	if upnpSnapshot != "" {
		appendCandidateUnique(seen, &out, upnpSnapshot)
	}

	if len(out) == 0 {
		return nil, errors.New("a2al/host: cannot determine advertise host; set FallbackHost, obtain observed_addr from peers, or enable UPnP")
	}
	return out, nil
}
