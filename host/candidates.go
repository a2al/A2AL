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

// v6ObservedSnap picks the IPv6 address to advertise or claim as observed.
// A plausible STUN mapping wins; otherwise the local GUA (no NAT66) paired
// with listenPort. Empty when neither source is usable.
func v6ObservedSnap(stunIP net.IP, stunPort uint16, gua net.IP, listenPort int) string {
	if stunIP != nil && isPlausibleWANIP(stunIP) {
		return net.JoinHostPort(stunIP.String(), strconv.Itoa(int(stunPort)))
	}
	if gua != nil && isPlausibleWANIP(gua) && listenPort > 0 {
		return net.JoinHostPort(gua.String(), strconv.Itoa(listenPort))
	}
	return ""
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

// upnpIPMatchesPublicV4 returns true when the UPnP ExternalIP (from upnpURL,
// a "quic://IP:port" string) equals the STUN-derived public IPv4 (from
// extIPv4, an "IP:port" or bare "IP" string).  Both must be non-empty.
//
// A match means the IGD port mapping is on the true WAN interface — UPnP is
// genuinely reachable by any peer and can be treated as Full Cone.  A mismatch
// (double-NAT, CGNAT) means the UPnP address is not the real public address.
func upnpIPMatchesPublicV4(upnpURL, extIPv4 string) bool {
	if upnpURL == "" || extIPv4 == "" {
		return false
	}
	u, err := url.Parse(upnpURL)
	if err != nil || u.Host == "" {
		return false
	}
	upnpHost := u.Host
	if h, _, e := net.SplitHostPort(u.Host); e == nil {
		upnpHost = h
	}
	upnpIP := net.ParseIP(upnpHost)
	if upnpIP == nil {
		return false
	}
	extHost := extIPv4
	if h, _, e := net.SplitHostPort(extIPv4); e == nil {
		extHost = h
	}
	extIP := net.ParseIP(extHost)
	if extIP == nil {
		return false
	}
	return upnpIP.Equal(extIP)
}

// orderedQUICEndpointStrings builds Phase 2b multi-candidate endpoints (deduped).
//
// Priority order — within each family, IPv6 is listed before IPv4 so that remote
// nodes attempting Happy Eyeballs will try v6 first (GUA is directly reachable
// without NAT traversal). Both families are always published; v4 remains the
// fallback for v6-only or v4-only peers.
//
//	① trusted observed_addr v6  (natsense consensus from DHT peers; v6 only)
//	② STUN external IPv6        (GUA from v6 STUN probe; only on dual-stack hosts)
//	   UPnP external URL        (promoted here when UPnP IP == STUN public IPv4)
//	① trusted observed_addr v4  (natsense consensus from DHT peers; v4 only)
//	② STUN external IPv4        (NAT-mapped address of the shared UDP socket)
//	③ QUIC bind IP              (only if already a public WAN IP, v4 or v6)
//	④ outbound probe IPv6       (routing-table probe; valid only with direct WAN IP)
//	④ outbound probe IPv4       (routing-table probe; valid only with direct WAN IP)
//	⑤ FallbackHost              (explicit operator override; required for loopback/LAN tests)
//	⑥ UPnP external URL         (IGD port-mapped address; only when IP ≠ STUN public IPv4)
//
// extIPv4Snapshot is the result of ensureExternalIP  (STUN "ip:port" or HTTP "ip", IPv4).
// extIPv6Snapshot is the result of ensureExternalIPv6 (STUN "ip:port", IPv6; may be "").
// upnpSnapshot    is the result of ensureUPnP.
// All three are pre-resolved outside this function to avoid holding locks during I/O.
func (h *Host) orderedQUICEndpointStrings(extIPv4Snapshot, extIPv6Snapshot, upnpSnapshot string) ([]string, error) {
	portStr := strconv.Itoa(h.QUICLocalAddr().Port)
	seen := make(map[string]struct{})
	var out []string

	// ① v6 observed_addr consensus (natsense; listed before v4 for Happy Eyeballs)
	sharedSocket := h.DHTLocalAddr().Port == h.QUICLocalAddr().Port
	for _, addr := range h.sense.TrustedUDPAll() {
		observedHost, ps, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(observedHost)
		if ip == nil || !isPlausibleWANIP(ip) || ip.To4() != nil {
			continue // v4 entries handled after UPnP promotion below
		}
		extPort := portStr
		if sharedSocket {
			if p64, err := strconv.ParseUint(ps, 10, 16); err == nil && p64 > 0 {
				extPort = strconv.Itoa(int(p64))
			}
		}
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(observedHost, extPort))
	}

	// ② STUN external IPv6 (GUA; listed before v4 and UPnP)
	if extIPv6Snapshot != "" {
		ipStr := extIPv6Snapshot
		if host, _, err := net.SplitHostPort(extIPv6Snapshot); err == nil {
			ipStr = host
		}
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ipStr, portStr))
	}

	// UPnP promotion: when the IGD ExternalIP equals the STUN-confirmed public
	// IPv4, insert the UPnP address here — after all v6 candidates but before
	// any v4 candidates — so peers with Full Cone semantics try the stable
	// port-mapped address before the NAT-reflected port.
	upnpPromoted := false
	if upnpSnapshot != "" && upnpIPMatchesPublicV4(upnpSnapshot, extIPv4Snapshot) {
		appendCandidateUnique(seen, &out, upnpSnapshot)
		upnpPromoted = true
	}

	// ① v4 observed_addr consensus (natsense; after UPnP when promoted)
	for _, addr := range h.sense.TrustedUDPAll() {
		observedHost, ps, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(observedHost)
		if ip == nil || !isPlausibleWANIP(ip) || ip.To4() == nil {
			continue // v6 entries already handled above
		}
		extPort := portStr
		if sharedSocket {
			if p64, err := strconv.ParseUint(ps, 10, 16); err == nil && p64 > 0 {
				extPort = strconv.Itoa(int(p64))
			}
		}
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(observedHost, extPort))
	}

	// ② STUN external IPv4 (after UPnP when promoted)
	// STUN returns the NAT-mapped address of an ephemeral probe socket, not the
	// QUIC listener.  We only want the public IP; always pair with the actual
	// QUIC port so we don't publish a stale port that may belong to a different
	// host on the same NAT.
	if extIPv4Snapshot != "" {
		ipStr := extIPv4Snapshot
		if host, _, err := net.SplitHostPort(extIPv4Snapshot); err == nil {
			ipStr = host // strip STUN's ephemeral port
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

	// ④ outbound probe (IPv6 before IPv4; valid only when machine has a direct WAN IP)
	if ip6 := outboundIPv6(); ip6 != nil && isPlausibleWANIP(ip6) {
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ip6.String(), portStr))
	}
	if ip := outboundIPv4(); ip != nil {
		if ip4 := ip.To4(); ip4 != nil && isPlausibleWANIP(ip4) {
			appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(ip4.String(), portStr))
		}
	}

	// ⑤ explicit FallbackHost override
	if fh := strings.TrimSpace(h.cfg.FallbackHost); fh != "" {
		appendCandidateUnique(seen, &out, "quic://"+net.JoinHostPort(fh, portStr))
	}

	// ⑥ UPnP port-mapped address (IPv4 IGD only).
	// Skipped when already promoted to ② above (IP matched public v4).
	if upnpSnapshot != "" && !upnpPromoted {
		appendCandidateUnique(seen, &out, upnpSnapshot)
	}

	if len(out) == 0 {
		return nil, errors.New("a2al/host: cannot determine advertise host; " +
			"ensure internet connectivity for STUN/HTTP probing, or set FallbackHost for local/LAN tests")
	}
	return out, nil
}
