// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package natsense implements observed address consensus (spec Phase 2a: ≥3 distinct reporters).
// For tests or small networks, set MinAgreeingPeers to 1.
package natsense

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// NAT type constants (mirror protocol.NAT* for convenience).
const (
	NATUnknown      uint8 = 0
	NATFullCone     uint8 = 1
	NATRestricted   uint8 = 2
	NATPortRestrict uint8 = 3
	NATSymmetric    uint8 = 4
)

// V6Reach classifies the local node's IPv6 reachability.
// The state space is simpler than v4 NAT types: v6 has globally routable
// addresses (Direct), is behind a stateful firewall (Firewalled), or we
// have not determined this yet (Unknown).
type V6Reach uint8

const (
	V6Unknown    V6Reach = 0
	V6Direct     V6Reach = 1 // GUA bind confirmed, or v6 probe echo received
	V6Firewalled V6Reach = 2 // v6 probe attempted but echo blocked
)

const defaultMinAgree = 3

// voteTTL is the maximum age of a vote before it is ignored by TrustedUDP and
// InferNATType.  Stale votes from when the node had a different external address
// (e.g. after a VPN reconnect or NAT rebinding) are silently discarded so that
// the new address reaches consensus within a few probe cycles rather than being
// blocked by leftover votes.
const voteTTL = 15 * time.Minute

// vote records the time a particular reporter last confirmed our endpoint.
type vote struct {
	at time.Time
}

// probeResultTTL is how long an active probe result is considered fresh.
const probeResultTTL = 30 * time.Minute

// Sense tracks distinct peers that reported the same reflected UDP endpoint (wire bytes)
// and infers NAT type from both passive mapping observation and active probe results.
//
// v4 and v6 state are maintained independently. InferNATType covers v4 only;
// use InferV6Reach for v6 reachability classification.
type Sense struct {
	mu  sync.Mutex
	min int
	// canonical key "host:port" -> reporter nodeIDKey -> last-seen timestamp
	votes map[string]map[nodeIDKey]vote
	// observedPorts is populated by Record but not used in inference; kept for
	// InvalidateObservations to clear atomically with votes.
	observedPorts map[uint16]struct{}

	// v4 active classification state (set by host.RunNATProbe).
	bindPublicV4  bool  // v4: local socket is bound to a public WAN IP
	probeResultV4 *bool // nil=unknown, true=reachable, false=unreachable
	probeAtV4     time.Time

	// v4 mapping probe: active port-consistency test (set by host.runMappingProbeV4).
	// nil=unknown, true=symmetric (no majority port), false=non-symmetric (majority port exists).
	mappingProbeResultV4 *bool
	mappingProbeAtV4     time.Time

	// v6 active classification state.
	v6GUABind     bool  // local interface has a GUA (globally unique address)
	probeResultV6 *bool // nil=unknown, true=direct, false=firewalled
	probeAtV6     time.Time
}

type nodeIDKey [32]byte

// NewSense returns a consensus tracker. If minAgreeingPeers <= 0, default 3 is used.
func NewSense(minAgreeingPeers int) *Sense {
	m := minAgreeingPeers
	if m <= 0 {
		m = defaultMinAgree
	}
	return &Sense{
		min:           m,
		votes:         make(map[string]map[nodeIDKey]vote),
		observedPorts: make(map[uint16]struct{}),
	}
}

// MinAgreeing returns the configured threshold.
func (s *Sense) MinAgreeing() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.min
}

// SetMinAgreeing updates the threshold (e.g. 1 for integration tests).
func (s *Sense) SetMinAgreeing(n int) {
	if n <= 0 {
		n = defaultMinAgree
	}
	s.mu.Lock()
	s.min = n
	s.mu.Unlock()
}

// --- v4 bind / probe state ---

// RecordV4BindPublic records whether the local UDP socket is bound to a public
// WAN IPv4 address. Called by host.RunNATProbe after inspecting the QUIC listen address.
func (s *Sense) RecordV4BindPublic(isPublic bool) {
	s.mu.Lock()
	s.bindPublicV4 = isPublic
	s.mu.Unlock()
}

// IsV4BindPublic reports whether the local socket is bound to a public WAN IPv4 address.
func (s *Sense) IsV4BindPublic() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bindPublicV4
}

// RecordV4ProbeResult records the outcome of an active v4 reachability probe.
// reachable=true means ≥1 remote peer successfully echoed our claimed v4 address.
func (s *Sense) RecordV4ProbeResult(reachable bool) {
	s.mu.Lock()
	s.probeResultV4 = &reachable
	s.probeAtV4 = time.Now()
	s.mu.Unlock()
}

// ClearV4ProbeResult discards the cached v4 probe result.
func (s *Sense) ClearV4ProbeResult() {
	s.mu.Lock()
	s.probeResultV4 = nil
	s.probeAtV4 = time.Time{}
	s.mu.Unlock()
}

// RecordMappingProbeV4 records the result of the active v4 NAT port-consistency
// probe. symmetric=true means no single external port held a strict majority
// across probe targets (Symmetric NAT behaviour); false means one port dominated.
func (s *Sense) RecordMappingProbeV4(symmetric bool) {
	s.mu.Lock()
	s.mappingProbeResultV4 = &symmetric
	s.mappingProbeAtV4 = time.Now()
	s.mu.Unlock()
}

// ClearMappingProbeV4 discards the cached v4 mapping probe result.
func (s *Sense) ClearMappingProbeV4() {
	s.mu.Lock()
	s.mappingProbeResultV4 = nil
	s.mappingProbeAtV4 = time.Time{}
	s.mu.Unlock()
}

// --- v6 bind / probe state ---

// RecordV6GUABind records whether the local interface has an IPv6 Globally
// Unique Address (GUA). A GUA bind implies v6 direct reachability absent a
// stateful firewall. Called by host.RunNATProbe.
func (s *Sense) RecordV6GUABind(hasGUA bool) {
	s.mu.Lock()
	s.v6GUABind = hasGUA
	s.mu.Unlock()
}

// IsV6GUABind reports whether a local GUA was detected.
func (s *Sense) IsV6GUABind() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v6GUABind
}

// RecordV6ProbeResult records the outcome of an active v6 reachability probe.
// reachable=true means ≥1 remote peer echoed our v6 address (Direct);
// false means a stateful firewall is blocking unsolicited inbound v6.
func (s *Sense) RecordV6ProbeResult(reachable bool) {
	s.mu.Lock()
	s.probeResultV6 = &reachable
	s.probeAtV6 = time.Now()
	s.mu.Unlock()
}

// ClearV6ProbeResult discards the cached v6 probe result.
func (s *Sense) ClearV6ProbeResult() {
	s.mu.Lock()
	s.probeResultV6 = nil
	s.probeAtV6 = time.Time{}
	s.mu.Unlock()
}

// --- Deprecated single-family wrappers (kept for backward compatibility) ---

// Deprecated: use RecordV4BindPublic.
func (s *Sense) RecordBindPublic(isPublic bool) { s.RecordV4BindPublic(isPublic) }

// Deprecated: use IsV4BindPublic.
func (s *Sense) IsBindPublic() bool { return s.IsV4BindPublic() }

// Deprecated: use RecordV4ProbeResult.
func (s *Sense) RecordProbeResult(reachable bool) { s.RecordV4ProbeResult(reachable) }

// ClearProbeResult discards cached active-probe classification so the next
// probe result is used immediately after network changes.
// Deprecated: use ClearV4ProbeResult / ClearV6ProbeResult as needed.
func (s *Sense) ClearProbeResult() {
	s.ClearV4ProbeResult()
	s.ClearV6ProbeResult()
	s.ClearMappingProbeV4()
}

// --- Passive vote management ---

// InvalidateObservations clears passive observed_addr votes after confirmed
// network changes so old mappings do not bias the next consensus cycle.
func (s *Sense) InvalidateObservations() {
	s.mu.Lock()
	s.votes = make(map[string]map[nodeIDKey]vote)
	s.observedPorts = make(map[uint16]struct{})
	s.mu.Unlock()
}

// HasMultiPortEvidence reports whether any single public IPv4 address has been
// observed with ≥2 distinct ports in the live (non-expired) vote window. Used
// to overrule probe-based FullCone classification when there is live evidence
// that a single NAT device is assigning different external ports per destination
// (Symmetric NAT behavior).
//
// Ports are only compared within the same public IP: a multi-homed host whose
// two NICs have different public IPs will each show one stable port and must
// NOT be treated as Symmetric. v6 GUA ports are also excluded.
func (s *Sense) HasMultiPortEvidence() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-voteTTL)
	// ipPorts: public-IP → set of observed ports
	ipPorts := make(map[string]map[uint16]struct{})
	for key, m := range s.votes {
		alive := false
		for _, v := range m {
			if v.at.After(cutoff) {
				alive = true
				break
			}
		}
		if !alive {
			continue
		}
		host, ps, err := net.SplitHostPort(key)
		if err != nil {
			continue
		}
		// Only count v4 addresses; v6 GUA ports are stable and irrelevant here.
		if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
			continue
		}
		p, err := strconv.ParseUint(ps, 10, 16)
		if err != nil {
			continue
		}
		pm := ipPorts[host]
		if pm == nil {
			pm = make(map[uint16]struct{})
			ipPorts[host] = pm
		}
		pm[uint16(p)] = struct{}{}
		if len(pm) > 1 {
			return true
		}
	}
	return false
}

// Record adds one vote: reporter saw our endpoint as observed (wire encoding).
func (s *Sense) Record(reporter a2al.NodeID, observed []byte) {
	host, port, ok := protocol.ParseObservedUDP(observed)
	if !ok {
		return
	}
	key := net.JoinHostPort(host, strconv.Itoa(int(port)))
	var z nodeIDKey
	copy(z[:], reporter[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.votes[key]
	if !ok {
		m = make(map[nodeIDKey]vote)
		s.votes[key] = m
	}
	m[z] = vote{at: time.Now()}
	s.observedPorts[port] = struct{}{}
}

// liveVotes returns the number of non-expired votes for the given key bucket.
// Must be called with s.mu held.
func liveVotes(m map[nodeIDKey]vote, cutoff time.Time) int {
	n := 0
	for _, v := range m {
		if v.at.After(cutoff) {
			n++
		}
	}
	return n
}

// effectiveMin returns the consensus threshold to use for this evaluation.
// When fewer distinct live reporters have been seen than the configured minimum
// (cold-start: small bootstrap set), the threshold is lowered to the actual
// reporter count so the node can still form a consensus and publish an endpoint.
// Once the node has seen at least s.min distinct reporters the original threshold
// is restored. Must be called with s.mu held.
func (s *Sense) effectiveMin(cutoff time.Time) int {
	if s.min <= 1 {
		return s.min
	}
	var seen int
	reporters := make(map[nodeIDKey]struct{})
	for _, m := range s.votes {
		for rid, v := range m {
			if v.at.After(cutoff) {
				if _, ok := reporters[rid]; !ok {
					reporters[rid] = struct{}{}
					seen++
				}
			}
		}
	}
	if seen > 0 && seen < s.min {
		return seen
	}
	return s.min
}

// TrustedUDP returns host and port if some observed key has >= min distinct
// reporters whose votes are younger than voteTTL.
func (s *Sense) TrustedUDP() (host string, port uint16, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-voteTTL)
	min := s.effectiveMin(cutoff)
	for key, reps := range s.votes {
		if liveVotes(reps, cutoff) < min {
			continue
		}
		h, ps, err := net.SplitHostPort(key)
		if err != nil {
			continue
		}
		p64, err := strconv.ParseUint(ps, 10, 16)
		if err != nil {
			continue
		}
		return h, uint16(p64), true
	}
	return "", 0, false
}

// TrustedUDPAll returns all observed keys (host:port strings) that have
// reached the minimum-agreement threshold. Unlike TrustedUDP it does not stop
// at the first match, so callers receive both IPv4 and IPv6 consensus entries
// when a dual-stack node is observed from multiple reporters.
func (s *Sense) TrustedUDPAll() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-voteTTL)
	min := s.effectiveMin(cutoff)
	var out []string
	for key, reps := range s.votes {
		if liveVotes(reps, cutoff) >= min {
			out = append(out, key)
		}
	}
	return out
}

// TrustedWire returns the first trusted observed_addr wire form (6 or 18 bytes),
// for any address family.
// Deprecated: prefer TrustedWireV4 / TrustedWireV6 for family-specific probing.
func (s *Sense) TrustedWire() ([]byte, bool) {
	host, port, ok := s.TrustedUDP()
	if !ok {
		return nil, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	b, err := protocol.FormatObservedUDP(ip, port)
	if err != nil {
		return nil, false
	}
	return b, true
}

// TrustedWireV4 returns the wire-encoded trusted IPv4 external address, if any.
// Only v4 consensus entries are considered.
func (s *Sense) TrustedWireV4() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-voteTTL)
	min := s.effectiveMin(cutoff)
	for key, reps := range s.votes {
		if liveVotes(reps, cutoff) < min {
			continue
		}
		h, ps, err := net.SplitHostPort(key)
		if err != nil {
			continue
		}
		ip := net.ParseIP(h)
		if ip == nil || ip.To4() == nil {
			continue
		}
		p64, err := strconv.ParseUint(ps, 10, 16)
		if err != nil {
			continue
		}
		b, err := protocol.FormatObservedUDP(ip.To4(), uint16(p64))
		if err != nil {
			continue
		}
		return b, true
	}
	return nil, false
}

// TrustedWireV6 returns the wire-encoded trusted IPv6 external address, if any.
// Only v6 consensus entries are considered.
func (s *Sense) TrustedWireV6() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-voteTTL)
	min := s.effectiveMin(cutoff)
	for key, reps := range s.votes {
		if liveVotes(reps, cutoff) < min {
			continue
		}
		h, ps, err := net.SplitHostPort(key)
		if err != nil {
			continue
		}
		ip := net.ParseIP(h)
		if ip == nil || ip.To4() != nil {
			continue // skip v4
		}
		p64, err := strconv.ParseUint(ps, 10, 16)
		if err != nil {
			continue
		}
		b, err := protocol.FormatObservedUDP(ip, uint16(p64))
		if err != nil {
			continue
		}
		return b, true
	}
	return nil, false
}

// symDetectResult is returned by detectSymmetricV4.
type symDetectResult struct {
	isSymmetric    bool
	supportedPorts int
	total          int
	// portsByHost collects "host:port(reporters)" strings for debug logging.
	portsByHost []string
}

// detectSymmetricV4 scans live v4 votes and returns whether this node appears
// to be behind a Symmetric NAT.
//
// Symmetric NAT is characterised by the NAT device assigning a *different*
// external port depending on the *destination*.  The tell-tale sign is that
// multiple remote peers observe our v4 source address as the same IP but
// *different* ports — all from the same egress interface.
//
// Multi-homed hosts (multiple WAN interfaces / public IPs) must NOT be
// misclassified: if peer A sees 203.0.113.1:4121 and peer B sees
// 198.51.100.2:1029, those are two different public IPs, each with one port —
// not a single NAT device varying its mapping.  The fix is to group votes by
// public IP first, then look for ≥2 well-supported ports *within the same IP*.
//
// filterIP, if non-nil, restricts analysis to votes where the observed IP
// equals filterIP.  Pass nil to analyse all v4 paths (worst-case).
//
// v6 votes are excluded: GUA ports are stable and must not bias this check.
//
// Must be called with s.mu held.
func (s *Sense) detectSymmetricV4(cutoff time.Time, filterIP net.IP) symDetectResult {
	minPerPort := 2
	if s.min <= 1 {
		minPerPort = 1
	}

	// hostPortReporters: IP → port → set-of-reporters
	type portMap = map[uint16]map[nodeIDKey]struct{}
	hostPortReporters := make(map[string]portMap)
	total := 0

	for key, m := range s.votes {
		host, ps, err := net.SplitHostPort(key)
		if err != nil {
			continue
		}
		// v4 only — v6 GUA ports are stable and irrelevant.
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil {
			continue
		}
		// Optional per-path filter: only analyse the specified IP.
		if filterIP != nil && !filterIP.Equal(ip.To4()) {
			continue
		}
		reporters := make(map[nodeIDKey]struct{})
		for rid, v := range m {
			if v.at.After(cutoff) {
				reporters[rid] = struct{}{}
			}
		}
		if len(reporters) == 0 {
			continue
		}
		total += len(reporters)

		p64, err := strconv.ParseUint(ps, 10, 16)
		if err != nil {
			continue
		}
		p := uint16(p64)

		pm := hostPortReporters[host]
		if pm == nil {
			pm = make(portMap)
			hostPortReporters[host] = pm
		}
		dst := pm[p]
		if dst == nil {
			dst = make(map[nodeIDKey]struct{})
			pm[p] = dst
		}
		for rid := range reporters {
			dst[rid] = struct{}{}
		}
	}

	// For each public IP, count how many ports have sufficient independent
	// reporters.  Symmetric NAT requires ≥2 such ports under the *same* IP.
	maxSupported := 0
	var debugParts []string
	for host, pm := range hostPortReporters {
		supported := 0
		for p, reps := range pm {
			if len(reps) >= minPerPort {
				supported++
				debugParts = append(debugParts, fmt.Sprintf("%s:%d(%d)", host, p, len(reps)))
			}
		}
		if supported > maxSupported {
			maxSupported = supported
		}
	}

	return symDetectResult{
		isSymmetric:    maxSupported >= 2,
		supportedPorts: maxSupported,
		total:          total,
		portsByHost:    debugParts,
	}
}

// trustedV4IPLocked returns the primary v4 IP that has reached consensus
// threshold in the passive vote window, or nil if none exists.
// Used by PublishNatType to filter symmetric detection to the STUN path.
// Must be called with s.mu held.
func (s *Sense) trustedV4IPLocked(cutoff time.Time) net.IP {
	min := s.effectiveMin(cutoff)
	for key, reps := range s.votes {
		if liveVotes(reps, cutoff) < min {
			continue
		}
		h, _, err := net.SplitHostPort(key)
		if err != nil {
			continue
		}
		ip := net.ParseIP(h)
		if ip != nil && ip.To4() != nil {
			return ip.To4()
		}
	}
	return nil
}

// InferNATType returns the best NAT classification for local operational use
// (punch strategy, session signalling). It is intentionally worst-case:
// symmetric detection considers ALL v4 paths — if any path shows symmetric
// behaviour the result is NATSymmetric, so the punch peer sprays ports.
// A false-positive symmetric here wastes spray bandwidth but never breaks
// connectivity; a false-negative would cause punch to miss.
//
// Do NOT use this for publishing to the DHT — call PublishNatType() instead,
// which restricts symmetric detection to the STUN-confirmed path and uses
// the active mapping probe as the authoritative signal for that path.
//
// Decision flow:
//
//  1. Public bind (QUIC socket on a WAN IPv4)  → NATFullCone.
//  2. Symmetric (worst-case): passive all-path OR fresh mapping probe → NATSymmetric.
//  3. Insufficient passive evidence             → NATUnknown.
//  4. Active probe result (RecordV4ProbeResult):
//     reachable=true  → NATFullCone  (any peer can initiate; Full Cone or cloud NAT)
//     reachable=false → NATRestricted
//  5. No probe result yet                       → NATRestricted (conservative default).
func (s *Sense) InferNATType() uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()

	// ① Public bind: local socket has a direct WAN IPv4 — treated as Full Cone on wire.
	if s.bindPublicV4 {
		return NATFullCone
	}

	cutoff := time.Now().Add(-voteTTL)
	effMin := s.effectiveMin(cutoff)
	// Worst-case: no IP filter — any v4 path showing symmetric behaviour counts.
	sym := s.detectSymmetricV4(cutoff, nil)

	// ② Symmetric (worst-case OR): passive any-path symmetric, or fresh mapping
	// probe confirmed symmetric on the STUN path.  Mapping probe result only
	// ADDS symmetric evidence here; it does NOT suppress the passive conclusion.
	freshProbe := s.mappingProbeResultV4 != nil && time.Since(s.mappingProbeAtV4) < probeResultTTL
	if sym.isSymmetric || (freshProbe && *s.mappingProbeResultV4) {
		slog.Debug("nat: symmetric detected", "component", "natsense",
			"passive", sym.isSymmetric, "probe", freshProbe && *s.mappingProbeResultV4,
			"supported_ports", sym.supportedPorts, "ports", sym.portsByHost,
			"total_reporters", sym.total)
		return NATSymmetric
	}

	// ③ Not enough passive evidence to proceed.
	if sym.total < effMin {
		return NATUnknown
	}

	// ④ Mapping is EIM (stable port); use active probe to classify filtering.
	if s.probeResultV4 != nil && time.Since(s.probeAtV4) < probeResultTTL {
		if *s.probeResultV4 {
			return NATFullCone // echo received → EIF filtering (Full Cone / cloud NAT)
		}
		return NATRestricted // echo blocked → EIF filtering restricted
	}

	// ⑤ No probe result available; conservative default.
	return NATRestricted
}

// PublishNatType returns the NAT capability value to embed in a published
// DHT endpoint record. It differs from InferNATType in two ways:
//
//  1. Symmetric detection is restricted to the STUN-confirmed v4 path
//     (trustedV4IPLocked).  Other paths (VPN, private) are excluded so that
//     a stable public endpoint is not mis-classified as Symmetric because of
//     an unrelated path's NAT behaviour.
//
//  2. A fresh active mapping probe is authoritative for the STUN path: when
//     one is available it overrides the passive vote analysis (which may be
//     contaminated by UPnP session reuse).  Without a fresh probe the passive
//     analysis acts as a fallback.
//
//  3. When passive evidence is sufficient but the active probe has not yet
//     completed, InferNATType returns NATRestricted; PublishNatType returns
//     NATUnknown so that peers attempt direct-dial optimistically.
func (s *Sense) PublishNatType() uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()

	// ① Public bind.
	if s.bindPublicV4 {
		return NATFullCone
	}

	cutoff := time.Now().Add(-voteTTL)
	effMin := s.effectiveMin(cutoff)
	// Restrict passive symmetric detection to the STUN-confirmed path.
	// nil primaryIP (no consensus yet) falls back to all-path analysis.
	primaryIP := s.trustedV4IPLocked(cutoff)
	sym := s.detectSymmetricV4(cutoff, primaryIP)

	// ② Symmetric: mapping probe is authoritative for the STUN path when fresh.
	// It overrides a passive symmetric conclusion that may be UPnP-session-
	// polluted.  Without a fresh probe, fall back to the (filtered) passive result.
	if s.mappingProbeResultV4 != nil && time.Since(s.mappingProbeAtV4) < probeResultTTL {
		if *s.mappingProbeResultV4 {
			return NATSymmetric
		}
		// Mapping probe says non-symmetric on the STUN path: trust it.
	} else if sym.isSymmetric {
		return NATSymmetric
	}

	// ③ Insufficient passive evidence.
	if sym.total < effMin {
		return NATUnknown
	}

	// ④ Active probe result available.
	if s.probeResultV4 != nil && time.Since(s.probeAtV4) < probeResultTTL {
		if *s.probeResultV4 {
			return NATFullCone
		}
		return NATRestricted
	}

	// ⑤ Single-port stable mapping confirmed but probe not yet run.
	// Publish Unknown so peers attempt direct-dial optimistically rather than
	// going straight to ICE before we have confirmed evidence either way.
	return NATUnknown
}

// InferV6Reach returns the current best classification of local IPv6 reachability.
// Decision flow:
//  1. GUA bind confirmed → Direct (globally routable, no NAT).
//  2. Active v6 probe result available → Direct or Firewalled.
//  3. No information → Unknown.
func (s *Sense) InferV6Reach() V6Reach {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v6GUABind {
		return V6Direct
	}
	if s.probeResultV6 != nil && time.Since(s.probeAtV6) < probeResultTTL {
		if *s.probeResultV6 {
			return V6Direct
		}
		return V6Firewalled
	}
	return V6Unknown
}

func netParseHost(host string) net.IP {
	return net.ParseIP(host)
}
