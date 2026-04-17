// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package natsense implements observed address consensus (spec Phase 2a: ≥3 distinct reporters).
// For tests or small networks, set MinAgreeingPeers to 1.
package natsense

import (
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
type Sense struct {
	mu sync.Mutex
	// min distinct NodeIDs that must have reported the same canonical key
	min int
	// canonical key "host:port" -> reporter nodeIDKey -> last-seen timestamp
	votes map[string]map[nodeIDKey]vote
	// distinct observed ports (for NAT type inference)
	observedPorts map[uint16]struct{}

	// Active classification state (set by host.RunNATProbe).
	bindPublic  bool  // local socket is bound to a public WAN IP
	probeResult *bool // nil=unknown, true=reachable, false=unreachable
	probeAt     time.Time
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

// RecordBindPublic records whether the local UDP socket is bound to a public WAN IP.
// Called by host.RunNATProbe after inspecting the QUIC listen address.
func (s *Sense) RecordBindPublic(isPublic bool) {
	s.mu.Lock()
	s.bindPublic = isPublic
	s.mu.Unlock()
}

// RecordProbeResult records the outcome of an active AutoNAT-style reachability probe.
// reachable=true means at least one remote peer successfully sent an echo to our
// claimed external address (Full Cone or equivalent); false means Restricted.
func (s *Sense) RecordProbeResult(reachable bool) {
	s.mu.Lock()
	s.probeResult = &reachable
	s.probeAt = time.Now()
	s.mu.Unlock()
}

// ClearProbeResult discards cached active-probe classification so the next
// probe result is used immediately after network changes.
func (s *Sense) ClearProbeResult() {
	s.mu.Lock()
	s.probeResult = nil
	s.probeAt = time.Time{}
	s.mu.Unlock()
}

// InvalidateObservations clears passive observed_addr votes after confirmed
// network changes so old mappings do not bias the next consensus cycle.
func (s *Sense) InvalidateObservations() {
	s.mu.Lock()
	s.votes = make(map[string]map[nodeIDKey]vote)
	s.observedPorts = make(map[uint16]struct{})
	s.mu.Unlock()
}

// IsBindPublic returns true when the local socket has a direct public WAN IP.
func (s *Sense) IsBindPublic() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bindPublic
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

// TrustedUDP returns host and port if some observed key has >= min distinct
// reporters whose votes are younger than voteTTL.
func (s *Sense) TrustedUDP() (host string, port uint16, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-voteTTL)
	for key, reps := range s.votes {
		if liveVotes(reps, cutoff) < s.min {
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

// TrustedWire returns the first trusted observed_addr wire form (6 or 18 bytes).
func (s *Sense) TrustedWire() ([]byte, bool) {
	host, port, ok := s.TrustedUDP()
	if !ok {
		return nil, false
	}
	ip := netParseHost(host)
	if ip == nil {
		return nil, false
	}
	b, err := protocol.FormatObservedUDP(ip, port)
	if err != nil {
		return nil, false
	}
	return b, true
}

// InferNATType returns the current best NAT classification for hole-punch strategy.
//
// Decision flow:
//
//  1. Public bind (QUIC socket on a WAN IP)  → NATFullCone (wire-compatible; host
//     exposes IsBindPublic() for UI to show "public" separately).
//  2. Symmetric mapping: ≥2 well-supported observed ports → NATSymmetric.
//  3. Insufficient passive evidence           → NATUnknown.
//  4. Active probe result (RecordProbeResult):
//     reachable=true  → NATFullCone  (any peer can initiate; Full Cone or cloud NAT)
//     reachable=false → NATRestricted
//  5. No probe result yet                    → NATRestricted (conservative default).
func (s *Sense) InferNATType() uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()

	// ① Public bind: local socket has a direct WAN IP — treated as Full Cone on wire.
	if s.bindPublic {
		return NATFullCone
	}

	// ② Passive mapping stability: count live votes per port bucket.
	cutoff := time.Now().Add(-voteTTL)
	total := 0
	portReporters := make(map[uint16]map[nodeIDKey]struct{})
	for key, m := range s.votes {
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
		_, ps, err := net.SplitHostPort(key)
		if err != nil {
			continue
		}
		p64, err := strconv.ParseUint(ps, 10, 16)
		if err != nil {
			continue
		}
		p := uint16(p64)
		dst := portReporters[p]
		if dst == nil {
			dst = make(map[nodeIDKey]struct{})
			portReporters[p] = dst
		}
		for rid := range reporters {
			dst[rid] = struct{}{}
		}
	}

	// Require each port bucket to have ≥2 independent reporters (1 in test mode).
	minPerPort := 2
	if s.min <= 1 {
		minPerPort = 1
	}
	supportedPorts := 0
	for _, reps := range portReporters {
		if len(reps) >= minPerPort {
			supportedPorts++
		}
	}
	if supportedPorts >= 2 {
		return NATSymmetric // different ports per destination → symmetric mapping
	}

	// ③ Not enough passive evidence to proceed.
	if total < s.min {
		return NATUnknown
	}

	// ④ Mapping is EIM (stable port); use active probe to classify filtering.
	if s.probeResult != nil && time.Since(s.probeAt) < probeResultTTL {
		if *s.probeResult {
			return NATFullCone // echo received → EIF filtering (Full Cone / cloud NAT)
		}
		return NATRestricted // echo blocked → EIF filtering restricted
	}

	// ⑤ No probe result available; conservative default.
	return NATRestricted
}

func netParseHost(host string) net.IP {
	return net.ParseIP(host)
}
