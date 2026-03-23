// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package natsense implements observed address consensus (spec Phase 2a: ≥3 distinct reporters).
// For tests or small networks, set MinAgreeingPeers to 1.
package natsense

import (
	"net"
	"strconv"
	"sync"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// NAT type constants (mirror protocol.NAT* for convenience).
const (
	NATUnknown       uint8 = 0
	NATFullCone      uint8 = 1
	NATRestricted    uint8 = 2
	NATPortRestrict  uint8 = 3
	NATSymmetric     uint8 = 4
)

const defaultMinAgree = 3

// Sense tracks distinct peers that reported the same reflected UDP endpoint (wire bytes)
// and infers a basic NAT type from observed port consistency.
type Sense struct {
	mu sync.Mutex
	// min distinct NodeIDs that must have reported the same canonical key
	min int
	// canonical key "host:port" -> reporters
	votes map[string]map[nodeIDKey]struct{}
	// distinct observed ports (for NAT type inference)
	observedPorts map[uint16]struct{}
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
		votes:         make(map[string]map[nodeIDKey]struct{}),
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
		m = make(map[nodeIDKey]struct{})
		s.votes[key] = m
	}
	m[z] = struct{}{}
	s.observedPorts[port] = struct{}{}
}

// TrustedUDP returns host and port if some observed key has >= min distinct reporters.
func (s *Sense) TrustedUDP() (host string, port uint16, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, reps := range s.votes {
		if len(reps) < s.min {
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

// InferNATType returns a basic NAT type inference based on observed port
// consistency across reporters (spec Phase 2a):
//   - All reporters saw the same port → endpoint-independent mapping (FullCone/Restricted)
//   - Different ports → NATSymmetric
//   - Insufficient data → NATUnknown
//
// Distinguishing FullCone from Restricted requires active probing (Phase 2b).
func (s *Sense) InferNATType() uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, m := range s.votes {
		total += len(m)
	}
	if total < s.min {
		return NATUnknown
	}
	if len(s.observedPorts) == 1 {
		return NATFullCone // or restricted — indistinguishable without active probing
	}
	if len(s.observedPorts) > 1 {
		return NATSymmetric
	}
	return NATUnknown
}

func netParseHost(host string) net.IP {
	return net.ParseIP(host)
}
