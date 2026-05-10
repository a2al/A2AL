// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"net"
	"sync"
	"time"

	ice "github.com/pion/ice/v3"

	"github.com/a2al/a2al"
)

// iceCacheTTL is how long a cached ICE endpoint hint remains valid. UDP NAT
// port mappings on most hardware survive 30 s–5 min of inactivity, so hints
// older than iceCacheTTL are unlikely to be reachable and are silently dropped.
const iceCacheTTL = 5 * time.Minute

// iceHint is a single cached remote UDP endpoint observed in a past successful
// ICE session. CandType is preserved from the original ICE candidate so the
// hint can be injected with the correct type priority.
type iceHint struct {
	addr     net.UDPAddr
	candType ice.CandidateType
	ts       time.Time
}

// peerICECache is a Host-level store of recently observed remote ICE endpoints
// keyed by remote agent AID. It is safe for concurrent use.
//
// After each successful ICE session the selected candidate pair and all
// non-relay remote candidates are recorded. On the next session to the same
// peer the cached endpoints are injected into the new ICE agent immediately
// after credential exchange, before trickle candidates arrive. This gives the
// connectivity checker a head start on known-good paths and reduces the time to
// first STUN check success — especially when the NAT hole from a previous
// session is still open.
//
// Relay (TURN) candidates are intentionally excluded: TURN allocations are
// session-specific and a cached relay address will not be routable in a new
// session.
type peerICECache struct {
	mu    sync.RWMutex
	hints map[a2al.Address][]iceHint
}

func (c *peerICECache) init() {
	c.hints = make(map[a2al.Address][]iceHint)
}

// Hints returns the non-expired cached hints for the given remote AID.
// The caller should inject each hint into the ICE agent as a remote candidate.
func (c *peerICECache) Hints(remote a2al.Address) []iceHint {
	now := time.Now()
	c.mu.RLock()
	all := c.hints[remote]
	c.mu.RUnlock()

	var out []iceHint
	for _, h := range all {
		if now.Sub(h.ts) < iceCacheTTL {
			out = append(out, h)
		}
	}
	return out
}

// Record adds remote ICE candidates from a completed session to the cache.
// Only non-relay candidates are stored. selected should be the result of
// agent.GetSelectedCandidatePair(); additional is the full set of remote
// candidates received during trickle ICE.
//
// The selected pair is prepended so that on the next dial it is tried first.
// Entries are deduplicated by UDP address.
func (c *peerICECache) Record(remote a2al.Address, selected ice.Candidate, additional []ice.Candidate) {
	seen := make(map[string]struct{})
	var hints []iceHint
	now := time.Now()

	add := func(cand ice.Candidate) {
		if cand == nil || cand.Type() == ice.CandidateTypeRelay {
			return
		}
		ip := net.ParseIP(cand.Address())
		if ip == nil {
			return
		}
		addr := net.UDPAddr{IP: ip, Port: cand.Port()}
		key := addr.String()
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		hints = append(hints, iceHint{addr: addr, candType: cand.Type(), ts: now})
	}

	add(selected)
	for _, c := range additional {
		add(c)
	}

	if len(hints) == 0 {
		return
	}

	c.mu.Lock()
	c.hints[remote] = hints
	c.mu.Unlock()
}
