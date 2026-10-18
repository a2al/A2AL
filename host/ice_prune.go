// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	ice "github.com/pion/ice/v3"
	"github.com/pion/transport/v3"
	"github.com/pion/transport/v3/stdnet"
)

// Unselected candidate pruning (RFC 8445 §8.3). pion v3 keeps every gathered
// candidate socket until Agent.Close. Once the selected pair has been stable
// for icePruneGrace, sockets that cannot carry it are closed.
//
// Rule: when in doubt, keep. Only host and srflx selections are pruned; relay,
// unknown types, or no matching socket skip pruning entirely. Sockets left open
// are still closed by Agent.Close. See doc-local/ICE与QUIC关闭原则.md.
const (
	// icePruneGrace is measured from the last selected-pair change. pion
	// nominates once; this covers in-flight nomination retransmits (RFC: 3 s).
	icePruneGrace = 10 * time.Second
	// icePruneFailWindow: ICE Failed this soon after a prune counts against
	// the process-wide circuit breaker.
	icePruneFailWindow  = 60 * time.Second
	icePruneMaxFailures = 2
)

var (
	icePruneFailures atomic.Int32
	icePruneDisabled atomic.Bool
)

// candidateNet records UDP sockets pion binds via ListenUDP (host and srflx
// candidates). Relay sockets (ListenPacket) and Dial* sockets are not recorded.
type candidateNet struct {
	*stdnet.Net
	mu    sync.Mutex
	conns []transport.UDPConn
}

func newCandidateNet() (*candidateNet, error) {
	n, err := stdnet.NewNet()
	if err != nil {
		return nil, err
	}
	return &candidateNet{Net: n}, nil
}

func (n *candidateNet) ListenUDP(network string, laddr *net.UDPAddr) (transport.UDPConn, error) {
	c, err := n.Net.ListenUDP(network, laddr)
	if err == nil {
		n.mu.Lock()
		n.conns = append(n.conns, c)
		n.mu.Unlock()
	}
	return c, err
}

// closeExceptPort closes recorded sockets not bound to port. If none is bound
// to port, the selection cannot be identified and nothing is closed.
func (n *candidateNet) closeExceptPort(port int) int {
	n.mu.Lock()
	var keep, drop []transport.UDPConn
	matched := false
	for _, c := range n.conns {
		ua, _ := c.LocalAddr().(*net.UDPAddr)
		switch {
		case ua == nil:
			keep = append(keep, c)
		case ua.Port == port:
			matched = true
			keep = append(keep, c)
		default:
			drop = append(drop, c)
		}
	}
	if !matched {
		n.mu.Unlock()
		return 0
	}
	n.conns = keep
	n.mu.Unlock()
	for _, c := range drop {
		_ = c.Close()
	}
	return len(drop)
}

// selectedBasePort returns the local socket port carrying the selected pair.
func selectedBasePort(c ice.Candidate) (int, bool) {
	switch c.Type() {
	case ice.CandidateTypeHost:
		return c.Port(), c.Port() > 0
	case ice.CandidateTypeServerReflexive:
		if ra := c.RelatedAddress(); ra != nil && ra.Port > 0 {
			return ra.Port, true
		}
	}
	return 0, false
}

// schedulePrune (re)arms pruning icePruneGrace after a selected-pair change.
func (s *iceSession) schedulePrune() {
	if s.cnet == nil || icePruneDisabled.Load() {
		return
	}
	s.pruneMu.Lock()
	defer s.pruneMu.Unlock()
	if s.pruneDone {
		return
	}
	if s.pruneTimer == nil {
		s.pruneTimer = time.AfterFunc(icePruneGrace, s.pruneUnselected)
		return
	}
	s.pruneTimer.Reset(icePruneGrace)
}

func (s *iceSession) stopPrune() {
	s.pruneMu.Lock()
	s.pruneDone = true
	if s.pruneTimer != nil {
		s.pruneTimer.Stop()
	}
	s.pruneMu.Unlock()
}

// pruneUnselected runs once. Any doubt (closed, not Connected, no pair,
// relay/unknown type, no matching socket) skips without closing anything.
func (s *iceSession) pruneUnselected() {
	s.pruneMu.Lock()
	if s.pruneDone {
		s.pruneMu.Unlock()
		return
	}
	s.pruneDone = true
	s.pruneMu.Unlock()

	if icePruneDisabled.Load() || s.agentClosed.Load() || !s.iceConnected.Load() {
		return
	}
	pair, err := s.agent.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return
	}
	port, ok := selectedBasePort(pair.Local)
	if !ok {
		return
	}
	if n := s.cnet.closeExceptPort(port); n > 0 {
		s.prunedAt.Store(time.Now().UnixNano())
		slog.Debug("ice pruned unselected candidate sockets", "closed", n, "kept_port", port, "local_type", pair.Local.Type())
	}
}

// onICEState tracks Connected for pruning and feeds the circuit breaker.
func (s *iceSession) onICEState(st ice.ConnectionState) {
	s.iceConnected.Store(st == ice.ConnectionStateConnected)
	if st != ice.ConnectionStateFailed {
		return
	}
	at := s.prunedAt.Load()
	if at == 0 || time.Since(time.Unix(0, at)) > icePruneFailWindow {
		return
	}
	if icePruneFailures.Add(1) >= icePruneMaxFailures && icePruneDisabled.CompareAndSwap(false, true) {
		slog.Warn("ice candidate pruning disabled: ICE failed shortly after pruning", "failures", icePruneMaxFailures)
	}
}
