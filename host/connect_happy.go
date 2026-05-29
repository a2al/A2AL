// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// DefaultConnectStagger is the delay between starting each QUIC dial (Happy Eyeballs).
const DefaultConnectStagger = 250 * time.Millisecond

// DefaultICEStagger is the delay before starting the ICE path when racing
// direct QUIC against ICE in parallel. This gives direct QUIC a head start:
// on open networks (FullCone / public IP) the handshake completes well under
// 1 s, so the ICE path is never needed. On NAT-restricted networks where
// direct QUIC cannot succeed, ICE kicks in after this delay and the overall
// connection time is stagger + ICE setup (~2 s) rather than
// HandshakeIdleTimeout (10 s) + ICE setup.
const DefaultICEStagger = 2 * time.Second

// shouldSkipDirect reports whether direct QUIC/UDP dial should be skipped for
// an endpoint record, treating the record as a whole (record-level check).
//
// Deprecated: prefer filterDirectTargets which evaluates each candidate
// individually and preserves IPv6 GUA candidates even when the peer's v4 NAT
// type mandates skipping.
func shouldSkipDirect(er *protocol.EndpointRecord) bool {
	if er == nil || er.Signal == "" {
		return false
	}
	switch er.NatType {
	case protocol.NATRestricted, protocol.NATPortRestricted, protocol.NATSymmetric:
		return true
	}
	return false
}

// filterDirectTargets returns the subset of addrs that can be dialled directly
// without first requiring ICE negotiation.
//
// Decision logic follows the published NatType semantics (see protocol.NAT*):
//
//   - NATUnknown / NATFullCone: reachability unconfirmed or confirmed OK →
//     keep all v4 candidates; peer should attempt direct dial.
//   - NATRestricted / NATPortRestricted / NATSymmetric: peer has confirmed that
//     cold inbound v4 UDP fails → skip v4 candidates when an ICE Signal URL is
//     available as a fallback. Without a Signal URL we must try direct anyway.
//   - IPv6 GUA addresses are always kept regardless of the peer's v4 NAT type,
//     because GUA addresses are globally routable and have no inbound restriction.
func filterDirectTargets(addrs []*net.UDPAddr, er *protocol.EndpointRecord) []*net.UDPAddr {
	if er == nil || er.Signal == "" {
		// No ICE fallback available; must try all candidates directly.
		return addrs
	}
	var skipV4 bool
	switch er.NatType {
	case protocol.NATRestricted, protocol.NATPortRestricted, protocol.NATSymmetric:
		skipV4 = true
	}
	if !skipV4 {
		return addrs // NAT type is benign; all candidates are fine
	}
	var out []*net.UDPAddr
	for _, a := range addrs {
		if a.IP.To4() == nil {
			// IPv6 GUA — directly reachable regardless of the peer's v4 NAT type.
			out = append(out, a)
		}
		// IPv4 under NAT type that blocks cold inbound UDP — skip.
	}
	return out
}

// dialTargets is the internal variant of QUICDialTargets that additionally
// filters candidates by the host's local IP-family capability (hasV4/hasV6).
// v4-only hosts silently skip v6 addresses and vice versa; both-capable hosts
// receive the full list unchanged. Falls back to the full list when only one
// family has entries, ensuring connectivity is never silently discarded.
func (h *Host) dialTargets(er *protocol.EndpointRecord) ([]*net.UDPAddr, error) {
	all, err := QUICDialTargets(er)
	if err != nil {
		return nil, err
	}
	if h.hasV4 && h.hasV6 {
		return all, nil
	}
	var out []*net.UDPAddr
	for _, a := range all {
		isV6 := a.IP.To4() == nil
		if isV6 && !h.hasV6 {
			continue
		}
		if !isV6 && !h.hasV4 {
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		// No address matched our capability; fall back to full list so we
		// never silently drop all candidates (edge case: capability detection
		// returned false but the OS can actually reach the address family).
		return all, nil
	}
	return out, nil
}

// QUICDialTargets returns ordered, deduplicated UDP addresses from quic:// / udp:// entries.
func QUICDialTargets(er *protocol.EndpointRecord) ([]*net.UDPAddr, error) {
	if er == nil {
		return nil, errors.New("a2al/host: nil endpoint record")
	}
	seen := make(map[string]struct{})
	var addrs []*net.UDPAddr
	for _, e := range er.Endpoints {
		u, err := url.Parse(e)
		if err != nil || u.Host == "" || (u.Scheme != "quic" && u.Scheme != "udp") {
			continue
		}
		a, err := net.ResolveUDPAddr("udp", u.Host)
		if err != nil {
			continue
		}
		k := a.String()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, errors.New("a2al/host: no quic endpoint in record")
	}
	return addrs, nil
}

// ConnectFromRecord dials expectRemote using the following strategy:
//   - When both direct QUIC targets and a Signal URL are available and the NAT
//     type does not mandate skipping direct: race direct QUIC against ICE in
//     parallel (see connectRace). Direct gets a DefaultICEStagger head start.
//   - When only direct targets are available (no Signal): Happy Eyeballs only.
//   - When direct must be skipped or no targets exist (Signal required): ICE only.
//
// The host's default agent identity is used for mutual TLS.
//
// On any failure the locally-cached endpoint record for expectRemote is
// transparently invalidated so the next Resolve fetches fresh data.
func (h *Host) ConnectFromRecord(ctx context.Context, expectRemote a2al.Address, er *protocol.EndpointRecord) (_ quic.Connection, _ bool, err error) {
	cert, certErr := h.defaultAgentCert()
	if certErr != nil {
		return nil, false, certErr
	}
	defer func() {
		if err != nil {
			h.node.LocalStoreInvalidate(a2al.NodeIDFromAddress(expectRemote), protocol.RecTypeEndpoint)
		}
	}()

	targets, terr := h.dialTargets(er)
	natType := protocol.NATUnknown
	hasSignal := false
	if er != nil {
		natType = er.NatType
		hasSignal = er.Signal != ""
	}
	// Per-candidate filter: v6 GUA candidates remain even when v4 NAT type would
	// otherwise mandate ICE-only.
	directTargets := filterDirectTargets(targets, er)
	h.log.Debug("connect path decision",
		"remote_aid", expectRemote.String(),
		"nat_type", natType,
		"has_signal", hasSignal,
		"quic_targets", len(targets),
		"direct_targets", len(directTargets),
	)
	if len(directTargets) > 0 && hasSignal {
		return h.connectRace(ctx, cert, h.addr, expectRemote, directTargets, er, false)
	}
	if len(directTargets) > 0 {
		conn, err := h.connectHappy(ctx, cert, expectRemote, directTargets, DefaultConnectStagger)
		return conn, false, err
	}
	if hasSignal {
		return h.connectViaICESignal(ctx, cert, h.addr, expectRemote, er, false)
	}
	if terr != nil {
		return nil, false, terr
	}
	return nil, false, errors.New("a2al/host: no quic targets and no signal url")
}

// ConnectFromRecordFor dials as localAgent (must be registered) toward expectRemote.
// Uses the same race/direct/ICE strategy as ConnectFromRecord.
//
// On failure the locally-cached endpoint record for expectRemote is transparently
// invalidated (same as ConnectFromRecord).
func (h *Host) ConnectFromRecordFor(ctx context.Context, localAgent, expectRemote a2al.Address, er *protocol.EndpointRecord, opts DialOptions) (_ quic.Connection, _ bool, err error) {
	h.agentsMu.RLock()
	ag, ok := h.agents[localAgent]
	h.agentsMu.RUnlock()
	if !ok {
		return nil, false, fmt.Errorf("a2al/host: unknown agent %s", localAgent)
	}
	defer func() {
		if err != nil {
			h.node.LocalStoreInvalidate(a2al.NodeIDFromAddress(expectRemote), protocol.RecTypeEndpoint)
		}
	}()

	targets, terr := h.dialTargets(er)
	natType := protocol.NATUnknown
	hasSignal := false
	if er != nil {
		natType = er.NatType
		hasSignal = er.Signal != ""
	}
	directTargets := filterDirectTargets(targets, er)
	h.log.Debug("connect path decision",
		"local_aid", localAgent.String(),
		"remote_aid", expectRemote.String(),
		"nat_type", natType,
		"has_signal", hasSignal,
		"quic_targets", len(targets),
		"direct_targets", len(directTargets),
	)
	if len(directTargets) > 0 && hasSignal {
		return h.connectRace(ctx, ag.cert, localAgent, expectRemote, directTargets, er, opts.DisableRelay)
	}
	if len(directTargets) > 0 {
		conn, err := h.connectHappy(ctx, ag.cert, expectRemote, directTargets, DefaultConnectStagger)
		return conn, false, err
	}
	if hasSignal {
		return h.connectViaICESignal(ctx, ag.cert, localAgent, expectRemote, er, opts.DisableRelay)
	}
	if terr != nil {
		return nil, false, terr
	}
	return nil, false, errors.New("a2al/host: no quic targets and no signal url")
}

// connectRace runs direct QUIC and ICE in parallel, returning the first
// successful connection. Direct QUIC starts immediately; ICE starts after
// DefaultICEStagger to give direct a head start on open networks.
//
// When a winner is found the losing path's context is cancelled so its
// goroutine exits promptly. Both goroutines always send exactly one value to
// the buffered channel, so the collector never blocks indefinitely.
func (h *Host) connectRace(ctx context.Context, localCert tls.Certificate, localAgent, expectRemote a2al.Address, targets []*net.UDPAddr, er *protocol.EndpointRecord, disableRelay bool) (quic.Connection, bool, error) {
	type res struct {
		c         quic.Connection
		isRelayed bool
		err       error
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	ch := make(chan res, 2)

	// Direct QUIC — starts immediately.
	go func() {
		c, err := h.connectHappy(raceCtx, localCert, expectRemote, targets, DefaultConnectStagger)
		ch <- res{c: c, err: err}
	}()

	// ICE — starts after stagger so direct can win on open networks.
	go func() {
		t := time.NewTimer(DefaultICEStagger)
		defer t.Stop()
		select {
		case <-raceCtx.Done():
			ch <- res{err: raceCtx.Err()}
			return
		case <-t.C:
		}
		c, relayed, err := h.connectViaICESignal(raceCtx, localCert, localAgent, expectRemote, er, disableRelay)
		ch <- res{c: c, isRelayed: relayed, err: err}
	}()

	var winner quic.Connection
	var winnerRelayed bool
	var errs []error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil && r.c != nil {
			if winner == nil {
				winner = r.c
				winnerRelayed = r.isRelayed
				raceCancel()
			} else {
				_ = r.c.CloseWithError(0, "superseded by faster candidate")
			}
			continue
		}
		if r.err != nil {
			errs = append(errs, r.err)
		}
	}
	if winner != nil {
		return winner, winnerRelayed, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return nil, false, errors.Join(errs...)
}

func (h *Host) connectHappy(ctx context.Context, localCert tls.Certificate, expectRemote a2al.Address, targets []*net.UDPAddr, stagger time.Duration) (quic.Connection, error) {
	if len(targets) == 0 {
		return nil, errors.New("a2al/host: no dial targets")
	}
	if stagger <= 0 {
		stagger = DefaultConnectStagger
	}

	type dialRes struct {
		c           quic.Connection
		err         error
		addr        *net.UDPAddr // address that was dialled
		wasCanceled bool         // true when failure was caused by gctx cancellation
	}
	gctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resCh := make(chan dialRes, len(targets))
	var wg sync.WaitGroup
	for i, addr := range targets {
		i, addr := i, addr
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i > 0 {
				t := time.NewTimer(time.Duration(i) * stagger)
				select {
				case <-gctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
			}
			if gctx.Err() != nil {
				return
			}
			c, err := h.dialAndAgentRoute(gctx, localCert, expectRemote, addr)
			// wasCanceled is true when the failure is directly caused by context
			// cancellation (a sibling dial already won).  We use errors.Is rather
			// than inspecting gctx.Err() because the cancel signal and the dial
			// error are independent events; checking the error itself is precise.
			resCh <- dialRes{c: c, err: err, addr: addr, wasCanceled: errors.Is(err, context.Canceled)}
		}()
	}
	go func() {
		wg.Wait()
		close(resCh)
	}()

	var winner quic.Connection
	var errs []error
	for r := range resCh {
		if r.err == nil && r.c != nil {
			if winner == nil {
				winner = r.c
				cancel()
				continue
			}
			_ = r.c.CloseWithError(0, "superseded by faster candidate")
			continue
		}
		if r.err != nil {
			// Report genuine transport failures to the DHT health subsystem so it
			// can revoke the fresh-live preference and update backoff state.
			// Two cases must be excluded:
			//   wasCanceled: context.Canceled means a sibling dial already won.
			//   controlStreamError: the QUIC handshake succeeded — the path is
			//     reachable; the failure is application-level, not transport-level.
			var csErr *controlStreamError
			if !r.wasCanceled && !errors.As(r.err, &csErr) {
				h.node.NotePeerDialFailure(a2al.NodeIDFromAddress(expectRemote), r.addr)
			}
			errs = append(errs, r.err)
		}
	}
	if winner != nil {
		return winner, nil
	}
	if len(errs) == 0 {
		return nil, errors.New("a2al/host: all dials canceled")
	}
	return nil, fmt.Errorf("a2al/host: all dials failed: %w", errors.Join(errs...))
}
