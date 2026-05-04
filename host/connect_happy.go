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

// shouldSkipDirect reports whether the direct QUIC/UDP dial should be skipped
// for an endpoint record. Direct dialing is skipped when the peer's NAT type
// makes a cold UDP connection essentially impossible and an ICE signal URL is
// available to negotiate a punched path instead.
//
// Skipped NAT types (with signal required):
//   - NATRestricted: address-restricted cone — inbound UDP blocked without prior outbound
//   - NATPortRestricted: port-restricted cone — same, plus port must match
//   - NATSymmetric: each outbound mapping uses a unique port, prediction impossible
//
// NATUnknown and NATFullCone are left for direct-dial first; ICE is attempted
// only if the direct dial fails.
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
func (h *Host) ConnectFromRecord(ctx context.Context, expectRemote a2al.Address, er *protocol.EndpointRecord) (_ quic.Connection, err error) {
	cert, certErr := h.defaultAgentCert()
	if certErr != nil {
		return nil, certErr
	}
	defer func() {
		if err != nil {
			h.node.LocalStoreInvalidate(a2al.NodeIDFromAddress(expectRemote), protocol.RecTypeEndpoint)
		}
	}()

	targets, terr := QUICDialTargets(er)
	natType := protocol.NATUnknown
	hasSignal := false
	if er != nil {
		natType = er.NatType
		hasSignal = er.Signal != ""
	}
	skipDirect := shouldSkipDirect(er)
	h.log.Debug("connect path decision",
		"remote_aid", expectRemote.String(),
		"nat_type", natType,
		"has_signal", hasSignal,
		"quic_targets", len(targets),
		"skip_direct", skipDirect,
	)
	if !skipDirect && len(targets) > 0 && hasSignal {
		return h.connectRace(ctx, cert, h.addr, expectRemote, targets, er)
	}
	if !skipDirect && len(targets) > 0 {
		return h.connectHappy(ctx, cert, expectRemote, targets, DefaultConnectStagger)
	}
	if hasSignal {
		return h.connectViaICESignal(ctx, cert, h.addr, expectRemote, er)
	}
	if terr != nil {
		return nil, terr
	}
	return nil, errors.New("a2al/host: no quic targets and no signal url")
}

// ConnectFromRecordFor dials as localAgent (must be registered) toward expectRemote.
// Uses the same race/direct/ICE strategy as ConnectFromRecord.
//
// On failure the locally-cached endpoint record for expectRemote is transparently
// invalidated (same as ConnectFromRecord).
func (h *Host) ConnectFromRecordFor(ctx context.Context, localAgent, expectRemote a2al.Address, er *protocol.EndpointRecord) (_ quic.Connection, err error) {
	h.agentsMu.RLock()
	ag, ok := h.agents[localAgent]
	h.agentsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("a2al/host: unknown agent %s", localAgent)
	}
	defer func() {
		if err != nil {
			h.node.LocalStoreInvalidate(a2al.NodeIDFromAddress(expectRemote), protocol.RecTypeEndpoint)
		}
	}()

	targets, terr := QUICDialTargets(er)
	natType := protocol.NATUnknown
	hasSignal := false
	if er != nil {
		natType = er.NatType
		hasSignal = er.Signal != ""
	}
	skipDirect := shouldSkipDirect(er)
	h.log.Debug("connect path decision",
		"local_aid", localAgent.String(),
		"remote_aid", expectRemote.String(),
		"nat_type", natType,
		"has_signal", hasSignal,
		"quic_targets", len(targets),
		"skip_direct", skipDirect,
	)
	if !skipDirect && len(targets) > 0 && hasSignal {
		return h.connectRace(ctx, ag.cert, localAgent, expectRemote, targets, er)
	}
	if !skipDirect && len(targets) > 0 {
		return h.connectHappy(ctx, ag.cert, expectRemote, targets, DefaultConnectStagger)
	}
	if hasSignal {
		return h.connectViaICESignal(ctx, ag.cert, localAgent, expectRemote, er)
	}
	if terr != nil {
		return nil, terr
	}
	return nil, errors.New("a2al/host: no quic targets and no signal url")
}

// connectRace runs direct QUIC and ICE in parallel, returning the first
// successful connection. Direct QUIC starts immediately; ICE starts after
// DefaultICEStagger to give direct a head start on open networks.
//
// When a winner is found the losing path's context is cancelled so its
// goroutine exits promptly. Both goroutines always send exactly one value to
// the buffered channel, so the collector never blocks indefinitely.
func (h *Host) connectRace(ctx context.Context, localCert tls.Certificate, localAgent, expectRemote a2al.Address, targets []*net.UDPAddr, er *protocol.EndpointRecord) (quic.Connection, error) {
	type res struct {
		c   quic.Connection
		err error
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	ch := make(chan res, 2)

	// Direct QUIC — starts immediately.
	go func() {
		c, err := h.connectHappy(raceCtx, localCert, expectRemote, targets, DefaultConnectStagger)
		ch <- res{c, err}
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
		c, err := h.connectViaICESignal(raceCtx, localCert, localAgent, expectRemote, er)
		ch <- res{c, err}
	}()

	var winner quic.Connection
	var errs []error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil && r.c != nil {
			if winner == nil {
				winner = r.c
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
		return winner, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.Join(errs...)
}

func (h *Host) connectHappy(ctx context.Context, localCert tls.Certificate, expectRemote a2al.Address, targets []*net.UDPAddr, stagger time.Duration) (quic.Connection, error) {
	if len(targets) == 0 {
		return nil, errors.New("a2al/host: no dial targets")
	}
	if stagger <= 0 {
		stagger = DefaultConnectStagger
	}

	type dialRes struct {
		c   quic.Connection
		err error
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
			resCh <- dialRes{c, err}
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
