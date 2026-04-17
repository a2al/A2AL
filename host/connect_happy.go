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

// ConnectFromRecord dials expectRemote using the three-layer strategy:
// ① Happy Eyeballs over quic:// candidates → ② ICE via signal (if record has Signal).
// The host's default agent identity is used for mutual TLS.
func (h *Host) ConnectFromRecord(ctx context.Context, expectRemote a2al.Address, er *protocol.EndpointRecord) (quic.Connection, error) {
	targets, terr := QUICDialTargets(er)
	var happyErr error
	natType := protocol.NATUnknown
	hasSignal := false
	if er != nil {
		natType = er.NatType
		hasSignal = er.Signal != ""
	}
	skipDirect := er != nil && er.NatType == protocol.NATSymmetric && er.Signal != ""
	h.log.Debug("connect path decision",
		"remote_aid", expectRemote.String(),
		"nat_type", natType,
		"has_signal", hasSignal,
		"quic_targets", len(targets),
		"skip_direct", skipDirect,
	)
	if !skipDirect && len(targets) > 0 {
		cert, err := h.defaultAgentCert()
		if err != nil {
			return nil, err
		}
		c, err := h.connectHappy(ctx, cert, expectRemote, targets, DefaultConnectStagger)
		if err == nil {
			return c, nil
		}
		h.log.Debug("connect direct failed, fallback maybe needed", "remote_aid", expectRemote.String(), "err", err)
		happyErr = err
	} else if len(targets) == 0 {
		happyErr = terr
	}
	if er == nil || er.Signal == "" {
		if happyErr != nil {
			return nil, happyErr
		}
		return nil, errors.New("a2al/host: no quic targets and no signal url")
	}
	h.log.Debug("connect via ice", "remote_aid", expectRemote.String(), "signal", hasSignal)
	cert, err := h.defaultAgentCert()
	if err != nil {
		return nil, err
	}
	iceConn, err := h.connectViaICESignal(ctx, cert, h.addr, expectRemote, er)
	if err != nil {
		h.log.Warn("connect ice failed", "remote_aid", expectRemote.String(), "err", err)
		if happyErr != nil {
			return nil, errors.Join(happyErr, fmt.Errorf("ice: %w", err))
		}
		return nil, err
	}
	return iceConn, nil
}

// ConnectFromRecordFor dials as localAgent (must be registered) toward expectRemote.
// After Happy Eyeballs over quic:// candidates fails, if the record includes Signal, falls back to ICE+QUIC over WebSocket signaling.
func (h *Host) ConnectFromRecordFor(ctx context.Context, localAgent, expectRemote a2al.Address, er *protocol.EndpointRecord) (quic.Connection, error) {
	h.agentsMu.RLock()
	ag, ok := h.agents[localAgent]
	h.agentsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("a2al/host: unknown agent %s", localAgent)
	}
	targets, terr := QUICDialTargets(er)
	var happyErr error
	natType := protocol.NATUnknown
	hasSignal := false
	if er != nil {
		natType = er.NatType
		hasSignal = er.Signal != ""
	}
	skipDirect := er != nil && er.NatType == protocol.NATSymmetric && er.Signal != ""
	h.log.Debug("connect path decision",
		"local_aid", localAgent.String(),
		"remote_aid", expectRemote.String(),
		"nat_type", natType,
		"has_signal", hasSignal,
		"quic_targets", len(targets),
		"skip_direct", skipDirect,
	)
	if !skipDirect && len(targets) > 0 {
		c, err := h.connectHappy(ctx, ag.cert, expectRemote, targets, DefaultConnectStagger)
		if err == nil {
			return c, nil
		}
		h.log.Debug("connect direct failed, fallback maybe needed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "err", err)
		happyErr = err
	} else if len(targets) == 0 {
		happyErr = terr
	}
	if er == nil || er.Signal == "" {
		if happyErr != nil {
			return nil, happyErr
		}
		return nil, errors.New("a2al/host: no quic targets and no signal url")
	}
	h.log.Debug("connect via ice", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "signal", hasSignal)
	iceConn, err := h.connectViaICESignal(ctx, ag.cert, localAgent, expectRemote, er)
	if err != nil {
		h.log.Warn("connect ice failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "err", err)
		if happyErr != nil {
			return nil, errors.Join(happyErr, fmt.Errorf("ice: %w", err))
		}
		return nil, err
	}
	return iceConn, nil
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
