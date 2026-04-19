// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/signaling"
)

// noAgentRetries is the number of extra attempts after a "noagent" response.
// A noagent reply means the callee is momentarily unregistered (e.g. reconnect
// after keepalive gap). Two retries with a 3 s pause each cover the typical
// 2–5 s reconnect window without significantly delaying callers in the normal
// (non-noagent) path.
const noAgentRetries = 2

// noAgentRetryDelay is the pause between noagent retry attempts.
const noAgentRetryDelay = 3 * time.Second

// connectViaICESignal is the controlling (caller) ICE path:
// WebSocket signaling → ICE pair selection → QUIC over ICE → agent-route.
//
// Resource lifecycle: the ICE session (agent, WS) and quic.Transport are tied
// to the returned quic.Connection via a background goroutine that cleans them
// up when the connection closes. The caller must NOT close these resources
// separately.
func (h *Host) connectViaICESignal(ctx context.Context, localCert tls.Certificate, localAgent, expectRemote a2al.Address, er *protocol.EndpointRecord) (quic.Connection, error) {
	if er == nil || er.Signal == "" {
		return nil, errors.New("a2al/host: no signal url in record")
	}
	room := signaling.RoomID(localAgent.String(), expectRemote.String())
	wsURL, err := signaling.AppendRoomToICEURL(er.Signal, room)
	if err != nil {
		return nil, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}
	wsURL, err = signaling.AppendQuery(wsURL, "target", expectRemote.String())
	if err != nil {
		return nil, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}
	wsURL, err = signaling.AppendQuery(wsURL, "caller", localAgent.String())
	if err != nil {
		return nil, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}

	urls := h.mergeICEURLs(ctx)
	var sess *iceSession
	for attempt := 0; attempt <= noAgentRetries; attempt++ {
		h.log.Debug("ice dial attempt", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "attempt", attempt+1, "max_attempts", noAgentRetries+1)
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(noAgentRetryDelay):
			}
		}
		sess, err = runICESession(ctx, wsURL, urls, true, false)
		if !errors.Is(err, ErrNoAgent) {
			break
		}
		h.log.Debug("ice dial retry on noagent", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "attempt", attempt+1)
	}
	if err != nil {
		h.log.Warn("ice session failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "err", err)
		return nil, err
	}

	pconn := &icePacketConn{c: sess.iceConn}
	tr := &quic.Transport{Conn: pconn}

	// From here, cleanup on error via this helper.
	teardown := func() {
		_ = tr.Close()
		sess.CloseSignaling()
	}

	ra := sess.iceConn.RemoteAddr()
	udpRA, ok := ra.(*net.UDPAddr)
	if !ok || udpRA == nil {
		teardown()
		return nil, fmt.Errorf("a2al/host: ice remote addr is %T", ra)
	}
	cliTLS, err := quicClientTLSWithCert(localCert, expectRemote)
	if err != nil {
		teardown()
		return nil, err
	}
	qc, err := tr.Dial(ctx, udpRA, cliTLS, defaultQUICConfig())
	if err != nil {
		h.log.Warn("quic dial over ice failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "dst", udpRA, "err", err)
		teardown()
		return nil, err
	}
	h.log.Debug("quic dial over ice ok", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "dst", udpRA)
	if err := h.doDialerControlStream(ctx, qc, expectRemote); err != nil {
		h.log.Warn("agent-route over ice failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "err", err)
		_ = qc.CloseWithError(1, "agent-route")
		teardown()
		return nil, err
	}

	// Tie resource lifetime to the QUIC connection: when it closes (idle
	// timeout, explicit close, error) the Transport and WS are cleaned up.
	go func() {
		<-qc.Context().Done()
		h.log.Debug("ice quic closed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "close_reason", qc.Context().Err())
		_ = tr.Close()
		sess.CloseSignaling()
	}()
	return qc, nil
}

// AcceptICEViaSignal is the controlled (callee) side: WebSocket ICE signaling
// on signalBase, then QUIC-over-ICE. expectRemote is the caller's agent address.
//
// Same lifetime semantics as connectViaICESignal — resources are freed when
// the AgentConn's underlying QUIC connection closes.
func (h *Host) AcceptICEViaSignal(ctx context.Context, localAgent, expectRemote a2al.Address, signalBase string) (*AgentConn, error) {
	if signalBase == "" {
		return nil, errors.New("a2al/host: empty signal base url")
	}
	h.agentsMu.RLock()
	ag, ok := h.agents[localAgent]
	h.agentsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("a2al/host: unknown agent %s", localAgent)
	}

	room := signaling.RoomID(localAgent.String(), expectRemote.String())
	wsURL, err := signaling.AppendRoomToICEURL(signalBase, room)
	if err != nil {
		return nil, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}

	urls := h.mergeICEURLs(ctx)
	sess, err := runICESession(ctx, wsURL, urls, false, false)
	if err != nil {
		return nil, err
	}

	pconn := &icePacketConn{c: sess.iceConn}
	tr := &quic.Transport{Conn: pconn}

	teardown := func() {
		_ = tr.Close()
		sess.CloseSignaling()
	}

	srvTLS := quicServerTLSWithSNI(ag.cert, h.certForSNI)
	ln, err := tr.Listen(srvTLS, defaultQUICConfig())
	if err != nil {
		teardown()
		return nil, err
	}

	qc, err := ln.Accept(ctx)
	_ = ln.Close() // stop accepting; the connection is already established
	if err != nil {
		teardown()
		return nil, err
	}

	ac, err := h.agentConnFromQUIC(ctx, qc, localAgent)
	if err != nil {
		_ = qc.CloseWithError(1, "agent-route")
		teardown()
		return nil, err
	}
	if ac.Remote != expectRemote {
		h.log.Warn("ice peer mismatch", "local_aid", localAgent.String(), "expected_remote", expectRemote.String(), "actual_remote", ac.Remote.String())
		_ = qc.CloseWithError(1, "peer mismatch")
		teardown()
		return nil, fmt.Errorf("a2al/host: ICE quic peer want %s got %s", expectRemote, ac.Remote)
	}

	go func() {
		<-qc.Context().Done()
		_ = tr.Close()
		sess.CloseSignaling()
	}()
	return ac, nil
}
