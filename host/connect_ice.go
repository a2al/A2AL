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

	"github.com/pion/stun/v2"
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
// Signal hub selection: prefer er.Signals (multi-center list); fall back to
// er.Signal for backward compatibility with old peers. Hubs are tried in order;
// the first successful ICE session wins. noAgentRetries are applied per hub.
//
// Resource lifecycle: the ICE session (agent, WS) and quic.Transport are tied
// to the returned quic.Connection via a background goroutine that cleans them
// up when the connection closes. The caller must NOT close these resources
// separately.
func (h *Host) connectViaICESignal(ctx context.Context, localCert tls.Certificate, localAgent, expectRemote a2al.Address, er *protocol.EndpointRecord) (quic.Connection, error) {
	signalURLs := er.Signals
	if len(signalURLs) == 0 && er.Signal != "" {
		signalURLs = []string{er.Signal}
	}
	if len(signalURLs) == 0 {
		return nil, errors.New("a2al/host: no signal url in record")
	}

	room := signaling.RoomID(localAgent.String(), expectRemote.String())
	iceURLs := h.mergeICEURLs(ctx)

	var lastErr error
	for _, signalBase := range signalURLs {
		qc, err := h.tryICEViaHub(ctx, localCert, localAgent, expectRemote, signalBase, room, iceURLs)
		if err == nil {
			return qc, nil
		}
		h.log.Debug("ice signal hub failed, trying next", "base", signalBase, "err", err)
		lastErr = err
	}
	return nil, lastErr
}

// tryICEViaHub attempts a full ICE → QUIC handshake through one signal hub.
// noAgentRetries are applied when the hub reports the callee is not registered.
func (h *Host) tryICEViaHub(ctx context.Context, localCert tls.Certificate, localAgent, expectRemote a2al.Address, signalBase, room string, iceURLs []*stun.URI) (quic.Connection, error) {
	wsURL, err := signaling.AppendRoomToICEURL(signalBase, room)
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

	var sess *iceSession
	for attempt := 0; attempt <= noAgentRetries; attempt++ {
		h.log.Debug("ice dial attempt", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "attempt", attempt+1, "max_attempts", noAgentRetries+1)
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(noAgentRetryDelay):
			}
		}
		sess, err = runICESession(ctx, wsURL, iceURLs, true, false)
		if !errors.Is(err, ErrNoAgent) {
			break
		}
		h.log.Debug("ice dial retry on noagent", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "attempt", attempt+1)
	}
	if err != nil {
		h.log.Warn("ice session failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "err", err)
		return nil, err
	}

	pconn := &icePacketConn{c: sess.iceConn}
	tr := &quic.Transport{Conn: pconn}

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
		h.log.Warn("quic dial over ice failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "dst", udpRA, "err", err)
		teardown()
		return nil, err
	}
	h.log.Debug("quic dial over ice ok", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "dst", udpRA)
	if err := h.doDialerControlStream(ctx, qc, expectRemote); err != nil {
		h.log.Warn("agent-route over ice failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "err", err)
		_ = qc.CloseWithError(1, "agent-route")
		teardown()
		return nil, err
	}

	// Tie resource lifetime to the QUIC connection.
	go func() {
		<-qc.Context().Done()
		h.log.Debug("ice quic closed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "close_reason", qc.Context().Err())
		_ = tr.Close()
		sess.CloseSignaling()
	}()
	return qc, nil
}

// acceptICEToQUIC runs the controlled (callee) side of ICE signaling, then
// builds a QUIC listener and accepts exactly one incoming connection.
// It returns the raw QUIC connection and the peer's UDP address without
// performing any upper-layer handshake (agent-route or DHT).
//
// qcfg selects the QUIC configuration; pass defaultQUICConfig() for Mode A
// (agent connections) or modeBQUICConfig() for Mode B (DHT control plane).
//
// isDirect is true when the selected ICE candidate pair is host/srflx on the
// remote side, indicating the remote is directly reachable without NAT punching.
// Used by Phase 8 reclassification in DHTpunchPool.
//
// The caller must invoke teardown when the connection is no longer needed.
func (h *Host) acceptICEToQUIC(ctx context.Context, wsURL string, cert tls.Certificate, qcfg *quic.Config) (qc quic.Connection, peerUDP *net.UDPAddr, isDirect bool, teardown func(), err error) {
	sess, err := runICESession(ctx, wsURL, h.mergeICEURLs(ctx), false, false)
	if err != nil {
		return nil, nil, false, nil, err
	}

	isDirect = sess.isDirectCandidate()

	pconn := &icePacketConn{c: sess.iceConn}
	tr := &quic.Transport{Conn: pconn}
	td := func() {
		_ = tr.Close()
		sess.CloseSignaling()
	}

	srvTLS := quicServerTLSWithSNI(cert, h.certForSNI)
	ln, err := tr.Listen(srvTLS, qcfg)
	if err != nil {
		td()
		return nil, nil, false, nil, err
	}

	qc, err = ln.Accept(ctx)
	_ = ln.Close()
	if err != nil {
		td()
		return nil, nil, false, nil, err
	}

	ra := qc.RemoteAddr()
	udpRA, ok := ra.(*net.UDPAddr)
	if !ok || udpRA == nil {
		_ = qc.CloseWithError(1, "non-udp remote")
		td()
		return nil, nil, false, nil, fmt.Errorf("a2al/host: ice remote addr is %T", ra)
	}
	return qc, udpRA, isDirect, td, nil
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

	qc, _, _, teardown, err := h.acceptICEToQUIC(ctx, wsURL, ag.cert, defaultQUICConfig())
	if err != nil {
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
		h.log.Debug("ice quic closed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "close_reason", qc.Context().Err())
		teardown()
	}()
	return ac, nil
}

// modeBQUICConfig returns the QUIC configuration for Mode B (DHT control-plane)
// connections. Key differences from the default (Mode A) config:
//   - KeepAlivePeriod 20s: maintains NAT mappings (strategy §7: ≤25s required)
//   - MaxIdleTimeout 5min: "仅路由途中偶遇 idle timeout 自然断开" (§7 table)
func modeBQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       5 * time.Minute,
		MaxIncomingStreams:   100,
		MaxIncomingUniStreams: 10,
		KeepAlivePeriod:     20 * time.Second,
	}
}

// connectViaICEForDHT performs the controlling (caller) ICE path for Mode B
// (DHT control-plane) connections. Unlike connectViaICESignal it does NOT run
// the agent-route control stream — the returned QUIC connection carries raw DHT
// messages only. The node identity certificate is used for mutual TLS.
//
// Resource lifetime: teardown is tied to qc.Context() by a background goroutine.
func (h *Host) connectViaICEForDHT(ctx context.Context, er *protocol.EndpointRecord) (qc quic.Connection, peerUDP *net.UDPAddr, isDirect bool, err error) {
	signalURLs := er.Signals
	if len(signalURLs) == 0 && er.Signal != "" {
		signalURLs = []string{er.Signal}
	}
	if len(signalURLs) == 0 {
		return nil, nil, false, errors.New("a2al/host: no signal url in record")
	}

	nodeCert, certErr := h.defaultAgentCert()
	if certErr != nil {
		return nil, nil, false, certErr
	}

	room := signaling.RoomID(h.addr.String(), er.Address.String())
	iceURLs := h.mergeICEURLs(ctx)

	var lastErr error
	for _, signalBase := range signalURLs {
		qc, peerUDP, isDirect, err = h.tryICEForDHT(ctx, nodeCert, er.Address, signalBase, room, iceURLs)
		if err == nil {
			return qc, peerUDP, isDirect, nil
		}
		h.log.Debug("dht ice hub failed, trying next", "base", signalBase, "remote", er.Address, "err", err)
		lastErr = err
	}
	return nil, nil, false, lastErr
}

// tryICEForDHT attempts a full ICE → QUIC handshake through one signal hub for
// Mode B (DHT control-plane). No agent-route control stream is opened.
// isDirect is true when the selected ICE candidate is host/srflx (Phase 8).
func (h *Host) tryICEForDHT(ctx context.Context, cert tls.Certificate, expectRemote a2al.Address, signalBase, room string, iceURLs []*stun.URI) (quic.Connection, *net.UDPAddr, bool, error) {
	wsURL, err := signaling.AppendRoomToICEURL(signalBase, room)
	if err != nil {
		return nil, nil, false, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}
	wsURL, err = signaling.AppendQuery(wsURL, "target", expectRemote.String())
	if err != nil {
		return nil, nil, false, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}
	wsURL, err = signaling.AppendQuery(wsURL, "caller", h.addr.String())
	if err != nil {
		return nil, nil, false, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}

	var (
		sess *iceSession
		lerr error
	)
	for attempt := 0; attempt <= noAgentRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, false, ctx.Err()
			case <-time.After(noAgentRetryDelay):
			}
		}
		sess, lerr = runICESession(ctx, wsURL, iceURLs, true, false)
		if !errors.Is(lerr, ErrNoAgent) {
			break
		}
		h.log.Debug("dht ice retry on noagent", "remote", expectRemote, "hub", signalBase, "attempt", attempt+1)
	}
	if lerr != nil {
		return nil, nil, false, lerr
	}

	// Phase 8: check if the remote is actually directly reachable (host/srflx candidate).
	isDirect := sess.isDirectCandidate()

	pconn := &icePacketConn{c: sess.iceConn}
	tr := &quic.Transport{Conn: pconn}
	teardown := func() {
		_ = tr.Close()
		sess.CloseSignaling()
	}

	ra := sess.iceConn.RemoteAddr()
	udpRA, ok := ra.(*net.UDPAddr)
	if !ok || udpRA == nil {
		teardown()
		return nil, nil, false, fmt.Errorf("a2al/host: ice remote addr is %T", ra)
	}

	cliTLS, err := quicClientTLSWithCert(cert, expectRemote)
	if err != nil {
		teardown()
		return nil, nil, false, err
	}
	qc, err := tr.Dial(ctx, udpRA, cliTLS, modeBQUICConfig())
	if err != nil {
		teardown()
		return nil, nil, false, err
	}

	// Mode B: no doDialerControlStream — connection carries raw DHT messages only.
	go func() {
		<-qc.Context().Done()
		teardown()
	}()
	return qc, udpRA, isDirect, nil
}
