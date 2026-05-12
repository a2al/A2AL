// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
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

// iceHubTimeout caps the time spent on a single ICE signal hub when racing
// multiple hubs in parallel. 30 s is enough for successful ICE negotiation
// (~1–5 s on cooperative NATs) while bounding the wait on stuck hubs so that
// the winner can be returned promptly.
const iceHubTimeout = 30 * time.Second

// hasTURNURLs reports whether the given STUN/TURN URL list contains at least
// one TURN or TURNS entry. Used to determine whether ErrRelayRequired should
// be returned when relay is disabled and direct connectivity fails.
func hasTURNURLs(urls []*stun.URI) bool {
	for _, u := range urls {
		if u.Scheme == stun.SchemeTypeTURN || u.Scheme == stun.SchemeTypeTURNS {
			return true
		}
	}
	return false
}

// recordICESession extracts the selected candidate pair and all collected
// trickle candidates from a completed ICE session and writes them into the
// peerICECache for future dial acceleration.
func (h *Host) recordICESession(remote a2al.Address, sess *iceSession) {
	if sess == nil || sess.agent == nil {
		return
	}
	pair, err := sess.agent.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return
	}
	h.iceCache.Record(remote, pair.Remote, sess.snapshotRemoteCands())
}

// connectViaICESignal is the controlling (caller) ICE path:
// WebSocket signaling → ICE pair selection → QUIC over ICE → agent-route.
//
// Signal hub selection: prefer er.Signals (multi-center list); fall back to
// er.Signal for backward compatibility with old peers.
//
// When multiple hubs are available they are raced in parallel (Happy Eyeballs).
// Each hub gets an independent sub-context capped at iceHubTimeout so a slow
// or stuck hub cannot starve the remaining candidates. The first successful
// connection wins; any redundant successes are closed immediately.
//
// Resource lifecycle: the ICE session (agent, WS) and quic.Transport are tied
// to the returned quic.Connection via a background goroutine that cleans them
// up when the connection closes. The caller must NOT close these resources
// separately.
func (h *Host) connectViaICESignal(ctx context.Context, localCert tls.Certificate, localAgent, expectRemote a2al.Address, er *protocol.EndpointRecord, disableRelay bool) (quic.Connection, bool, error) {
	signalURLs := er.Signals
	if len(signalURLs) == 0 && er.Signal != "" {
		signalURLs = []string{er.Signal}
	}
	if len(signalURLs) == 0 {
		return nil, false, errors.New("a2al/host: no signal url in record")
	}

	room := signaling.RoomID(localAgent.String(), expectRemote.String())
	iceURLs := h.mergeICEURLs(ctx)

	if len(signalURLs) == 1 {
		return h.tryICEViaHub(ctx, localCert, localAgent, expectRemote, signalURLs[0], room, iceURLs, disableRelay)
	}

	// Race all hubs in parallel; return the first success.
	type res struct {
		conn      quic.Connection
		isRelayed bool
		err       error
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	ch := make(chan res, len(signalURLs))
	for _, hub := range signalURLs {
		hub := hub
		go func() {
			hubCtx, hubCancel := context.WithTimeout(raceCtx, iceHubTimeout)
			defer hubCancel()
			conn, relayed, err := h.tryICEViaHub(hubCtx, localCert, localAgent, expectRemote, hub, room, iceURLs, disableRelay)
			ch <- res{conn, relayed, err}
		}()
	}

	var lastErr error
	for received := 0; received < len(signalURLs); received++ {
		r := <-ch
		if r.err == nil {
			raceCancel()
			// Drain remaining goroutines in background; close any redundant successes.
			if remaining := len(signalURLs) - received - 1; remaining > 0 {
				go func(n int) {
					for i := 0; i < n; i++ {
						if r2 := <-ch; r2.conn != nil {
							_ = r2.conn.CloseWithError(0, "superseded by faster ice hub")
						}
					}
				}(remaining)
			}
			return r.conn, r.isRelayed, nil
		}
		lastErr = r.err
	}
	return nil, false, lastErr
}

// tryICEViaHub attempts an ICE → QUIC handshake through one signal hub.
// ICE connectivity checks race against a DCUtR punch attempt on the same
// WebSocket; the first QUIC connection to be established wins.
// noAgentRetries are applied when the hub reports the callee is not registered.
func (h *Host) tryICEViaHub(ctx context.Context, localCert tls.Certificate, localAgent, expectRemote a2al.Address, signalBase, room string, iceURLs []*stun.URI, disableRelay bool) (quic.Connection, bool, error) {
	wsURL, err := signaling.AppendRoomToICEURL(signalBase, room)
	if err != nil {
		return nil, false, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}
	wsURL, err = signaling.AppendQuery(wsURL, "target", expectRemote.String())
	if err != nil {
		return nil, false, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}
	wsURL, err = signaling.AppendQuery(wsURL, "caller", localAgent.String())
	if err != nil {
		return nil, false, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}

	hints := h.iceCache.Hints(expectRemote)

	// Retry loop for noagent (callee momentarily reconnecting).
	var (
		sess       *iceSession
		remoteCred [2]string
	)
	for attempt := 0; attempt <= noAgentRetries; attempt++ {
		h.log.Debug("ice dial attempt", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "attempt", attempt+1, "max_attempts", noAgentRetries+1)
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(noAgentRetryDelay):
			}
		}
		sess, remoteCred, err = startICESession(ctx, wsURL, iceURLs, true, false, disableRelay, h.cfg.ICENetworkTypes, hints)
		if !errors.Is(err, ErrNoAgent) {
			break
		}
		if sess != nil {
			sess.Close()
			sess = nil
		}
		h.log.Debug("ice dial retry on noagent", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "attempt", attempt+1)
	}
	if err != nil {
		h.log.Warn("ice session start failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "err", err)
		return nil, false, err
	}

	sessOwned := true
	defer func() {
		if sessOwned {
			sess.Close()
		}
	}()

	// Race ICE completion (QUIC over ICE) against DCUtR punch.
	// pathEnd=true is a sentinel meaning "this goroutine has finished sending connections".
	// Each of the two goroutines (ICE and punch) emits exactly one pathEnd when done.
	// Connections are emitted to ch as they are established (punch may yield 0-2).
	type connResult struct {
		qc        quic.Connection
		teardown  func()
		fromICE   bool
		isRelayed bool
		pathEnd   bool // sentinel: goroutine finished
		err      error
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	// ch capacity: 1 ICE conn + 1 ICE pathEnd + N punch conn + 1 punch pathEnd.
	// Punch may forward more than 2 connections (full phase-2 budget); buffered
	// at 5 as a reasonable bound — punch goroutine forwards continuously while
	// the race loop drains ch, so momentary overflow is the only risk.
	ch := make(chan connResult, 5)

	// ICE goroutine: complete connectivity checks then dial QUIC over ICE.
	go func() {
		if iErr := completeICESession(raceCtx, sess, true, remoteCred); iErr != nil {
			ch <- connResult{pathEnd: true, err: iErr}
			return
		}
		pconn := &icePacketConn{c: sess.iceConn}
		tr := &quic.Transport{Conn: pconn}
		ra, ok := sess.iceConn.RemoteAddr().(*net.UDPAddr)
		if !ok || ra == nil {
			_ = tr.Close()
			ch <- connResult{pathEnd: true, err: fmt.Errorf("a2al/host: ice remote addr is %T", sess.iceConn.RemoteAddr())}
			return
		}
		cliTLS, tlsErr := quicClientTLSWithCert(localCert, expectRemote)
		if tlsErr != nil {
			_ = tr.Close()
			ch <- connResult{pathEnd: true, err: tlsErr}
			return
		}
		qc, dialErr := tr.Dial(raceCtx, ra, cliTLS, defaultQUICConfig())
		if dialErr != nil {
			h.log.Debug("quic dial over ice failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "dst", ra, "err", dialErr)
			_ = tr.Close()
			ch <- connResult{pathEnd: true, err: dialErr}
			return
		}
		h.log.Debug("quic dial over ice ok", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "dst", ra)
		ch <- connResult{
			qc:        qc,
			teardown:  func() { _ = tr.Close(); sess.CloseSignaling() },
			fromICE:   true,
			isRelayed: sess.isRelayedCandidate(),
		}
		ch <- connResult{pathEnd: true}
	}()

	// Punch goroutine: DCUtR synchronized hole-punch, runs concurrently with ICE.
	// Forwards all established connections from punchDial for the full phase-2
	// budget, giving onConn maximum fallback candidates.
	go func() {
		punchOutCh := make(chan punchWin, 2)
		punchErr := h.punchDial(raceCtx, sess, true, localCert, expectRemote, defaultQUICConfig(), punchOutCh)
		if punchErr != nil {
			ch <- connResult{pathEnd: true, err: punchErr}
			return
		}
		for w := range punchOutCh {
			h.log.Debug("quic dial over punch ok", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase)
			ch <- connResult{qc: w.qc, teardown: w.teardown}
		}
		ch <- connResult{pathEnd: true}
	}()

	// Collect: first established connection wins.
	// Loop until winner found or both goroutines have finished (pathsDone == 2).
	pathsDone := 0
	var winnerR *connResult
	var errs []error

	for winnerR == nil && pathsDone < 2 {
		r := <-ch
		if r.pathEnd {
			pathsDone++
			if r.err != nil {
				errs = append(errs, r.err)
			}
			continue
		}
		// First connection: winner candidate. Stop both goroutines.
		raceCancel()
		if r.fromICE {
			h.recordICESession(expectRemote, sess)
		} else {
			// Punch winner: wrap teardown to also close the ICE session when QUIC closes.
			origTD := r.teardown
			r.teardown = func() {
				if origTD != nil {
					origTD()
				}
				sess.Close()
			}
		}
		sessOwned = false
		cp := r
		winnerR = &cp
	}

	if winnerR == nil {
		h.log.Warn("ice+punch both failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "errs", errs)
		joined := errors.Join(errs...)
		if disableRelay && hasTURNURLs(iceURLs) {
			return nil, false, fmt.Errorf("%w: %w", ErrRelayRequired, joined)
		}
		return nil, false, joined
	}

	// Drain remaining goroutine outputs (pathEnds + any trailing connections) in background.
	remPaths := 2 - pathsDone
	go func(rem int) {
		for rem > 0 {
			r2 := <-ch
			if r2.pathEnd {
				rem--
				continue
			}
			if r2.qc != nil {
				_ = r2.qc.CloseWithError(0, "superseded by faster path")
				if r2.teardown != nil {
					r2.teardown()
				}
			}
		}
	}(remPaths)

	if ctrlErr := h.doDialerControlStream(ctx, winnerR.qc, expectRemote); ctrlErr != nil {
		h.log.Warn("agent-route failed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase, "err", ctrlErr)
		_ = winnerR.qc.CloseWithError(1, "agent-route")
		if winnerR.teardown != nil {
			winnerR.teardown()
		}
		return nil, false, ctrlErr
	}
	go func(td func()) {
		<-winnerR.qc.Context().Done()
		h.log.Debug("ice/punch quic closed", "local_aid", localAgent.String(), "remote_aid", expectRemote.String(), "hub", signalBase)
		if td != nil {
			td()
		}
	}(winnerR.teardown)
	return winnerR.qc, winnerR.isRelayed, nil
}

// acceptICEToQUIC runs the controlled (callee) side of ICE signaling, then
// builds a QUIC listener and accepts exactly one incoming connection.
// It returns the raw QUIC connection and the peer's UDP address without
// performing any upper-layer handshake (agent-route or DHT).
//
// qcfg selects the QUIC configuration; pass defaultQUICConfig() for Mode A
// (agent connections) or modeBQUICConfig() for Mode B (DHT control plane).
//
// onConn, when non-nil, is called for each established QUIC connection and
// acts as the winner selector: the first connection for which onConn returns
// nil is returned to the caller; the others are closed. This is used by Mode A
// to race the control stream across ICE and punch connections, resolving the
// race where both complete nearly simultaneously and each side independently
// picks a different "winner" (see ICE打洞排障记录-2026-05.md, Bug A). When
// nil, the first established QUIC connection wins without verification (Mode B).
//
// isDirect is true when the selected ICE candidate pair is host/srflx on the
// remote side, indicating the remote is directly reachable without NAT punching.
// Used by Phase 8 reclassification in DHTpunchPool.
//
// The caller must invoke teardown when the connection is no longer needed.
//
// expectRemote, when non-zero, is used to look up cached ICE hints for the
// peer and to record the session outcome into peerICECache. Pass a zero value
// (e.g. for DHT Mode B callers that use NodeID-keyed routing) to skip caching.
func (h *Host) acceptICEToQUIC(ctx context.Context, wsURL string, cert tls.Certificate, qcfg *quic.Config, expectRemote a2al.Address, onConn func(context.Context, quic.Connection) error, disableRelay bool) (qc quic.Connection, peerUDP *net.UDPAddr, isDirect bool, isRelayed bool, teardown func(), err error) {
	zeroAddr := a2al.Address{}
	var hints []iceHint
	if expectRemote != zeroAddr {
		hints = h.iceCache.Hints(expectRemote)
	}
	iceURLs := h.mergeICEURLs(ctx)

	sess, remoteCred, err := startICESession(ctx, wsURL, iceURLs, false, false, disableRelay, h.cfg.ICENetworkTypes, hints)
	if err != nil {
		return nil, nil, false, false, nil, err
	}

	sessOwned := true
	defer func() {
		if sessOwned {
			sess.Close()
		}
	}()

	// Race ICE accept against DCUtR punch.
	// pathEnd=true is a sentinel: goroutine finished sending connections.
	// ICE emits 0-1 connection + 1 pathEnd; punch emits 0-2 connections + 1 pathEnd.
	type connResult struct {
		qc        quic.Connection
		peerUDP   *net.UDPAddr
		isDirect  bool
		isRelayed bool
		teardown  func()
		pathEnd   bool // sentinel: goroutine finished
		err       error
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	// ch capacity: 1 ICE conn + 1 ICE pathEnd + N punch conn + 1 punch pathEnd.
	// Punch may forward more than 2 connections (full phase-2 budget); buffered
	// at 5 as a reasonable bound — punch goroutine forwards continuously while
	// the race loop drains ch, so momentary overflow is the only risk.
	ch := make(chan connResult, 5)

	// ICE goroutine: complete controlled-side connectivity checks then accept QUIC.
	go func() {
		if iceErr := completeICESession(raceCtx, sess, false, remoteCred); iceErr != nil {
			ch <- connResult{pathEnd: true, err: iceErr}
			return
		}
		if expectRemote != zeroAddr {
			h.recordICESession(expectRemote, sess)
		}
		direct := sess.isDirectCandidate()
		pconn := &icePacketConn{c: sess.iceConn}
		tr := &quic.Transport{Conn: pconn}
		srvTLS := quicServerTLSWithSNI(cert, h.certForSNI)
		ln, lnErr := tr.Listen(srvTLS, qcfg)
		if lnErr != nil {
			_ = tr.Close()
			ch <- connResult{pathEnd: true, err: lnErr}
			return
		}
		iqc, acceptErr := ln.Accept(raceCtx)
		_ = ln.Close()
		if acceptErr != nil {
			_ = tr.Close()
			ch <- connResult{pathEnd: true, err: acceptErr}
			return
		}
		ra, ok := iqc.RemoteAddr().(*net.UDPAddr)
		if !ok || ra == nil {
			_ = iqc.CloseWithError(1, "non-udp remote")
			_ = tr.Close()
			ch <- connResult{pathEnd: true, err: fmt.Errorf("a2al/host: ice remote addr is %T", iqc.RemoteAddr())}
			return
		}
		ch <- connResult{
			qc:        iqc,
			peerUDP:   ra,
			isDirect:  direct,
			isRelayed: sess.isRelayedCandidate(),
			teardown:  func() { _ = tr.Close(); sess.CloseSignaling() },
		}
		ch <- connResult{pathEnd: true}
	}()

	// Punch goroutine: DCUtR callee side (controlled=false).
	// Requires a known expectRemote for TLS verification; skip when zero.
	// Forwards all established connections for the full phase-2 budget.
	// Teardown for each punchWin is a no-op; sess.Close() is added by
	// Mode A only for the winning punch connection (see winner teardown below).
	go func() {
		if expectRemote == zeroAddr {
			ch <- connResult{pathEnd: true, err: fmt.Errorf("punch: expectRemote not set")}
			return
		}
		punchOutCh := make(chan punchWin, 2)
		punchErr := h.punchDial(raceCtx, sess, false, cert, expectRemote, qcfg, punchOutCh)
		if punchErr != nil {
			ch <- connResult{pathEnd: true, err: punchErr}
			return
		}
		for w := range punchOutCh {
			ch <- connResult{
				qc:       w.qc,
				peerUDP:  w.peer,
				isDirect: true, // punch path bypasses relay
				teardown: w.teardown,
			}
		}
		ch <- connResult{pathEnd: true}
	}()

	// drainCh drains ch until rem pathEnd sentinels have been received,
	// closing any trailing QUIC connections found along the way.
	drainCh := func(rem int) {
		for rem > 0 {
			r2 := <-ch
			if r2.pathEnd {
				rem--
				continue
			}
			if r2.qc != nil {
				_ = r2.qc.CloseWithError(0, "superseded by faster path")
				if r2.teardown != nil {
					r2.teardown()
				}
			}
		}
	}

	if onConn == nil {
		// Mode B (DHT): first established QUIC connection wins, no stream check.
		pathsDone := 0
		var errs []error
		for pathsDone < 2 {
			r := <-ch
			if r.pathEnd {
				pathsDone++
				if r.err != nil {
					errs = append(errs, r.err)
				}
				continue
			}
			raceCancel()
			sessOwned = false
			go drainCh(2 - pathsDone)
			return r.qc, r.peerUDP, r.isDirect, r.isRelayed, r.teardown, nil
		}
		return nil, nil, false, false, nil, errors.Join(errs...)
	}

	// Mode A (agent): race control streams across all established QUIC connections.
	// Winner is the first connection on which onConn succeeds (i.e. the connection
	// the caller is actually using). This prevents the ICE-vs-punch winner mismatch
	// where both sides independently pick different paths.
	//
	// For punch winners: sess.Close() (ICE agent + WebSocket) is added to the winner's
	// teardown here, since punch connections' own teardowns only release the shared
	// UDP transport reference count. ICE winners' teardowns already include CloseSignaling.
	type strmResult struct {
		connResult
		streamErr error
	}
	strmCh := make(chan strmResult, 3) // up to 3 concurrent stream races (1 ICE + 2 punch)
	strmCtx, strmCancel := context.WithCancel(ctx)
	defer strmCancel()

	pathsDone := 0
	strmLaunched := 0
	strmDone := 0
	var pathErrs []error
	var strmErrs []error

	// Use a sync.Once so sess.Close() is called at most once regardless of
	// how many punch connections have their teardown invoked.
	var sessCloseOnce sync.Once
	sessClose := func() { sessCloseOnce.Do(func() { sess.Close() }) }

	for {
		// Exit when all path goroutines and all stream goroutines have reported.
		// Do NOT select on ctx.Done() here: when ctx is cancelled, raceCtx and
		// strmCtx are also cancelled (they derive from ctx), so all goroutines
		// unblock and send to ch/strmCh naturally. Selecting ctx.Done() directly
		// would return early and leak any QUIC connections already in flight.
		if pathsDone == 2 && strmDone == strmLaunched {
			break
		}
		select {
		case r := <-ch:
			if r.pathEnd {
				pathsDone++
				if r.err != nil {
					pathErrs = append(pathErrs, r.err)
				}
				continue
			}
			// Got a QUIC connection; race the control stream on it.
			strmLaunched++
			go func(r connResult) {
				h.log.Debug("ice stream race: trying path", "component", "ice",
					"path", r.isDirect)
				sErr := onConn(strmCtx, r.qc)
				if sErr != nil {
					h.log.Debug("ice stream race: path rejected", "component", "ice",
						"direct", r.isDirect, "err", sErr)
				}
				strmCh <- strmResult{r, sErr}
			}(r)
		case sr := <-strmCh:
			strmDone++
			if sr.streamErr == nil {
				// Winner: this connection received the caller's stream.
				h.log.Debug("ice stream race: winner selected", "component", "ice",
					"direct", sr.isDirect)
				strmCancel() // stop other stream goroutines
				raceCancel() // stop remaining ICE/punch goroutines
				sessOwned = false

				// Build winner teardown. Punch winners need sess.Close() since
				// their punchWin teardown only releases the UDP socket reference.
				// ICE winners' teardown already handles CloseSignaling.
				winTD := sr.teardown
				if sr.isDirect {
					origTD := sr.teardown
					winTD = func() {
						if origTD != nil {
							origTD()
						}
						sessClose()
					}
				}

				remPaths := 2 - pathsDone
				remStrm := strmLaunched - strmDone
				go func(rP, rS int) {
					drainCh(rP)
					for i := 0; i < rS; i++ {
						if sr2 := <-strmCh; sr2.qc != nil {
							_ = sr2.qc.CloseWithError(0, "superseded by faster path")
							if sr2.teardown != nil {
								sr2.teardown()
							}
						}
					}
				}(remPaths, remStrm)
				return sr.qc, sr.peerUDP, sr.isDirect, sr.isRelayed, winTD, nil
			}
			// This connection's stream failed; close it and try others.
			strmErrs = append(strmErrs, sr.streamErr)
			_ = sr.qc.CloseWithError(1, "control stream rejected")
			if sr.teardown != nil {
				sr.teardown()
			}
		}
	}

	if strmLaunched > 0 {
		return nil, nil, false, false, nil, fmt.Errorf("a2al/host: all paths rejected control stream: %w",
			errors.Join(strmErrs...))
	}
	return nil, nil, false, false, nil, errors.Join(pathErrs...)
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
		h.log.Debug("ice accept: agent not registered in host",
			"component", "ice",
			"local_aid", localAgent.String(),
			"remote_aid", expectRemote.String())
		return nil, fmt.Errorf("a2al/host: unknown agent %s", localAgent)
	}

	room := signaling.RoomID(localAgent.String(), expectRemote.String())
	wsURL, err := signaling.AppendRoomToICEURL(signalBase, room)
	if err != nil {
		return nil, fmt.Errorf("a2al/host: ice signal url: %w", err)
	}

	// onConn is called for each established QUIC connection and runs the
	// control stream acceptance to determine which connection the caller is
	// actually using. The winning target address is captured via closure.
	var winTarget a2al.Address
	onConn := func(sCtx context.Context, qc quic.Connection) error {
		target, err := h.doAcceptorControlStream(sCtx, qc)
		if err != nil {
			return err
		}
		winTarget = target
		return nil
	}

	qc, _, _, isRelayed, teardown, err := h.acceptICEToQUIC(ctx, wsURL, ag.cert, defaultQUICConfig(), expectRemote, onConn, false)
	if err != nil {
		return nil, err
	}

	// Build AgentConn; doAcceptorControlStream already ran inside acceptICEToQUIC.
	ac := &AgentConn{Connection: qc, Local: localAgent, IsRelayed: isRelayed}
	if remote, err := peerAddrFromTLSState(qc.ConnectionState().TLS); err == nil {
		ac.Remote = remote
	}
	if winTarget != (a2al.Address{}) {
		h.agentsMu.RLock()
		_, registered := h.agents[winTarget]
		h.agentsMu.RUnlock()
		if registered {
			ac.Local = winTarget
		}
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
// When multiple signal hubs are available they are raced in parallel (same as
// connectViaICESignal) so a slow or unreachable hub cannot block the path.
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

	if len(signalURLs) == 1 {
		return h.tryICEForDHT(ctx, nodeCert, er.Address, signalURLs[0], room, iceURLs)
	}

	// Race all hubs in parallel; return the first success.
	type res struct {
		qc       quic.Connection
		peerUDP  *net.UDPAddr
		isDirect bool
		err      error
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	ch := make(chan res, len(signalURLs))
	for _, hub := range signalURLs {
		hub := hub
		go func() {
			hubCtx, hubCancel := context.WithTimeout(raceCtx, iceHubTimeout)
			defer hubCancel()
			c, u, d, e := h.tryICEForDHT(hubCtx, nodeCert, er.Address, hub, room, iceURLs)
			ch <- res{c, u, d, e}
		}()
	}

	var errs []error
	for range signalURLs {
		r := <-ch
		if r.err == nil {
			raceCancel()
			// Drain remaining goroutine results in background, closing any redundant connections.
			go func(remaining int) {
				for i := 0; i < remaining; i++ {
					if r2 := <-ch; r2.err == nil && r2.qc != nil {
						_ = r2.qc.CloseWithError(0, "superseded by faster hub")
					}
				}
			}(len(signalURLs) - 1)
			return r.qc, r.peerUDP, r.isDirect, nil
		}
		errs = append(errs, r.err)
	}
	return nil, nil, false, errors.Join(errs...)
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

	hints := h.iceCache.Hints(expectRemote)

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
		sess, lerr = runICESession(ctx, wsURL, iceURLs, true, false, true, h.cfg.ICENetworkTypes, hints)
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

	h.recordICESession(expectRemote, sess)

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
