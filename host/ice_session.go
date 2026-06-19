// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/fxamacker/cbor/v2"
	ice "github.com/pion/ice/v3"
	"github.com/pion/stun/v2"

	"github.com/a2al/a2al/signaling"
)

// defaultICECredentialTimeout is the safety-net deadline for receiving remote
// ICE credentials via the signaling WebSocket. If the caller's context already
// carries a deadline, it takes precedence.
const defaultICECredentialTimeout = 30 * time.Second

// ErrNoAgent is returned by runICESession when the signaling hub reports that
// the target agent is not currently registered ("noagent" frame). Callers may
// retry after a brief delay to ride out a callee reconnect window.
var ErrNoAgent = errors.New("a2al/host: target agent not registered")

// iceSession holds resources created during ICE signaling that must outlive the
// signaling exchange. The caller is responsible for calling Close (or
// CloseSignaling + letting the Transport chain handle the rest).
type iceSession struct {
	iceConn *ice.Conn
	ws      *websocket.Conn
	agent   *ice.Agent

	// remoteCands accumulates non-relay remote candidates received via trickle
	// ICE. Written by the read goroutine concurrently with agent.Dial/Accept;
	// mu must be held for all access.
	mu          sync.Mutex
	remoteCands []ice.Candidate

	// wsMu serializes writes to ws. OnCandidate fires in an ICE-internal
	// goroutine while the DCUtR punch protocol may also write; all callers
	// must go through writeFrame.
	wsMu sync.Mutex

	// punchCh receives punch-init/ack/go frames from the read goroutine so
	// that the DCUtR punch protocol can consume them concurrently with ICE
	// Dial/Accept. Buffered to avoid blocking the read goroutine.
	punchCh chan signaling.Frame

	// localSrflx accumulates server-reflexive candidate addresses ("ip:port")
	// as they are gathered. Protected by srflxMu.
	localSrflx []string
	srflxMu    sync.Mutex

}

// snapshotRemoteCands returns a copy of all accumulated trickle remote candidates.
// Safe to call after agent.Dial/Accept returns while the read goroutine is still running.
func (s *iceSession) snapshotRemoteCands() []ice.Candidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.remoteCands) == 0 {
		return nil
	}
	cp := make([]ice.Candidate, len(s.remoteCands))
	copy(cp, s.remoteCands)
	return cp
}

// writeFrame encodes f as CBOR and writes it to the signaling WebSocket.
// Safe to call concurrently (serialized via wsMu).
func (s *iceSession) writeFrame(ctx context.Context, f signaling.Frame) error {
	b, err := signaling.EncodeFrame(f)
	if err != nil {
		return err
	}
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if s.ws == nil {
		return errors.New("a2al/host: ice ws already closed")
	}
	return s.ws.Write(ctx, websocket.MessageBinary, b)
}

// copyLocalSrflx returns a snapshot of the locally gathered server-reflexive
// candidate addresses collected so far.
func (s *iceSession) copyLocalSrflx() []string {
	s.srflxMu.Lock()
	defer s.srflxMu.Unlock()
	out := make([]string, len(s.localSrflx))
	copy(out, s.localSrflx)
	return out
}

// CloseSignaling shuts down the WebSocket only, leaving the ICE data path
// intact. Call this after QUIC is established on top of the ICE connection.
//
// Uses a graceful WebSocket close (sends Close frame with 5 s timeout, waits
// for peer ack) so the hub receives a clean TCP FIN instead of RST. On
// Windows, an abrupt close (CloseNow) triggers WSAECONNABORTED (10053) when
// there is pending send data, which also disrupts the hub's read loop for
// unrelated sessions on the same connection.
func (s *iceSession) CloseSignaling() {
	s.wsMu.Lock()
	ws := s.ws
	s.ws = nil
	s.wsMu.Unlock()
	if ws == nil {
		return
	}
	_ = ws.Close(websocket.StatusNormalClosure, "")
}

// isRelayedCandidate reports whether the selected ICE candidate pair uses a
// TURN relay on either the local or remote side.
func (s *iceSession) isRelayedCandidate() bool {
	if s.agent == nil {
		return false
	}
	pair, err := s.agent.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return false
	}
	return pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay
}

// isDirectCandidate reports whether the ICE-selected candidate pair is host
// or server-reflexive on both local and remote sides — no prflx hole-punch
// and no TURN relay was required to establish connectivity.
//
// Used by Phase 8 (误分类纠正): if true the remote is admitted to the standard
// routing bucket (tabAdd + tryLive) rather than the punched zone (AddPunched +
// tryEphemeral). Note: srflx still traverses NAT; "direct" means no ongoing
// hole-punch maintenance is needed, not that the path is NAT-free.
func (s *iceSession) isDirectCandidate() bool {
	if s.agent == nil {
		return false
	}
	pair, err := s.agent.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return false
	}
	isDirect := func(t ice.CandidateType) bool {
		return t == ice.CandidateTypeHost || t == ice.CandidateTypeServerReflexive
	}
	return isDirect(pair.Local.Type()) && isDirect(pair.Remote.Type())
}

// Close tears down all resources: WebSocket, ICE connection, and agent.
func (s *iceSession) Close() {
	s.CloseSignaling()
	if s.iceConn != nil {
		_ = s.iceConn.Close() // also closes the agent
	} else if s.agent != nil {
		_ = s.agent.Close()
	}
}

// mergeICEURLs builds a deduplicated list of STUN/TURN URIs from local config.
// Falls back to a public STUN server when no URIs are configured.
//
// Note: er.Turns (callee's TURN server hints from the DHT record) are intentionally
// NOT included. The caller has no credentials for callee's TURN server; callee-pays
// relay candidates arrive via trickle ICE as remote candidates, not as local server URIs.
func (h *Host) mergeICEURLs(ctx context.Context) []*stun.URI {
	seen := make(map[string]struct{})
	var out []*stun.URI

	addURI := func(u *stun.URI) {
		key := u.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, u)
	}
	addRaw := func(s string) {
		if s == "" {
			return
		}
		u, err := stun.ParseURI(s)
		if err != nil {
			return
		}
		addURI(u)
	}

	for _, s := range h.cfg.ICESTUNURLs {
		addRaw(s)
	}
	// Legacy embedded-credential TURN URLs (ICETURNURLs).
	for _, s := range h.cfg.ICETURNURLs {
		addRaw(s)
	}
	// Structured TURN servers with HMAC / REST API credential support.
	for _, ts := range h.cfg.TURNServers {
		u, err := resolveTURNURI(ctx, ts)
		if err != nil {
			h.log.Warn("TURN credential resolution failed, skipping server",
				"url", ts.URL, "err", err)
			continue
		}
		addURI(u)
	}
	if len(out) == 0 {
		// Derive STUN candidates from known-reachable signal hubs (requires coturn
		// co-located on the hub server at port 3478; harmless if not deployed yet).
		for _, signalURL := range h.effectiveICESignalURLs() {
			u, err := url.Parse(signalURL)
			if err == nil && u.Hostname() != "" {
				addRaw("stun:" + u.Hostname() + ":3478")
			}
		}
		// Public fallback, queried in parallel with hub-derived candidates.
		addRaw("stun:stun.l.google.com:19302")
		addRaw("stun:stun.cloudflare.com:3478")
	}
	return out
}

// resolveTURNURI returns a *stun.URI with credentials populated for the given TURNServer.
// For HMAC, credentials are generated locally. For REST API, the credential endpoint
// is called with the configured Authorization header.
func resolveTURNURI(ctx context.Context, ts TURNServer) (*stun.URI, error) {
	u, err := stun.ParseURI(ts.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid TURN URL %q: %w", ts.URL, err)
	}
	switch ts.CredentialType {
	case TURNCredentialStatic:
		u.Username = ts.Username
		u.Password = ts.Credential
	case TURNCredentialHMAC:
		// coturn use-auth-secret: username = unix_expiry:base_user, password = base64(HMAC-SHA1(secret, username)).
		exp := time.Now().Add(time.Hour).Unix()
		username := strconv.FormatInt(exp, 10) + ":" + ts.Username
		mac := hmac.New(sha1.New, []byte(ts.Credential))
		mac.Write([]byte(username))
		u.Username = username
		u.Password = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	case TURNCredentialRESTAPI:
		user, pass, err := fetchTURNRESTCredentials(ctx, ts.CredentialURL, ts.Credential)
		if err != nil {
			return nil, fmt.Errorf("REST API credential fetch for %q: %w", ts.URL, err)
		}
		u.Username = user
		u.Password = pass
	default:
		return nil, fmt.Errorf("unsupported TURN credential type %d for %q", ts.CredentialType, ts.URL)
	}
	return u, nil
}

// fetchTURNRESTCredentials calls a REST endpoint to retrieve short-lived TURN credentials.
// auth is placed verbatim in the Authorization header (e.g. "Basic base64(sid:token)").
// The JSON response must contain "username" and "password" (or "credential") fields.
func fetchTURNRESTCredentials(ctx context.Context, apiURL, auth string) (username, password string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, nil)
	if err != nil {
		return "", "", err
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var body struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Credential string `json:"credential"` // Twilio / some providers use "credential"
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return "", "", fmt.Errorf("decode response: %w", err)
	}
	if body.Password == "" {
		body.Password = body.Credential
	}
	if body.Username == "" || body.Password == "" {
		return "", "", errors.New("response missing username or password")
	}
	return body.Username, body.Password, nil
}

// hintToRemoteCandidate converts a peerICECache hint into a pion/ice remote
// candidate that can be injected via agent.AddRemoteCandidate. Relay candidates
// are never cached, so only host and server-reflexive types are handled.
func hintToRemoteCandidate(h iceHint) (ice.Candidate, error) {
	ip := h.addr.IP.String()
	port := h.addr.Port
	switch h.candType {
	case ice.CandidateTypeServerReflexive:
		return ice.NewCandidateServerReflexive(&ice.CandidateServerReflexiveConfig{
			Network: "udp",
			Address: ip,
			Port:    port,
		})
	default: // CandidateTypeHost and anything else
		return ice.NewCandidateHost(&ice.CandidateHostConfig{
			Network: "udp",
			Address: ip,
			Port:    port,
		})
	}
}

func newICEAgent(urls []*stun.URI, hostOnly, disableRelay bool, networkTypes []ice.NetworkType) (*ice.Agent, error) {
	cfg := &ice.AgentConfig{
		Urls:             urls,
		NetworkTypes:     networkTypes,
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
	}
	if hostOnly {
		cfg.CandidateTypes = []ice.CandidateType{ice.CandidateTypeHost}
		cfg.Urls = nil
	} else {
		hasTURN := false
		for _, u := range urls {
			if u.Scheme == stun.SchemeTypeTURN || u.Scheme == stun.SchemeTypeTURNS {
				hasTURN = true
				break
			}
		}
		if hasTURN && !disableRelay {
			cfg.CandidateTypes = []ice.CandidateType{
				ice.CandidateTypeHost,
				ice.CandidateTypeServerReflexive,
				ice.CandidateTypeRelay,
			}
		} else {
			cfg.CandidateTypes = []ice.CandidateType{
				ice.CandidateTypeHost,
				ice.CandidateTypeServerReflexive,
			}
		}
	}
	return ice.NewAgent(cfg)
}

// startICESession performs steps 1–6 of trickle-ICE signaling: WebSocket dial,
// ICE agent creation, local candidate trickle setup, read goroutine startup,
// credential exchange, hint injection, and GatherCandidates.
//
// The returned session has gathering running but agent.Dial/Accept not yet
// called. Call completeICESession to finish (blocking). The session's punchCh
// receives any "punch-init/ack/go" frames so that DCUtR can run concurrently.
//
// Returns the session and the remote ICE credentials needed by completeICESession.
// If the remote hub reports the target is not registered, the error wraps ErrNoAgent.
func startICESession(ctx context.Context, wsURL string, urls []*stun.URI, controlling, hostOnly, disableRelay bool, networkTypes []ice.NetworkType, hintRemotes []iceHint) (*iceSession, [2]string, error) {
	sess := &iceSession{
		punchCh: make(chan signaling.Frame, 8),
	}
	ok := false
	defer func() {
		if !ok {
			sess.Close()
		}
	}()

	// --- 1. WebSocket ---
	ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{signaling.SubprotocolICE},
	})
	if err != nil {
		return nil, [2]string{}, fmt.Errorf("a2al/host: ice ws dial: %w", err)
	}
	sess.ws = ws

	// slog.Debug("ice agent urls", "controlling", controlling, "count", len(urls), "urls", fmt.Sprintf("%v", urls))

	// --- 2. ICE agent ---
	agent, err := newICEAgent(urls, hostOnly, disableRelay, networkTypes)
	if err != nil {
		return nil, [2]string{}, err
	}
	sess.agent = agent

	_ = agent.OnConnectionStateChange(func(st ice.ConnectionState) {
		slog.Debug("ice state changed", "controlling", controlling, "state", st)
	})
	_ = agent.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		relayed := local.Type() == ice.CandidateTypeRelay || remote.Type() == ice.CandidateTypeRelay
		slog.Debug("ice pair selected",
			"controlling", controlling,
			"local", fmt.Sprintf("%s:%d(%s)", local.Address(), local.Port(), local.Type()),
			"remote", fmt.Sprintf("%s:%d(%s)", remote.Address(), remote.Port(), remote.Type()),
			"relayed", relayed,
		)
	})

	// --- 3. Trickle: send local candidates as they are gathered ---
	if err := agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			// Gathering complete – notify remote (informational).
			_ = sess.writeFrame(ctx, signaling.Frame{T: "eoc"})
			return
		}
		// slog.Debug("ice local cand", "controlling", controlling, "type", c.Type(), "addr", c.Address(), "port", c.Port())
		if c.Type() == ice.CandidateTypeServerReflexive {
			sess.srflxMu.Lock()
			sess.localSrflx = append(sess.localSrflx, fmt.Sprintf("%s:%d", c.Address(), c.Port()))
			sess.srflxMu.Unlock()
		}
		_ = sess.writeFrame(ctx, signaling.Frame{T: "cand", C: c.Marshal()})
	}); err != nil {
		return nil, [2]string{}, err
	}

	// --- 4. Read goroutine: remote cred + trickle candidates + punch frames ---
	credCh := make(chan [2]string, 1)
	readErr := make(chan error, 1)
	go func() {
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				select {
				case readErr <- err:
				default:
				}
				return
			}
			var fr signaling.Frame
			if err := cbor.Unmarshal(data, &fr); err != nil {
				select {
				case readErr <- err:
				default:
				}
				return
			}
			switch fr.T {
			case "cred":
				if fr.U != "" && fr.P != "" {
					select {
					case credCh <- [2]string{fr.U, fr.P}:
					default:
					}
				}
			case "cand":
				if fr.C == "" {
					continue
				}
				cand, err := ice.UnmarshalCandidate(fr.C)
				if err != nil {
					continue // best-effort; don't tear down the session
				}
				// slog.Debug("ice remote cand", "controlling", controlling, "type", cand.Type(), "addr", cand.Address(), "port", cand.Port())
				_ = agent.AddRemoteCandidate(cand)
				if cand.Type() != ice.CandidateTypeRelay {
					sess.mu.Lock()
					sess.remoteCands = append(sess.remoteCands, cand)
					sess.mu.Unlock()
				}
			case "eoc":
				// Informational; ICE handles this naturally.
			case "noagent":
				// Target agent is not registered on the hub.
				select {
				case readErr <- ErrNoAgent:
				default:
				}
				return
			case "punch-init", "punch-ack", "punch-go":
				// Route punch frames to DCUtR handler (non-blocking; drop if full).
				select {
				case sess.punchCh <- fr:
				default:
				}
			}
		}
	}()

	// --- 5. Exchange credentials ---
	ufrag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		return nil, [2]string{}, err
	}
	if err := sess.writeFrame(ctx, signaling.Frame{T: "cred", U: ufrag, P: pwd}); err != nil {
		return nil, [2]string{}, fmt.Errorf("a2al/host: ice send cred: %w", err)
	}

	credTimer := time.NewTimer(defaultICECredentialTimeout)
	defer credTimer.Stop()

	var remoteCred [2]string
	select {
	case <-ctx.Done():
		return nil, [2]string{}, ctx.Err()
	case err := <-readErr:
		return nil, [2]string{}, fmt.Errorf("a2al/host: signaling read: %w", err)
	case <-credTimer.C:
		return nil, [2]string{}, errors.New("a2al/host: ice credentials timeout")
	case remoteCred = <-credCh:
	}

	// --- 6. Inject cached hints as remote candidates (best-effort) ---
	// Hints from peerICECache represent endpoints that worked in a recent session.
	// Injecting them before GatherCandidates lets connectivity checks start on
	// known-good paths immediately, without waiting for trickle. Failures are
	// silently ignored — fresh trickle candidates still arrive via the read goroutine.
	for _, h := range hintRemotes {
		cand, err := hintToRemoteCandidate(h)
		if err != nil {
			continue
		}
		_ = agent.AddRemoteCandidate(cand)
	}

	// --- 7. Begin candidate gathering (non-blocking; candidates trickle via OnCandidate) ---
	if err := agent.GatherCandidates(); err != nil {
		return nil, [2]string{}, err
	}

	ok = true
	return sess, remoteCred, nil
}

// completeICESession calls agent.Dial (controlling) or agent.Accept (!controlling)
// to run ICE connectivity checks and select a candidate pair. On success
// sess.iceConn is set. Designed to run concurrently with punchDial.
func completeICESession(ctx context.Context, sess *iceSession, controlling bool, remoteCred [2]string) error {
	var err error
	if controlling {
		sess.iceConn, err = sess.agent.Dial(ctx, remoteCred[0], remoteCred[1])
	} else {
		sess.iceConn, err = sess.agent.Accept(ctx, remoteCred[0], remoteCred[1])
	}
	return err
}

// runICESession is a convenience wrapper around startICESession +
// completeICESession. Used by callers that do not race ICE against DCUtR punch
// and by existing tests.
func runICESession(ctx context.Context, wsURL string, urls []*stun.URI, controlling, hostOnly, disableRelay bool, networkTypes []ice.NetworkType, hintRemotes []iceHint) (*iceSession, error) {
	sess, remoteCred, err := startICESession(ctx, wsURL, urls, controlling, hostOnly, disableRelay, networkTypes, hintRemotes)
	if err != nil {
		return nil, err
	}
	if err := completeICESession(ctx, sess, controlling, remoteCred); err != nil {
		sess.Close()
		return nil, err
	}
	return sess, nil
}
