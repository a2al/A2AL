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
	"net/http"
	"strconv"
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
}

// CloseSignaling shuts down the WebSocket only, leaving the ICE data path
// intact. Call this after QUIC is established on top of the ICE connection.
func (s *iceSession) CloseSignaling() {
	if s.ws != nil {
		_ = s.ws.CloseNow()
		s.ws = nil
	}
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
		addRaw("stun:stun.l.google.com:19302")
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

func newICEAgent(urls []*stun.URI, hostOnly bool) (*ice.Agent, error) {
	cfg := &ice.AgentConfig{
		Urls:             urls,
		NetworkTypes:     []ice.NetworkType{ice.NetworkTypeUDP4},
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
	}
	if hostOnly {
		cfg.CandidateTypes = []ice.CandidateType{ice.CandidateTypeHost}
		cfg.Urls = nil
	}
	return ice.NewAgent(cfg)
}

// runICESession performs trickle-ICE signaling over a WebSocket, following the
// standard pion/ice pattern:
//
//  1. Connect to the signaling WebSocket.
//  2. Create an ICE agent and register a trickle OnCandidate handler that sends
//     each local candidate to the remote peer immediately.
//  3. Start a read goroutine that feeds remote credentials and candidates from
//     the WebSocket into the ICE agent.
//  4. Exchange local/remote credentials.
//  5. Begin candidate gathering (trickle: candidates flow as they are discovered).
//  6. Call agent.Dial (controlling) or agent.Accept (controlled), which runs
//     connectivity checks concurrently with gathering and returns when a pair is
//     selected.
//
// On success the returned *iceSession owns the ICE connection, the underlying
// agent, and the WebSocket. The caller must eventually close them (directly or
// by tying their lifetime to a QUIC connection).
func runICESession(ctx context.Context, wsURL string, urls []*stun.URI, controlling, hostOnly bool) (*iceSession, error) {
	sess := &iceSession{}
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
		return nil, fmt.Errorf("a2al/host: ice ws dial: %w", err)
	}
	sess.ws = ws

	// --- 2. ICE agent ---
	agent, err := newICEAgent(urls, hostOnly)
	if err != nil {
		return nil, err
	}
	sess.agent = agent

	// --- 3. Trickle: send local candidates as they are gathered ---
	if err := agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			// Gathering complete – notify remote (informational).
			b, _ := signaling.EncodeFrame(signaling.Frame{T: "eoc"})
			_ = ws.Write(ctx, websocket.MessageBinary, b)
			return
		}
		b, _ := signaling.EncodeFrame(signaling.Frame{T: "cand", C: c.Marshal()})
		_ = ws.Write(ctx, websocket.MessageBinary, b)
	}); err != nil {
		return nil, err
	}

	// --- 4. Read goroutine: remote cred + trickle candidates ---
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
				_ = agent.AddRemoteCandidate(cand)
			case "eoc":
				// Informational; ICE handles this naturally.
			case "noagent":
				// Target agent is not registered on the hub. Signal the caller
				// with a typed error so it can decide whether to retry.
				select {
				case readErr <- ErrNoAgent:
				default:
				}
				return
			}
		}
	}()

	// --- 5. Exchange credentials ---
	ufrag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		return nil, err
	}
	credFrame, _ := signaling.EncodeFrame(signaling.Frame{T: "cred", U: ufrag, P: pwd})
	if err := ws.Write(ctx, websocket.MessageBinary, credFrame); err != nil {
		return nil, fmt.Errorf("a2al/host: ice send cred: %w", err)
	}

	credTimer := time.NewTimer(defaultICECredentialTimeout)
	defer credTimer.Stop()

	var remoteCred [2]string
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-readErr:
		return nil, fmt.Errorf("a2al/host: signaling read: %w", err)
	case <-credTimer.C:
		return nil, errors.New("a2al/host: ice credentials timeout")
	case remoteCred = <-credCh:
	}

	// --- 6. Gather + connectivity checks (concurrent, standard trickle) ---
	if err := agent.GatherCandidates(); err != nil {
		return nil, err
	}
	if controlling {
		sess.iceConn, err = agent.Dial(ctx, remoteCred[0], remoteCred[1])
	} else {
		sess.iceConn, err = agent.Accept(ctx, remoteCred[0], remoteCred[1])
	}
	if err != nil {
		return nil, err
	}

	ok = true
	return sess, nil
}
