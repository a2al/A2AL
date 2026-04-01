// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"
	"github.com/fxamacker/cbor/v2"
	ice "github.com/pion/ice/v3"
	"github.com/pion/stun/v2"

	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/signaling"
)

// defaultICECredentialTimeout is the safety-net deadline for receiving remote
// ICE credentials via the signaling WebSocket. If the caller's context already
// carries a deadline, it takes precedence.
const defaultICECredentialTimeout = 30 * time.Second

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

// mergeICEURLs builds a deduplicated list of STUN/TURN URIs from local config
// and the remote endpoint record. Falls back to a public STUN server when no
// URIs are configured.
func (h *Host) mergeICEURLs(er *protocol.EndpointRecord) []*stun.URI {
	seen := make(map[string]struct{})
	var out []*stun.URI
	add := func(s string) {
		if s == "" {
			return
		}
		u, err := stun.ParseURI(s)
		if err != nil {
			return
		}
		key := u.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, u)
	}
	for _, s := range h.cfg.ICESTUNURLs {
		add(s)
	}
	for _, s := range h.cfg.ICETURNURLs {
		add(s)
	}
	if er != nil {
		for _, s := range er.Turns {
			add(s)
		}
	}
	if len(out) == 0 {
		add("stun:stun.l.google.com:19302")
	}
	return out
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
