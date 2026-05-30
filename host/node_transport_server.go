// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

// nodeTransportServer manages ICE-backed QUIC transports on the callee side.
//
// After the first Mode A QUIC connection is accepted on a shared transport,
// the QUIC listener is kept open. Subsequent QUIC connections from the same
// caller node (reusing the hole-punched UDP path) are accepted in a background
// goroutine and queued to sharedConnCh for consumption by Host.AcceptShared.
//
// Lifetime: each entry lives as long as its underlying ice.Conn is alive.
// When ICE fails (consent freshness timeout after the last keepalive), the
// quic.Transport errors, ln.Accept returns, the goroutine exits, and evict
// closes all resources.
type nodeTransportServer struct {
	sharedConnCh chan quic.Connection
	mu           sync.Mutex
	entries      map[string]*serverEntry // key: remoteUDPAddr.String()
	log          *slog.Logger
}

type serverEntry struct {
	tr     *quic.Transport
	ln     *quic.Listener
	sess   *iceSession
	cancel context.CancelFunc
}

func newNodeTransportServer(log *slog.Logger) *nodeTransportServer {
	return &nodeTransportServer{
		sharedConnCh: make(chan quic.Connection, 16),
		entries:      make(map[string]*serverEntry),
		log:          log,
	}
}

// register keeps the QUIC listener alive after the first connection is
// accepted, routing subsequent connections to sharedConnCh.
// Ownership of tr, ln, and sess transfers to the server.
func (s *nodeTransportServer) register(ra *net.UDPAddr, tr *quic.Transport,
	ln *quic.Listener, sess *iceSession) {

	key := ra.String()
	ctx, cancel := context.WithCancel(context.Background())
	e := &serverEntry{tr: tr, ln: ln, sess: sess, cancel: cancel}

	s.mu.Lock()
	if old, ok := s.entries[key]; ok {
		old.cancel()
	}
	s.entries[key] = e
	s.mu.Unlock()

	s.log.Debug("node transport server: registered", "remote", key)

	go func() {
		defer s.evict(key)
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			// Non-blocking: if no consumer is reading sharedConnCh (e.g. the
			// application only calls Accept, not AcceptShared), close this
			// connection so the caller falls back to a fresh ICE session rather
			// than hanging indefinitely.
			select {
			case s.sharedConnCh <- conn:
			case <-ctx.Done():
				_ = conn.CloseWithError(0, "server shutdown")
				return
			default:
				_ = conn.CloseWithError(0, "no accept consumer")
			}
		}
	}()
}

func (s *nodeTransportServer) evict(key string) {
	s.mu.Lock()
	e := s.entries[key]
	delete(s.entries, key)
	s.mu.Unlock()
	if e == nil {
		return
	}
	e.cancel()
	_ = e.tr.Close()
	e.sess.Close()
	s.log.Debug("node transport server: evicted", "remote", key)
}
