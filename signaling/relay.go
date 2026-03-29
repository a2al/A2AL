// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package signaling

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/coder/websocket"
)

type relaySlot struct {
	mu      sync.Mutex
	waiting *websocket.Conn
	ready   chan *websocket.Conn
}

func newRelaySlot() *relaySlot {
	return &relaySlot{ready: make(chan *websocket.Conn, 1)}
}

// Relay is a minimal WebSocket relay: two clients joining the same ?room= are
// paired and their binary frames are forwarded bidirectionally.
// Intended for tests and small-scale deployments.
type Relay struct {
	ln    net.Listener
	srv   *http.Server
	mu    sync.Mutex
	slots map[string]*relaySlot
}

// StartRelay listens on addr (e.g. "127.0.0.1:0") and serves the relay.
func StartRelay(addr string) (*Relay, error) {
	r := &Relay{slots: make(map[string]*relaySlot)}
	mux := http.NewServeMux()
	mux.HandleFunc("/ice", r.handleICE)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	r.ln = ln
	r.srv = &http.Server{Handler: mux}
	go func() { _ = r.srv.Serve(ln) }()
	return r, nil
}

// BaseURL returns ws://host:port (no trailing slash).
func (r *Relay) BaseURL() string {
	if r.ln == nil {
		return ""
	}
	return "ws://" + r.ln.Addr().String()
}

func (r *Relay) Close() error {
	if r.srv == nil {
		return nil
	}
	return r.srv.Close()
}

func (r *Relay) slotFor(room string) *relaySlot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.slots[room]
	if !ok {
		s = newRelaySlot()
		r.slots[room] = s
	}
	return s
}

func (r *Relay) removeSlot(room string) {
	r.mu.Lock()
	delete(r.slots, room)
	r.mu.Unlock()
}

func (r *Relay) handleICE(w http.ResponseWriter, req *http.Request) {
	room := req.URL.Query().Get("room")
	if room == "" {
		http.Error(w, "missing room", http.StatusBadRequest)
		return
	}
	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		Subprotocols: []string{SubprotocolICE},
	})
	if err != nil {
		return
	}

	slot := r.slotFor(room)
	slot.mu.Lock()
	if slot.waiting == nil {
		// First peer for this room — block until the second arrives.
		slot.waiting = c
		slot.mu.Unlock()

		peer := <-slot.ready
		// Both peers connected; relay frames. Blocks until one side closes.
		relayPair(c, peer)
		r.removeSlot(room)
		return
	}
	// Second peer — unblock the first (which is waiting on slot.ready).
	slot.waiting = nil
	slot.mu.Unlock()
	slot.ready <- c
}

// relayPair forwards binary frames between a and b until either side errors.
func relayPair(a, b *websocket.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer a.CloseNow()
	defer b.CloseNow()

	go func() {
		defer cancel()
		for {
			typ, data, err := a.Read(ctx)
			if err != nil {
				return
			}
			if err := b.Write(ctx, typ, data); err != nil {
				return
			}
		}
	}()
	for {
		typ, data, err := b.Read(ctx)
		if err != nil {
			return
		}
		if err := a.Write(ctx, typ, data); err != nil {
			return
		}
	}
}

// JoinURL returns a full WebSocket URL including room query for a relay base.
func JoinURL(relayBase, room string) (string, error) {
	return AppendRoomQuery(relayBase+"/ice", room)
}

// MustJoinURL is JoinURL that panics on error (for tests with fixed inputs).
func MustJoinURL(relayBase, room string) string {
	s, err := JoinURL(relayBase, room)
	if err != nil {
		panic(fmt.Errorf("signaling: MustJoinURL: %w", err))
	}
	return s
}
