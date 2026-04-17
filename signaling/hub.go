// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package signaling

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

const icePairTimeout = 30 * time.Second

// Hub is an A2AL ICE signaling server: callee subscription on /signal and
// trickle relay on /ice (with optional target= for waking callees).
type Hub struct {
	ln   net.Listener
	srv  *http.Server
	mu   sync.Mutex
	slots map[string]*relaySlot

	callees  map[string]*websocket.Conn // AID string → subscriber conn
	connAIDs map[*websocket.Conn][]string

	sessionsTotal   atomic.Uint64
	sessionsActive  atomic.Int32
	noAgentTotal    atomic.Uint64
}

// ListenHub serves /signal and /ice on tcpAddr (e.g. "0.0.0.0:4121").
func ListenHub(tcpAddr string) (*Hub, error) {
	ln, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	h := &Hub{
		ln:       ln,
		slots:    make(map[string]*relaySlot),
		callees:  make(map[string]*websocket.Conn),
		connAIDs: make(map[*websocket.Conn][]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/signal", h.handleSignal)
	mux.HandleFunc("/ice", h.handleICE)
	h.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = h.srv.Serve(ln) }()
	return h, nil
}

// Addr returns the bound TCP address.
func (h *Hub) Addr() net.Addr {
	if h == nil || h.ln == nil {
		return nil
	}
	return h.ln.Addr()
}

// Close shuts down the hub listener.
func (h *Hub) Close() error {
	if h == nil || h.srv == nil {
		return nil
	}
	return h.srv.Close()
}

// StatsMap returns counters for merging into /debug/stats.
func (h *Hub) StatsMap() map[string]any {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	nConn := len(h.connAIDs)
	nAid := len(h.callees)
	h.mu.Unlock()
	return map[string]any{
		"callees_connected": nConn,
		"aids_registered":   nAid,
		"sessions_active":   h.sessionsActive.Load(),
		"sessions_total":    h.sessionsTotal.Load(),
		"noagent_total":     h.noAgentTotal.Load(),
	}
}

func (h *Hub) slotFor(room string) *relaySlot {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.slots[room]
	if !ok {
		s = newRelaySlot()
		h.slots[room] = s
	}
	return s
}

func (h *Hub) removeSlot(room string) {
	h.mu.Lock()
	delete(h.slots, room)
	h.mu.Unlock()
}

func (h *Hub) handleSignal(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		Subprotocols: []string{SubprotocolICE},
	})
	if err != nil {
		return
	}
	go h.signalConnLoop(c)
}

func (h *Hub) signalConnLoop(c *websocket.Conn) {
	defer h.unregisterSignalConn(c)
	ctx := context.Background()
	for {
		rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		_, data, err := c.Read(rctx)
		cancel()
		if err != nil {
			return
		}
		fr, err := DecodeFrame(data)
		if err != nil {
			continue
		}
		if fr.T == "reg" && fr.AID != "" {
			h.registerAID(c, fr.AID)
		}
	}
}

func (h *Hub) registerAID(c *websocket.Conn, aid string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old := h.callees[aid]; old != nil && old != c {
		h.removeAIDFromConnLocked(old, aid)
	}
	h.callees[aid] = c
	sl := h.connAIDs[c]
	for _, x := range sl {
		if x == aid {
			return
		}
	}
	h.connAIDs[c] = append(sl, aid)
}

func (h *Hub) removeAIDFromConnLocked(c *websocket.Conn, aid string) {
	sl := h.connAIDs[c]
	out := sl[:0]
	for _, x := range sl {
		if x != aid {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		delete(h.connAIDs, c)
	} else {
		h.connAIDs[c] = out
	}
}

func (h *Hub) unregisterSignalConn(c *websocket.Conn) {
	h.mu.Lock()
	for _, aid := range h.connAIDs[c] {
		if h.callees[aid] == c {
			delete(h.callees, aid)
		}
	}
	delete(h.connAIDs, c)
	h.mu.Unlock()
	_ = c.CloseNow()
}

func (h *Hub) handleICE(w http.ResponseWriter, req *http.Request) {
	room := req.URL.Query().Get("room")
	if room == "" {
		http.Error(w, "missing room", http.StatusBadRequest)
		return
	}
	target := req.URL.Query().Get("target")
	caller := req.URL.Query().Get("caller")
	if target != "" && caller == "" {
		http.Error(w, "missing caller", http.StatusBadRequest)
		return
	}

	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		Subprotocols: []string{SubprotocolICE},
	})
	if err != nil {
		return
	}

	if target != "" {
		h.mu.Lock()
		calleeConn, ok := h.callees[target]
		h.mu.Unlock()
		if !ok {
			h.noAgentTotal.Add(1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			b, _ := EncodeFrame(Frame{T: "noagent"})
			_ = c.Write(ctx, websocket.MessageBinary, b)
			cancel()
			_ = c.CloseNow()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		b, err := EncodeFrame(Frame{T: "incoming", Room: room, Caller: caller, Target: target})
		if err != nil {
			cancel()
			_ = c.CloseNow()
			return
		}
		if err := calleeConn.Write(ctx, websocket.MessageBinary, b); err != nil {
			cancel()
			_ = c.CloseNow()
			return
		}
		cancel()
	}

	h.pairICE(room, c)
}

func (h *Hub) pairICE(room string, c *websocket.Conn) {
	slot := h.slotFor(room)
	slot.mu.Lock()
	if slot.waiting == nil {
		slot.waiting = c
		slot.mu.Unlock()
		h.sessionsActive.Add(1)

		var peer *websocket.Conn
		select {
		case peer = <-slot.ready:
		case <-time.After(icePairTimeout):
			slot.mu.Lock()
			if slot.waiting == c {
				slot.waiting = nil
			}
			slot.mu.Unlock()
			_ = c.CloseNow()
			h.removeSlot(room)
			h.sessionsActive.Add(-1)
			return
		}
		h.sessionsTotal.Add(1)
		relayPair(c, peer)
		h.removeSlot(room)
		h.sessionsActive.Add(-1)
		return
	}
	slot.waiting = nil
	slot.mu.Unlock()
	slot.ready <- c
	// First peer runs relayPair; this goroutine is done.
}
