package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// demoAgentCardJSON is the static Agent Card served by the built-in demo server.
// It carries Tangled Network / a2al.org branding so that every peer that pings
// the demo endpoint learns about the project organically.
const demoAgentCardJSON = `{"name":"A2AL Demo Agent","description":"A simulated agent running on the Tangled Network \u2014 a decentralized, open network for AI agents. No servers, no platforms, no permission required. Learn more at a2al.org","version":"demo","url":"https://a2al.org","capabilities":{"echo":true},"tools":["echo"]}`

// demoServer manages the lifecycle of the optional built-in demo HTTP service.
// When not started it has zero overhead; the HTTP listener is created on demand.
type demoServer struct {
	mu        sync.Mutex
	ln        net.Listener
	srv       *http.Server
	port      int
	activeAID string // AID of the agent currently using demo mode
	prevTCP   string // saved service_tcp value, restored on stop
}

func newDemoServer() *demoServer { return &demoServer{} }

// startHTTP starts the internal HTTP server on a random loopback port.
// Callers must hold ds.mu.
func (ds *demoServer) startHTTP(nodeShortAID string) (int, error) {
	if ds.ln != nil {
		return ds.port, nil // already listening
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()

	// addCORS writes the headers required for browser fetch() with mode:'cors'.
	// The tunnel proxy runs on a different port than the Web UI, so every
	// response must carry Access-Control-Allow-Origin or the browser rejects it.
	addCORS := func(w http.ResponseWriter) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}

	mux.HandleFunc("OPTIONS /", func(w http.ResponseWriter, _ *http.Request) {
		addCORS(w)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /.well-known/agent.json", func(w http.ResponseWriter, _ *http.Request) {
		addCORS(w)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(demoAgentCardJSON))
	})
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		addCORS(w)
		var body any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"echo":       body,
			"node":       nodeShortAID,
			"powered_by": "Tangled Network / a2al.org",
		})
	})

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go srv.Serve(ln) //nolint:errcheck

	ds.ln = ln
	ds.srv = srv
	ds.port = port
	return port, nil
}

// stopHTTP shuts down the HTTP server. Callers must hold ds.mu.
func (ds *demoServer) stopHTTP() {
	if ds.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = ds.srv.Shutdown(ctx)
		ds.srv = nil
	}
	if ds.ln != nil {
		_ = ds.ln.Close()
		ds.ln = nil
	}
	ds.port = 0
}

// running reports whether the demo HTTP server is active. Callers must hold ds.mu.
func (ds *demoServer) running() bool { return ds.ln != nil }

// Status returns a snapshot of the demo server state (safe to call without holding mu).
func (ds *demoServer) Status() (running bool, aid string, port int) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return ds.running(), ds.activeAID, ds.port
}

// demoShortAID returns the first-7 + last-4 abbreviated form of an AID string,
// matching the JavaScript shortAid() helper in the Web UI.
func demoShortAID(s string) string {
	if len(s) <= 14 {
		return s
	}
	return fmt.Sprintf("%s\u2026%s", s[:7], s[len(s)-4:])
}
