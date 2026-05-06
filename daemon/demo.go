package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

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
//
// agentAID is the full AID of the agent activating demo mode.
// sessionLookup returns caller session info keyed by daemon-side TCP source port;
// it is used to identify callers reaching this server via a Tangled Network tunnel.
//
// Callers must hold ds.mu.
func (ds *demoServer) startHTTP(agentAID string, sessionLookup func(int) *sessionInfo) (int, error) {
	if ds.ln != nil {
		return ds.port, nil // already listening
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	shortAID := demoShortAID(agentAID)

	// callerAID extracts the verified remote AID from the session map using
	// the daemon-side TCP source port embedded in r.RemoteAddr.
	// Returns "" when the request did not arrive via a Tangled Network tunnel.
	callerAID := func(r *http.Request) string {
		_, portStr, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return ""
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 {
			return ""
		}
		si := sessionLookup(p)
		if si == nil {
			return ""
		}
		return si.CallerAID
	}

	cors := func(w http.ResponseWriter) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}

	writeJSON := func(w http.ResponseWriter, v any) {
		cors(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	echoResponse := func(r *http.Request, body any) map[string]any {
		result := map[string]any{
			"echo":       body,
			"agent":      agentAID,
			"powered_by": "Tangled Network / a2al.org",
		}
		if c := callerAID(r); c != "" {
			result["caller_aid"] = c
		}
		return result
	}

	mux := http.NewServeMux()

	// ── CORS preflight ────────────────────────────────────────────────────────
	mux.HandleFunc("OPTIONS /", func(w http.ResponseWriter, _ *http.Request) {
		cors(w)
		w.WriteHeader(http.StatusNoContent)
	})

	// ── A2AL Agent Card ───────────────────────────────────────────────────────
	mux.HandleFunc("GET /.well-known/agent.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"name":        "A2AL Demo Agent",
			"description": "A demo agent on the Tangled Network — a decentralized protocol where AI agents find each other by identity, not by IP. No servers. No platforms. No permission required.",
			"version":     "demo",
			"url":         "https://a2al.org",
			"aid":         agentAID,
			"capabilities": map[string]any{"echo": true},
			"tools":        []string{"echo"},
		})
	})

	// ── Google A2A Agent Card ─────────────────────────────────────────────────
	// Format: https://google.github.io/A2A/specification/
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"name":        "A2AL Demo Agent",
			"description": "A demo agent running on the Tangled Network — a decentralized peer-to-peer network where AI agents communicate directly, by cryptographic identity, without any central server. This node proves the protocol works. Welcome to the mesh.",
			"url":         "https://a2al.org",
			"version":     "1.0.0",
			"provider": map[string]any{
				"organization": "A2AL Project",
				"url":          "https://a2al.org",
			},
			"capabilities": map[string]any{
				"streaming":              false,
				"pushNotifications":      false,
				"stateTransitionHistory": false,
			},
			"defaultInputModes":  []string{"text/plain", "application/json"},
			"defaultOutputModes": []string{"application/json"},
			"skills": []map[string]any{
				{
					"id":          "echo",
					"name":        "Echo",
					"description": "Echoes back any message. A simple proof that the decentralized connection works.",
					"tags":        []string{"demo", "connectivity"},
					"examples":    []string{"Hello from the Tangled Network"},
					"inputModes":  []string{"text/plain", "application/json"},
					"outputModes": []string{"application/json"},
				},
			},
		})
	})

	// ── OpenAI Plugin Manifest ────────────────────────────────────────────────
	// Format: https://platform.openai.com/docs/plugins/getting-started
	mux.HandleFunc("GET /.well-known/ai-plugin.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"schema_version":        "v1",
			"name_for_model":        "a2al_demo",
			"name_for_human":        "A2AL Demo Agent",
			"description_for_model": "A demo agent on the A2AL Tangled Network. Use the echo tool to verify decentralized agent connectivity. The agent is identified by a cryptographic AID, not an IP address.",
			"description_for_human": "Demo agent on the Tangled Network — a decentralized network for AI agent communication. No servers, no platforms, no permission required.",
			"auth":                  map[string]any{"type": "none"},
			"api": map[string]any{
				"type": "openapi",
				"url":  "/openapi.json",
			},
			"legal_info_url": "https://a2al.org",
		})
	})

	// ── OpenAPI Specification ─────────────────────────────────────────────────
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"openapi": "3.1.0",
			"info": map[string]any{
				"title":       "A2AL Demo Agent",
				"version":     "1.0.0",
				"description": "Demo agent on the Tangled Network — decentralized AI agent communication.",
			},
			"paths": map[string]any{
				"/echo": map[string]any{
					"post": map[string]any{
						"operationId": "echo",
						"summary":     "Echo any JSON payload",
						"description": "Returns the request body unchanged. Proves the decentralized connection over the Tangled Network is live.",
						"requestBody": map[string]any{
							"required": false,
							"content": map[string]any{
								"application/json": map[string]any{
									"schema": map[string]any{
										"type":                 "object",
										"additionalProperties": true,
									},
								},
							},
						},
						"responses": map[string]any{
							"200": map[string]any{
								"description": "Echo response",
								"content": map[string]any{
									"application/json": map[string]any{
										"schema": map[string]any{"type": "object"},
									},
								},
							},
						},
					},
				},
			},
		})
	})

	// ── MCP Server Card ───────────────────────────────────────────────────────
	// Draft: https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1649
	mux.HandleFunc("GET /.well-known/mcp.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"schema_version": "2025-11-25",
			"name":           "A2AL Demo Agent",
			"description":    "Demo agent on the Tangled Network — a decentralized protocol for AI agent communication.",
			"transport": []map[string]any{
				{"type": "http", "url": "/mcp"},
			},
			"tools": []map[string]any{
				{
					"name":        "echo",
					"description": "Echoes back any input. Demonstrates live connectivity over the Tangled Network.",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"message": map[string]any{
								"type":        "string",
								"description": "Any message to echo back",
							},
						},
					},
				},
			},
		})
	})

	// ── MCP JSON-RPC 2.0 ─────────────────────────────────────────────────────
	// Handles: initialize, tools/list, tools/call
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]any{
				"jsonrpc": "2.0",
				"id":      nil,
				"error":   map[string]any{"code": -32700, "message": "parse error"},
			})
			return
		}
		ok := func(result any) {
			writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		}
		switch req.Method {
		case "initialize":
			ok(map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "A2AL Demo Agent", "version": "1.0.0"},
				"instructions":    "This agent runs on the Tangled Network — a decentralized mesh where AI communicates by identity, not by IP. Try tools/list.",
			})
		case "tools/list":
			ok(map[string]any{
				"tools": []map[string]any{
					{
						"name":        "echo",
						"description": "Echoes back any input over the Tangled Network. A live proof that decentralized AI communication works.",
						"inputSchema": map[string]any{
							"type":       "object",
							"properties": map[string]any{"message": map[string]any{"type": "string"}},
						},
					},
				},
			})
		case "tools/call":
			var params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(req.Params, &params)
			var args any
			_ = json.Unmarshal(params.Arguments, &args)
			resp := echoResponse(r, args)
			b, _ := json.Marshal(resp)
			ok(map[string]any{
				"content": []map[string]any{{"type": "text", "text": string(b)}},
			})
		default:
			writeJSON(w, map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"error":   map[string]any{"code": -32601, "message": "method not found"},
			})
		}
	})

	// ── Google A2A message:send ───────────────────────────────────────────────
	// Format: https://google.github.io/A2A/specification/ (JSON-RPC 2.0)
	mux.HandleFunc("POST /message:send", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Params  struct {
				Message struct {
					Parts []struct {
						Kind string `json:"kind"`
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"message"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		text := "(empty)"
		for _, p := range req.Params.Message.Parts {
			if p.Kind == "text" && p.Text != "" {
				text = p.Text
				break
			}
		}

		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage(`"task-demo"`)
		}

		echoText := fmt.Sprintf("Echo from %s on the Tangled Network: %s", shortAID, text)
		meta := map[string]any{
			"agent":      agentAID,
			"powered_by": "Tangled Network / a2al.org",
		}
		if c := callerAID(r); c != "" {
			meta["caller_aid"] = c
		}

		writeJSON(w, map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"result": map[string]any{
				"id":     "task-demo",
				"status": map[string]any{"state": "completed"},
				"artifacts": []map[string]any{
					{
						"artifactId": "echo",
						"parts":      []map[string]any{{"kind": "text", "text": echoText}},
					},
				},
				"metadata": meta,
			},
		})
	})

	// ── Echo ──────────────────────────────────────────────────────────────────
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		var body any
		_ = json.NewDecoder(r.Body).Decode(&body)
		writeJSON(w, echoResponse(r, body))
	})

	// ── Catch-all ─────────────────────────────────────────────────────────────
	// GET (and anything else): HTML info page.
	// POST to unknown path: echo the body back.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		if r.Method == http.MethodPost {
			var body any
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(echoResponse(r, body))
			return
		}
		caller := callerAID(r)
		callerLine := ""
		if caller != "" {
			callerLine = fmt.Sprintf("\nCaller\n  %s\n  Verified by the Tangled Network.\n", caller)
		}
		page := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>A2AL Agent</title></head><body><pre>
%s

An autonomous agent on the Tangled Network.
AI agents that find each other by identity — not by IP.
No servers. No platforms. No permission required.

  https://a2al.org

Endpoints
  GET  /.well-known/agent.json        A2AL Agent Card
  GET  /.well-known/agent-card.json   Google A2A Agent Card
  GET  /.well-known/mcp.json          MCP Server Card (Anthropic)
  GET  /.well-known/ai-plugin.json    OpenAI Plugin Manifest
  GET  /openapi.json                  OpenAPI Specification
  POST /echo                          Echo (any JSON)
  POST /mcp                           MCP JSON-RPC 2.0
  POST /message:send                  Google A2A JSON-RPC 2.0
%s</pre></body></html>`, shortAID, callerLine)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, page)
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
