// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/host"
)

func (d *Daemon) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", d.handleHealth)
	mux.HandleFunc("GET /status", d.handleStatus)
	mux.HandleFunc("GET /config", d.handleGetConfig)
	mux.HandleFunc("PATCH /config", d.handlePatchConfig)
	mux.HandleFunc("GET /config/schema", d.handleConfigSchema)
	mux.HandleFunc("POST /identity/generate", d.handleIdentityGenerate)
	mux.HandleFunc("GET /agents/{aid}/export", d.handleAgentsExport)
	mux.HandleFunc("POST /agents", d.handleAgentsPost)
	mux.HandleFunc("POST /agents/generate", d.handleAgentsGenerate)
	mux.HandleFunc("POST /agents/ethereum/delegation-message", d.handleEthDelegationMessage)
	mux.HandleFunc("POST /agents/ethereum/register", d.handleEthRegister)
	mux.HandleFunc("POST /agents/ethereum/proof", d.handleEthProof)
	mux.HandleFunc("POST /agents/paralism/proof", d.handleParalismProof)
	mux.HandleFunc("GET /agents", d.handleAgentsList)
	mux.HandleFunc("GET /agents/{aid}", d.handleAgentsGet)
	mux.HandleFunc("GET /agents/{aid}/probe", d.handleAgentsProbe)
	mux.HandleFunc("PATCH /agents/{aid}", d.withAgentMiddleware(d.handleAgentsPatch))
	mux.HandleFunc("POST /agents/{aid}/heartbeat", d.withAgentMiddleware(d.handleAgentHeartbeat))
	mux.HandleFunc("POST /agents/{aid}/publish", d.withAgentMiddleware(d.handleAgentsPublish))
	mux.HandleFunc("POST /agents/{aid}/records", d.withAgentMiddleware(d.handleAgentsRecordsPost))
	mux.HandleFunc("POST /agents/{aid}/mailbox/send", d.withAgentMiddleware(d.handleAgentsMailboxSend))
	mux.HandleFunc("POST /agents/{aid}/mailbox/poll", d.withAgentMiddleware(d.handleAgentsMailboxPoll))
	mux.HandleFunc("POST /agents/{aid}/services", d.withAgentMiddleware(d.handleAgentsTopicsPost))
	mux.HandleFunc("DELETE /agents/{aid}/services/{service...}", d.withAgentMiddleware(d.handleAgentsTopicsDelete))
	mux.HandleFunc("POST /agents/{aid}/profile", d.withAgentMiddleware(d.handleAgentsProfilePost))
	mux.HandleFunc("DELETE /agents/{aid}/profile", d.withAgentMiddleware(d.handleAgentsProfileDelete))
	mux.HandleFunc("POST /discover", d.handleDiscover)
	mux.HandleFunc("DELETE /agents/{aid}", d.withAgentMiddleware(d.handleAgentsDelete))
	mux.HandleFunc("GET /resolve/{aid}/records", d.handleResolveRecords)
	mux.HandleFunc("POST /resolve/{aid}", d.handleResolve)
	mux.HandleFunc("POST /connect/{aid}", d.handleConnect)
	mux.HandleFunc("POST /fetch/{aid}", d.handleFetch)
	mux.HandleFunc("POST /tunnel/{aid}", d.handleTunnelOpen)
	mux.HandleFunc("DELETE /tunnel/{id}", d.handleTunnelClose)
	mux.HandleFunc("GET /tunnel", d.handleTunnelList)
	mux.HandleFunc("GET /tunnel/{id}", d.handleTunnelGet)
	mux.Handle("/debug/", d.h.DebugHTTPHandler())
	mux.Handle("/mcp/", d.mcpHTTPHandler())
	mux.HandleFunc("POST /demo/start", d.handleDemoStart)
	mux.HandleFunc("POST /demo/stop", d.handleDemoStop)
	mux.HandleFunc("GET /sessions/{port}", d.handleGetSession)
	mux.HandleFunc("GET /agents/{aid}/events", d.withAgentMiddleware(d.handleAgentEvents))
	mux.HandleFunc("GET /events", d.handleGlobalEvents)
	mux.HandleFunc("GET /update/status", d.handleUpdateStatus)
	mux.HandleFunc("POST /update/apply", d.handleUpdateApply)

	// Mount Web UI assets and the AID proxy outside withMiddleware:
	// - Web UI HTML/JS/CSS contain no sensitive data; auth happens at the API call level.
	// - AID proxy must accept arbitrary Content-Types and requests without an API token.
	outer := http.NewServeMux()
	registerWebUIRoutes(outer)
	outer.Handle("/aid/", d.newAIDProxy())
	outer.Handle("/", d.withMiddleware(mux))
	return outer
}

// withAgentMiddleware wraps agent-specific handlers with:
//  1. (Future) per-agent token verification via X-Agent-Token header.
//     When the registry entry carries a token (not yet issued), it will be
//     validated here with constant-time compare before proceeding.
//  2. Implicit heartbeat: any non-GET call that reaches a registered agent
//     is treated as a liveness signal, eliminating the need for explicit
//     heartbeat calls in agents that already use other API endpoints.
//
// The hook point for per-agent auth is intentionally isolated here so that
// future implementations only need to fill in step 1 without touching
// individual handler functions.
func (d *Daemon) withAgentMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		aid, err := a2al.ParseAddress(r.PathValue("aid"))
		if err != nil {
			// Let the underlying handler produce the proper error.
			next(w, r)
			return
		}

		// --- Future per-agent token verification slot ---
		// When per-agent tokens are introduced, uncomment and implement:
		//
		//   agentToken := r.Header.Get("X-Agent-Token")
		//   d.regMu.RLock()
		//   e := d.reg.Get(aid)
		//   d.regMu.RUnlock()
		//   if e != nil && e.Token != "" {
		//       if subtle.ConstantTimeCompare([]byte(agentToken), []byte(e.Token)) != 1 {
		//           http.Error(w, `{"error":"agent unauthorized"}`, http.StatusUnauthorized)
		//           return
		//       }
		//   }
		// ------------------------------------------------

		d.touchHeartbeat(aid)

		next(w, r)
	}
}

func (d *Daemon) withMiddleware(next http.Handler) http.Handler {
	const maxRequestBody = 1 << 20 // 1 MiB
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

		// Auth model:
		//   - No api_token configured  → fully open (local + remote).
		//   - api_token configured     → loopback callers bypass by default;
		//                                 remote callers must present Bearer token.
		//   - require_local_token=true → loopback callers must also present token.
		// Loopback access additionally enforces Host-header check to defeat DNS rebinding.
		// Reject requests that arrive on loopback but carry a non-loopback Host
		// header — this is the fingerprint of a DNS-rebinding attack from a browser.
		// An absent Host header (HTTP/1.0 clients, raw TCP tools) is allowed because
		// non-browser callers never send a spoofed Host.
		if isLoopback(r) && r.Host != "" && !hostHeaderIsLoopback(r.Host) {
			http.Error(w, `{"error":"host header not allowed"}`, http.StatusBadRequest)
			return
		}
		isLocal := isLoopback(r) && (r.Host == "" || hostHeaderIsLoopback(r.Host))
		needToken := d.cfg.APIToken != "" && (!isLocal || d.cfg.RequireLocalToken)
		if needToken {
			got := r.Header.Get("Authorization")
			want := "Bearer " + d.cfg.APIToken
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			ct := r.Header.Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				http.Error(w, `{"error":"Content-Type must be application/json"}`, http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopback reports whether the request came from a loopback address.
func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// hostHeaderIsLoopback reports whether the HTTP Host header refers to a loopback name.
// Accepts "127.0.0.1", "localhost", "[::1]" with optional ":port".
func hostHeaderIsLoopback(host string) bool {
	if host == "" {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // no port
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func (d *Daemon) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func (d *Daemon) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, d.execStatus())
}

func (d *Daemon) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if err := d.execAgentHeartbeat(r.PathValue("aid")); err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"error":"heartbeat failed"}`, http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (d *Daemon) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	c := *d.cfg
	if c.APIToken != "" {
		c.APIToken = "***"
	}
	writeJSON(w, c)
}

type patchConfigReq struct {
	ListenAddr       *string                     `json:"listen_addr,omitempty"`
	QUICListenAddr   *string                     `json:"quic_listen_addr,omitempty"`
	Bootstrap        *[]string                   `json:"bootstrap,omitempty"`
	DisableUPnP      *bool                       `json:"disable_upnp,omitempty"`
	FallbackHost     *string                     `json:"fallback_host,omitempty"`
	MinObservedPeers *int                        `json:"min_observed_peers,omitempty"`
	APIAddr          *string                     `json:"api_addr,omitempty"`
	APIToken         *string                     `json:"api_token,omitempty"`
	KeyDir           *string                     `json:"key_dir,omitempty"`
	LogFormat        *string                     `json:"log_format,omitempty"`
	LogLevel         *string                     `json:"log_level,omitempty"`
	AutoPublish      *bool                       `json:"auto_publish,omitempty"`
	TURNServers      *[]config.TURNServerConfig  `json:"turn_servers,omitempty"`
	DisableRelay     *bool                       `json:"disable_relay,omitempty"`
}

func (d *Daemon) handlePatchConfig(w http.ResponseWriter, r *http.Request) {
	var req patchConfigReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	cfg := *d.cfg
	prevAutoPublish := cfg.AutoPublish
	restart := []string{}
	if req.ListenAddr != nil {
		cfg.ListenAddr = *req.ListenAddr
		restart = append(restart, "listen_addr")
	}
	if req.QUICListenAddr != nil {
		cfg.QUICListenAddr = *req.QUICListenAddr
		restart = append(restart, "quic_listen_addr")
	}
	if req.Bootstrap != nil {
		cfg.Bootstrap = *req.Bootstrap
		restart = append(restart, "bootstrap")
	}
	if req.DisableUPnP != nil {
		cfg.DisableUPnP = *req.DisableUPnP
		restart = append(restart, "disable_upnp")
	}
	if req.FallbackHost != nil {
		cfg.FallbackHost = *req.FallbackHost
		restart = append(restart, "fallback_host")
	}
	if req.MinObservedPeers != nil {
		cfg.MinObservedPeers = *req.MinObservedPeers
		restart = append(restart, "min_observed_peers")
	}
	if req.APIAddr != nil {
		cfg.APIAddr = *req.APIAddr
		restart = append(restart, "api_addr")
	}
	if req.APIToken != nil {
		cfg.APIToken = *req.APIToken
	}
	if req.KeyDir != nil {
		cfg.KeyDir = *req.KeyDir
		restart = append(restart, "key_dir")
	}
	if req.LogFormat != nil {
		cfg.LogFormat = *req.LogFormat
	}
	if req.LogLevel != nil {
		cfg.LogLevel = *req.LogLevel
	}
	if req.AutoPublish != nil {
		cfg.AutoPublish = *req.AutoPublish
	}
	if req.TURNServers != nil {
		cfg.TURNServers = *req.TURNServers
		restart = append(restart, "turn_servers")
	}
	if req.DisableRelay != nil {
		cfg.DisableRelay = *req.DisableRelay
	}
	if err := cfg.Validate(); err != nil {
		http.Error(w, `{"error":"invalid config"}`, http.StatusBadRequest)
		return
	}
	if err := config.Save(d.cfgPath, cfg); err != nil {
		http.Error(w, `{"error":"save failed"}`, http.StatusInternalServerError)
		return
	}
	*d.cfg = cfg
	if req.AutoPublish != nil && *req.AutoPublish && !prevAutoPublish {
		d.publishNodeNowAsync()
	}
	writeJSON(w, map[string]any{"ok": true, "restart_required": restart})
}

func (d *Daemon) handleConfigSchema(w http.ResponseWriter, _ *http.Request) {
	const schema = `{
  "type": "object",
  "properties": {
    "listen_addr": {"type": "string"},
    "quic_listen_addr": {"type": "string"},
    "bootstrap": {"type": "array", "items": {"type": "string"}},
    "disable_upnp": {"type": "boolean"},
    "fallback_host": {"type": "string"},
    "min_observed_peers": {"type": "integer"},
    "api_addr": {"type": "string"},
    "api_token": {"type": "string"},
    "key_dir": {"type": "string"},
    "log_format": {"type": "string", "enum": ["text","json"]},
    "log_level": {"type": "string"},
    "auto_publish": {"type": "boolean", "description": "Publish node AID to DHT on a schedule (default true)"},
    "signal_listen_addr": {"type": "string", "description": "TCP address for embedded ICE hub; empty=same port as listen_addr; off=disable"},
    "turn_servers": {"type": "array", "items": {"type": "object", "properties": {"url": {"type": "string"}, "credential_type": {"type": "string", "enum": ["static","hmac","rest_api"]}, "username": {"type": "string"}, "credential": {"type": "string"}, "credential_url": {"type": "string"}}}},
    "disable_relay": {"type": "boolean", "description": "Disable TURN relay for outbound connections by default (default false)"}
  }
}`
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(schema))
}

type identityGenResp struct {
	MasterPrivateKeyHex      string `json:"master_private_key_hex,omitempty"`
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	AID                      string `json:"aid"`
	Warning                  string `json:"warning,omitempty"`
}

func (d *Daemon) handleIdentityGenerate(w http.ResponseWriter, r *http.Request) {
	out, err := d.execIdentityGenerate()
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	writeJSON(w, out)
}

func (d *Daemon) handleAgentsExport(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r) {
		http.Error(w, `{"error":"export only available on loopback"}`, http.StatusForbidden)
		return
	}
	out, err := d.execAgentExport(r.PathValue("aid"))
	if err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, out)
}

type registerAgentReq struct {
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	ServiceTCP               string `json:"service_tcp"`
}

type patchAgentReq struct {
	OperationalPrivateKeyHex string  `json:"operational_private_key_hex"`
	ServiceTCP               *string `json:"service_tcp"`
}

// probeTCP dials addr (which may carry an "https://" or "http://" scheme
// prefix as accepted by parseServiceTCP) and returns true on success.
// The scheme is stripped before dialling; TLS handshake is not attempted —
// a successful TCP connect is sufficient to confirm reachability.
func probeTCP(raw string, d time.Duration) bool {
	_, addr := parseServiceTCP(raw)
	h, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	network := "tcp"
	dialAddr := addr
	if ip := net.ParseIP(h); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			network = "tcp4"
			dialAddr = net.JoinHostPort(ip4.String(), port)
		}
	}
	c, err := net.DialTimeout(network, dialAddr, d)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// validateServiceTCP returns an error when v contains a path component.
// Accepted formats: "host:port", "http://host:port", "https://host:port".
func validateServiceTCP(v string) error {
	if v == "" {
		return nil
	}
	_, addr := parseServiceTCP(v)
	if strings.Contains(addr, "/") {
		return errBadServiceTCP
	}
	return nil
}

type agentsGenerateReq struct {
	Chain string `json:"chain,omitempty"`
}

type ethDelegationMessageReq struct {
	OperationalPublicKeyHex      string `json:"operational_public_key_hex,omitempty"`
	OperationalPrivateKeySeedHex string `json:"operational_private_key_seed_hex,omitempty"`
	Agent                        string `json:"agent"`
	IssuedAt                     uint64 `json:"issued_at"`
	ExpiresAt                    uint64 `json:"expires_at"`
	Scope                        uint8  `json:"scope,omitempty"`
}

func (d *Daemon) handleEthDelegationMessage(w http.ResponseWriter, r *http.Request) {
	var req ethDelegationMessageReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	msg, err := d.execEthereumDelegationMessage(req.OperationalPublicKeyHex, req.OperationalPrivateKeySeedHex, req.Agent, req.IssuedAt, req.ExpiresAt, req.Scope)
	if err != nil {
		switch {
		case errors.Is(err, errBadOpPubHex), errors.Is(err, errBadOpSeedHex):
			http.Error(w, `{"error":"bad operational key material"}`, http.StatusBadRequest)
		case errors.Is(err, errEthPubOrSeedRequired), errors.Is(err, errEthOpKeyAmbiguous):
			http.Error(w, `{"error":"provide exactly one of operational_public_key_hex or operational_private_key_seed_hex"}`, http.StatusBadRequest)
		case errors.Is(err, errEthBadAgent):
			http.Error(w, `{"error":"bad agent"}`, http.StatusBadRequest)
		default:
			http.Error(w, `{"error":"delegation message"}`, http.StatusBadRequest)
		}
		return
	}
	writeJSON(w, map[string]string{"message": msg})
}

type ethRegisterAPIReq struct {
	Agent                        string `json:"agent"`
	IssuedAt                     uint64 `json:"issued_at"`
	ExpiresAt                    uint64 `json:"expires_at"`
	Scope                        uint8  `json:"scope,omitempty"`
	EthSignatureHex              string `json:"eth_signature_hex"`
	ServiceTCP                   string `json:"service_tcp"`
	OperationalPrivateKeyHex     string `json:"operational_private_key_hex,omitempty"`
	OperationalPrivateKeySeedHex string `json:"operational_private_key_seed_hex,omitempty"`
}

func (d *Daemon) handleEthRegister(w http.ResponseWriter, r *http.Request) {
	var req ethRegisterAPIReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	aid, err := d.execEthereumRegister(req.Agent, req.IssuedAt, req.ExpiresAt, req.Scope, req.EthSignatureHex, req.ServiceTCP, req.OperationalPrivateKeyHex, req.OperationalPrivateKeySeedHex)
	if err != nil {
		switch {
		case errors.Is(err, errEthOpKeyMissing), errors.Is(err, errEthOpKeyAmbiguous):
			http.Error(w, `{"error":"operational key"}`, http.StatusBadRequest)
		case errors.Is(err, errBadOpKeyHex), errors.Is(err, errBadOpSeedHex):
			http.Error(w, `{"error":"bad operational key"}`, http.StatusBadRequest)
		case errors.Is(err, errEthBadAgent):
			http.Error(w, `{"error":"bad agent"}`, http.StatusBadRequest)
		case errors.Is(err, errEthBadSignature):
			http.Error(w, `{"error":"bad eth_signature_hex"}`, http.StatusBadRequest)
		case errors.Is(err, errEthSigVerify):
			http.Error(w, `{"error":"signature verify failed"}`, http.StatusBadRequest)
		case errors.Is(err, errDelegationVerify):
			http.Error(w, `{"error":"delegation verify"}`, http.StatusBadRequest)
		case errors.Is(err, errNodeAsAgent):
			http.Error(w, `{"error":"cannot register node identity as agent"}`, http.StatusBadRequest)
		case errors.Is(err, errPersist):
			http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		default:
			writeJSONStatus(w, http.StatusConflict, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, map[string]string{"aid": aid.String(), "status": "registered"})
}

type ethProofAPIReq struct {
	EthereumPrivateKeyHex        string `json:"ethereum_private_key_hex"`
	IssuedAt                     uint64 `json:"issued_at"`
	ExpiresAt                    uint64 `json:"expires_at"`
	Scope                        uint8  `json:"scope,omitempty"`
	OperationalPrivateKeyHex     string `json:"operational_private_key_hex,omitempty"`
	OperationalPrivateKeySeedHex string `json:"operational_private_key_seed_hex,omitempty"`
}

func (d *Daemon) handleEthProof(w http.ResponseWriter, r *http.Request) {
	var req ethProofAPIReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	out, err := d.execEthereumProofFromKey(req.EthereumPrivateKeyHex, req.IssuedAt, req.ExpiresAt, req.Scope, req.OperationalPrivateKeyHex, req.OperationalPrivateKeySeedHex)
	if err != nil {
		switch {
		case errors.Is(err, errEthBadPrivHex):
			http.Error(w, `{"error":"bad ethereum_private_key_hex"}`, http.StatusBadRequest)
		case errors.Is(err, errEthOpKeyAmbiguous):
			http.Error(w, `{"error":"operational key"}`, http.StatusBadRequest)
		case errors.Is(err, errBadOpKeyHex), errors.Is(err, errBadOpSeedHex):
			http.Error(w, `{"error":"bad operational key"}`, http.StatusBadRequest)
		default:
			http.Error(w, `{"error":"proof failed"}`, http.StatusBadRequest)
		}
		return
	}
	writeJSON(w, out)
}

type paralismProofAPIReq struct {
	ParalismPrivateKeyHex        string `json:"paralism_private_key_hex"`
	IssuedAt                     uint64 `json:"issued_at"`
	ExpiresAt                    uint64 `json:"expires_at"`
	Scope                        uint8  `json:"scope,omitempty"`
	OperationalPrivateKeyHex     string `json:"operational_private_key_hex,omitempty"`
	OperationalPrivateKeySeedHex string `json:"operational_private_key_seed_hex,omitempty"`
}

func (d *Daemon) handleParalismProof(w http.ResponseWriter, r *http.Request) {
	var req paralismProofAPIReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	out, err := d.execParalismProofFromKey(req.ParalismPrivateKeyHex, req.IssuedAt, req.ExpiresAt, req.Scope, req.OperationalPrivateKeyHex, req.OperationalPrivateKeySeedHex)
	if err != nil {
		switch {
		case errors.Is(err, errParalismBadPrivHex):
			http.Error(w, `{"error":"bad paralism_private_key_hex"}`, http.StatusBadRequest)
		case errors.Is(err, errEthOpKeyAmbiguous):
			http.Error(w, `{"error":"operational key"}`, http.StatusBadRequest)
		case errors.Is(err, errBadOpKeyHex), errors.Is(err, errBadOpSeedHex):
			http.Error(w, `{"error":"bad operational key"}`, http.StatusBadRequest)
		default:
			http.Error(w, `{"error":"proof failed"}`, http.StatusBadRequest)
		}
		return
	}
	writeJSON(w, out)
}

func (d *Daemon) handleAgentsGenerate(w http.ResponseWriter, r *http.Request) {
	var req agentsGenerateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	switch req.Chain {
	case "", "ethereum":
		out, err := d.execEthereumIdentityGenerate()
		if err != nil {
			http.Error(w, `{"error":"generate failed"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, out)
	case "paralism":
		out, err := d.execParalismIdentityGenerate()
		if err != nil {
			http.Error(w, `{"error":"generate failed"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, out)
	default:
		http.Error(w, `{"error":"unsupported chain"}`, http.StatusBadRequest)
		return
	}
}

func (d *Daemon) handleAgentsPost(w http.ResponseWriter, r *http.Request) {
	var req registerAgentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	aid, err := d.execAgentRegister(req)
	if err != nil {
		switch {
		case errors.Is(err, errBadDelegationHex):
			http.Error(w, `{"error":"bad delegation_proof_hex"}`, http.StatusBadRequest)
		case errors.Is(err, errDelegationParse):
			http.Error(w, `{"error":"delegation parse"}`, http.StatusBadRequest)
		case errors.Is(err, errBadOpKeyHex):
			http.Error(w, `{"error":"bad operational_private_key_hex"}`, http.StatusBadRequest)
		case errors.Is(err, errDelegationVerify):
			http.Error(w, `{"error":"delegation verify"}`, http.StatusBadRequest)
		case errors.Is(err, errAID):
			http.Error(w, `{"error":"aid"}`, http.StatusBadRequest)
		case errors.Is(err, errNodeAsAgent):
			http.Error(w, `{"error":"cannot register node identity as agent"}`, http.StatusBadRequest)
		case errors.Is(err, errPersist):
			http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		default:
			writeJSONStatus(w, http.StatusConflict, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, map[string]string{"aid": aid.String(), "status": "registered"})
}

func (d *Daemon) handleAgentsList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"agents": d.execAgentsList()})
}

func (d *Daemon) handleAgentsGet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	out, err := d.execAgentGet(ctx, r.PathValue("aid"))
	if err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, out)
}

func (d *Daemon) handleAgentsProbe(w http.ResponseWriter, r *http.Request) {
	out, err := d.execAgentProbe(r.Context(), r.PathValue("aid"))
	if err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, out)
}

func (d *Daemon) handleAgentsPatch(w http.ResponseWriter, r *http.Request) {
	var req patchAgentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if err := d.execAgentPatch(r.PathValue("aid"), req); err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		case errors.Is(err, errBadOpKeyHex):
			http.Error(w, `{"error":"bad operational_private_key_hex"}`, http.StatusBadRequest)
		case errors.Is(err, errOpKeyMismatch):
			http.Error(w, `{"error":"operational key mismatch"}`, http.StatusForbidden)
		case errors.Is(err, errBadServiceTCP):
			http.Error(w, `{"error":"service_tcp cannot contain a path — use host:port or https://host:port"}`, http.StatusBadRequest)
		case errors.Is(err, errPersist):
			http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		default:
			http.Error(w, `{"error":"patch failed"}`, http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, map[string]string{"status": "updated"})
}

func (d *Daemon) handleAgentsPublish(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	seq, err := d.execAgentPublish(ctx, r.PathValue("aid"))
	if err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"error":"publish failed"}`, http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, map[string]any{"ok": true, "seq": seq})
}

func (d *Daemon) handleAgentsRecordsPost(w http.ResponseWriter, r *http.Request) {
	var req agentPublishRecordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := d.execAgentPublishRecord(ctx, r.PathValue("aid"), req); err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errBadRecType):
			http.Error(w, `{"error":"rec_type must be 0x02-0x0f"}`, http.StatusBadRequest)
		case errors.Is(err, errTTLRequired):
			http.Error(w, `{"error":"ttl required"}`, http.StatusBadRequest)
		case errors.Is(err, errBadPayloadB64):
			http.Error(w, `{"error":"invalid payload_base64"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		case errors.Is(err, errNoDelegation):
			http.Error(w, `{"error":"delegation required"}`, http.StatusBadRequest)
		default:
			http.Error(w, `{"error":"publish failed"}`, http.StatusBadGateway)
		}
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *Daemon) handleResolveRecords(w http.ResponseWriter, r *http.Request) {
	var recType uint8
	if s := r.URL.Query().Get("type"); s != "" {
		v, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			http.Error(w, `{"error":"bad type"}`, http.StatusBadRequest)
			return
		}
		recType = uint8(v)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	records, err := d.execResolveRecords(ctx, r.PathValue("aid"), recType)
	if err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"resolve failed"}`, http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"records": records})
}

type mailboxSendReq struct {
	Recipient  string `json:"recipient"`
	MsgType    uint8  `json:"msg_type"`
	BodyBase64 string `json:"body_base64"`
}

func (d *Daemon) handleAgentsMailboxSend(w http.ResponseWriter, r *http.Request) {
	var req mailboxSendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if req.Recipient == "" {
		http.Error(w, `{"error":"recipient required"}`, http.StatusBadRequest)
		return
	}
	body, err := base64.StdEncoding.DecodeString(req.BodyBase64)
	if err != nil {
		http.Error(w, `{"error":"invalid body_base64"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := d.execMailboxSend(ctx, r.PathValue("aid"), req.Recipient, req.MsgType, body); err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"error":"mailbox send failed"}`, http.StatusBadGateway)
		}
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *Daemon) handleAgentsMailboxPoll(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	msgs, err := d.execMailboxPoll(ctx, r.PathValue("aid"))
	if err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"error":"mailbox poll failed"}`, http.StatusBadGateway)
		}
		return
	}
	writeJSON(w, map[string]any{"messages": msgs})
}

func (d *Daemon) handleAgentsTopicsPost(w http.ResponseWriter, r *http.Request) {
	var req topicRegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := d.execTopicRegister(ctx, r.PathValue("aid"), req); err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errServicesRequired):
			http.Error(w, `{"error":"services required"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"error":"service register failed"}`, http.StatusBadGateway)
		}
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *Daemon) handleAgentsTopicsDelete(w http.ResponseWriter, r *http.Request) {
	topic := r.PathValue("service")
	if topic == "" {
		http.Error(w, `{"error":"service required"}`, http.StatusBadRequest)
		return
	}
	if err := d.execTopicUnregister(r.PathValue("aid"), topic); err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *Daemon) handleAgentsProfilePost(w http.ResponseWriter, r *http.Request) {
	var req agentProfileReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := d.execAgentSetProfile(ctx, r.PathValue("aid"), req); err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		}
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *Daemon) handleAgentsProfileDelete(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := d.execAgentDeleteProfile(ctx, r.PathValue("aid")); err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *Daemon) handleDiscover(w http.ResponseWriter, r *http.Request) {
	var req discoverReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	entries, err := d.execDiscover(ctx, req)
	if err != nil {
		if errors.Is(err, errServicesRequired) {
			http.Error(w, `{"error":"services required"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"discover failed"}`, http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"entries": entries})
}

func (d *Daemon) handleAgentsDelete(w http.ResponseWriter, r *http.Request) {
	if err := d.execAgentDelete(r.PathValue("aid")); err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errDeleteNode):
			http.Error(w, `{"error":"cannot delete node identity"}`, http.StatusBadRequest)
		default:
			http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *Daemon) handleResolve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	out, err := d.execResolve(ctx, r.PathValue("aid"))
	if err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"resolve failed"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, out)
}

type connectReq struct {
	LocalAID     string `json:"local_aid,omitempty"`
	DisableRelay *bool  `json:"disable_relay,omitempty"` // nil = use node default
}

func (d *Daemon) pickLocalAgent(localAID string) (a2al.Address, error) {
	if localAID != "" {
		return a2al.ParseAddress(localAID)
	}
	// Outbound QUIC uses the host default identity (node); see CLI spec §1.4.
	return d.nodeAddr, nil
}

func (d *Daemon) handleConnect(w http.ResponseWriter, r *http.Request) {
	var body connectReq
	_ = json.NewDecoder(r.Body).Decode(&body)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	tun, err := d.execConnect(ctx, r.PathValue("aid"), body)
	if err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errResolve):
			http.Error(w, `{"error":"resolve failed"}`, http.StatusNotFound)
		case errors.Is(err, errListen):
			http.Error(w, `{"error":"listen failed"}`, http.StatusInternalServerError)
		case errors.Is(err, host.ErrRelayRequired):
			writeJSONStatus(w, http.StatusPreconditionFailed, map[string]string{"error": "relay_required"})
		case errors.Is(err, errConnectQUIC):
			http.Error(w, `{"error":"quic connect failed"}`, http.StatusBadGateway)
		default:
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, map[string]string{"tunnel": tun})
}

// ── Tunnel handlers ────────────────────────────────────────────────────────

func (d *Daemon) handleTunnelOpen(w http.ResponseWriter, r *http.Request) {
	var req tunnelOpenReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	entry, err := d.execTunnelOpen(ctx, r.PathValue("aid"), req)
	if err != nil {
		switch {
		case errors.Is(err, errBadAID):
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad aid"})
		case errors.Is(err, errResolve):
			writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": "resolve failed"})
		case errors.Is(err, errListen):
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "listen failed"})
		case errors.Is(err, host.ErrRelayRequired):
			writeJSONStatus(w, http.StatusPreconditionFailed, map[string]string{"error": "relay_required"})
		case errors.Is(err, errConnectQUIC):
			writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": "quic connect failed"})
		default:
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSONStatus(w, http.StatusCreated, entry.status())
}

func (d *Daemon) handleTunnelClose(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !d.closeTunnel(id) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *Daemon) handleTunnelList(w http.ResponseWriter, r *http.Request) {
	_ = r
	writeJSON(w, map[string]any{"tunnels": d.tunnels.list()})
}

func (d *Daemon) handleTunnelGet(w http.ResponseWriter, r *http.Request) {
	_ = r
	e, ok := d.tunnels.get(r.PathValue("id"))
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	writeJSON(w, e.status())
}

// ── Demo mode handlers ─────────────────────────────────────────────────────

type demoStartReq struct {
	AID string `json:"aid"`
}

func (d *Daemon) handleDemoStart(w http.ResponseWriter, r *http.Request) {
	var req demoStartReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if _, err := a2al.ParseAddress(req.AID); err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}

	d.regMu.Lock()
	e := d.reg.Get(mustParseAddress(req.AID))
	if e == nil {
		d.regMu.Unlock()
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	port, err := d.demo.startForAgent(req.AID, d.sessionLookup)
	if err != nil {
		d.regMu.Unlock()
		http.Error(w, `{"error":"failed to start demo server"}`, http.StatusInternalServerError)
		return
	}
	tcpAddr := fmt.Sprintf("127.0.0.1:%d", port)
	e.ServiceTCP = tcpAddr
	e.DemoActive = true
	if err := d.reg.Put(e); err != nil {
		d.regMu.Unlock()
		d.demo.stopForAgent(req.AID)
		http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		return
	}
	d.regMu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_ = d.execTopicRegister(ctx, req.AID, topicRegisterReq{
		Services:  []string{"demo.echo"},
		Name:      "Demo Echo",
		Brief:     "A2AL demo capability — echoes back any request. Powered by Tangled Network.",
		Protocols: []string{"http"},
		TTL:       3600,
	})

	writeJSON(w, map[string]any{"port": port, "service_tcp": tcpAddr})
}

func (d *Daemon) handleDemoStop(w http.ResponseWriter, r *http.Request) {
	var req demoStartReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if req.AID == "" {
		http.Error(w, `{"error":"aid required"}`, http.StatusBadRequest)
		return
	}
	if _, err := a2al.ParseAddress(req.AID); err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}

	_ = d.execTopicUnregister(req.AID, "demo.echo")
	d.demo.stopForAgent(req.AID)

	d.regMu.Lock()
	if e := d.reg.Get(mustParseAddress(req.AID)); e != nil {
		e.ServiceTCP = ""
		e.DemoActive = false
		_ = d.reg.Put(e)
	}
	d.regMu.Unlock()

	writeJSON(w, map[string]string{"status": "stopped"})
}

// handleGetSession returns the caller metadata for an active gateway TCP bridge,
// keyed by the daemon-side TCP source port that the backend sees as RemoteAddr.Port.
//
// Backends call this immediately after Accept() to retrieve the verified caller AID
// without any modification to the byte stream.
func (d *Daemon) handleGetSession(w http.ResponseWriter, r *http.Request) {
	portStr := r.PathValue("port")
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		http.Error(w, `{"error":"invalid port"}`, http.StatusBadRequest)
		return
	}
	v, ok := d.sessions.Load(port)
	if !ok {
		http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, v)
}

// mustParseAddress parses an AID string, panicking only in unreachable cases
// (callers already validated the AID before calling this).
func mustParseAddress(s string) a2al.Address {
	addr, _ := a2al.ParseAddress(s)
	return addr
}

// handleAgentEvents streams SSE events for a specific agent AID.
// Accepts optional ?types=mailbox.received,... query param to filter event types.
func (d *Daemon) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	aidStr := r.PathValue("aid")
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}
	types := parseTypesParam(r.URL.Query().Get("types"))
	ch, cancel := d.bus.Subscribe(Filter{AID: aid, Types: types})
	defer cancel()

	if d.subMgr != nil {
		d.subMgr.Acquire(aid)
		defer d.subMgr.Release(aid)
	}

	serveSSE(w, r, ch)
}

// handleGlobalEvents streams SSE events for all agents (CLI-friendly, loopback-only in practice).
// Accepts optional ?types=... query param to filter event types.
func (d *Daemon) handleGlobalEvents(w http.ResponseWriter, r *http.Request) {
	types := parseTypesParam(r.URL.Query().Get("types"))
	ch, cancel := d.bus.Subscribe(Filter{Types: types})
	defer cancel()
	serveSSE(w, r, ch)
}

// serveSSE writes W3C SSE headers and streams events from ch until the client disconnects.
func serveSSE(w http.ResponseWriter, r *http.Request, ch <-chan Event) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}
	fl.Flush()

	enc := json.NewEncoder(w)
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, open := <-ch:
			if !open {
				return
			}
			data, err := sseEventJSON(evt)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data)
			_ = enc
			fl.Flush()
		}
	}
}

func sseEventJSON(evt Event) ([]byte, error) {
	payload := map[string]any{
		"type": evt.Type,
		"at":   evt.At.UTC().Format(time.RFC3339),
	}
	if evt.AID != (a2al.Address{}) {
		payload["aid"] = evt.AID.String()
	}
	if evt.Data != nil {
		payload["data"] = evt.Data
	}
	return json.Marshal(payload)
}

func (d *Daemon) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, d.upd.Status())
}

func (d *Daemon) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	go func() {
		// Use a background context: r.Context() is cancelled as soon as the
		// 202 response is sent (which is nearly instant), aborting all HTTP
		// calls inside TriggerNow before they complete.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		if err := d.upd.TriggerNow(ctx); err != nil {
			d.log.Warn("update apply: failed", "err", err)
		}
	}()
	resp := map[string]any{"message": "update check initiated"}
	if !d.persistentService {
		resp["warning"] = "daemon is not running as a managed service; if the new binary crashes immediately, the node will not self-recover — manual restart may be required"
	}
	writeJSONStatus(w, http.StatusAccepted, resp)
}

// parseTypesParam splits a comma-separated event types string.
// Returns nil (match all) for empty input.
func parseTypesParam(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
