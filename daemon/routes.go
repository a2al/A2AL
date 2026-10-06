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
	"github.com/a2al/a2al/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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
	mux.HandleFunc("GET /agents/{aid}/groups", d.handleGroupInspectList)
	mux.HandleFunc("GET /agents/{aid}/groups/{group_id}", d.handleGroupInspectHead)
	mux.HandleFunc("GET /agents/{aid}/groups/{group_id}/entries", d.handleGroupInspectEntries)
	mux.HandleFunc("POST /agents/{aid}/groups/{group_id}/append", d.withAgentMiddleware(d.handleGroupAppend))
	mux.HandleFunc("POST /agents/{aid}/groups/{group_id}/leave", d.withAgentMiddleware(d.handleGroupLeave))
	mux.HandleFunc("GET /agents/{aid}/chat/contacts", d.handleChatInspectContacts)
	mux.HandleFunc("GET /agents/{aid}/chat/peers/{peer}", d.handleChatInspectLog)
	mux.HandleFunc("POST /agents/{aid}/chat/request", d.withAgentMiddleware(d.handleChatRequest))
	mux.HandleFunc("POST /agents/{aid}/chat/accept", d.withAgentMiddleware(d.handleChatAccept))
	mux.HandleFunc("POST /agents/{aid}/chat/refuse", d.withAgentMiddleware(d.handleChatRefuse))
	mux.HandleFunc("POST /agents/{aid}/chat/remove", d.withAgentMiddleware(d.handleChatRemove))
	mux.HandleFunc("POST /agents/{aid}/chat/block", d.withAgentMiddleware(d.handleChatBlock))
	mux.HandleFunc("POST /agents/{aid}/chat/send", d.withAgentMiddleware(d.handleChatSend))
	mux.HandleFunc("POST /agents/{aid}/chat/mark-read", d.withAgentMiddleware(d.handleChatMarkRead))
	mux.HandleFunc("GET /agents/{aid}/probe", d.handleAgentsProbe)
	mux.HandleFunc("PATCH /agents/{aid}", d.withAgentMiddleware(d.handleAgentsPatch))
	mux.HandleFunc("POST /agents/{aid}/heartbeat", d.withAgentMiddleware(d.handleAgentHeartbeat))
	mux.HandleFunc("POST /agents/{aid}/publish", d.withAgentMiddleware(d.handleAgentsPublish))
	mux.HandleFunc("POST /agents/{aid}/records", d.withAgentMiddleware(d.handleAgentsRecordsPost))
	mux.HandleFunc("POST /agents/{aid}/mailbox/send", d.withAgentMiddleware(d.handleAgentsMailboxSend))
	mux.HandleFunc("GET /agents/{aid}/mailbox", d.handleAgentsMailboxList)
	mux.HandleFunc("POST /agents/{aid}/mailbox/poll", d.withAgentMiddleware(d.handleAgentsMailboxPoll))
	mux.HandleFunc("POST /agents/{aid}/services", d.withAgentMiddleware(d.handleAgentsTopicsPost))
	mux.HandleFunc("DELETE /agents/{aid}/services/{service...}", d.withAgentMiddleware(d.handleAgentsTopicsDelete))
	mux.HandleFunc("POST /agents/{aid}/profile", d.withAgentMiddleware(d.handleAgentsProfilePost))
	mux.HandleFunc("DELETE /agents/{aid}/profile", d.withAgentMiddleware(d.handleAgentsProfileDelete))
	mux.HandleFunc("GET /agents/{aid}/acl", d.withAgentMiddleware(d.handleACLGet))
	mux.HandleFunc("PATCH /agents/{aid}/acl", d.withAgentMiddleware(d.handleACLPatch))
	mux.HandleFunc("POST /agents/{aid}/acl/allow", d.withAgentMiddleware(d.handleACLAllowPost))
	mux.HandleFunc("POST /agents/{aid}/acl/deny", d.withAgentMiddleware(d.handleACLDenyPost))
	mux.HandleFunc("DELETE /agents/{aid}/acl/allow/{id}", d.withAgentMiddleware(d.handleACLAllowDelete))
	mux.HandleFunc("DELETE /agents/{aid}/acl/deny/{id}", d.withAgentMiddleware(d.handleACLDenyDelete))
	mux.HandleFunc("POST /discover", d.handleDiscover)
	mux.HandleFunc("DELETE /agents/{aid}", d.withAgentMiddleware(d.handleAgentsDelete))
	mux.HandleFunc("GET /resolve/{aid}/records", d.handleResolveRecords)
	mux.HandleFunc("POST /resolve/{aid}", d.handleResolve)
	mux.HandleFunc("POST /connect/{aid}", d.handleConnect)
	mux.HandleFunc("POST /fetch/{aid}", d.handleFetch)
	mux.HandleFunc("POST /tunnel/{aid}", d.handleTunnelOpen)
	mux.HandleFunc("DELETE /tunnel/{id}", d.handleTunnelClose)
	mux.HandleFunc("POST /tunnel/{id}/reset", d.handleTunnelReset)
	mux.HandleFunc("GET /tunnel", d.handleTunnelList)
	mux.HandleFunc("GET /tunnel/{id}", d.handleTunnelGet)
	mux.Handle("/debug/", d.h.DebugHTTPHandler())
	mux.Handle("/mcp/", d.mcpHTTPHandler())
	mux.HandleFunc("POST /mcp/call", d.handleMCPCall)
	mux.HandleFunc("POST /demo/start", d.handleDemoStart)
	mux.HandleFunc("POST /demo/stop", d.handleDemoStop)
	mux.HandleFunc("GET /sessions/{port}", d.handleGetSession)
	mux.HandleFunc("GET /agents/{aid}/events", d.withAgentMiddleware(d.handleAgentEvents))
	mux.HandleFunc("POST /agents/{aid}/cas", d.withAgentMiddleware(d.handleAgentCASUpload))
	mux.HandleFunc("GET /agents/{aid}/cas/{object_id}", d.withAgentMiddleware(d.handleAgentCASGet))
	mux.HandleFunc("GET /events", d.handleGlobalEvents)
	mux.HandleFunc("GET /update/status", d.handleUpdateStatus)
	mux.HandleFunc("POST /update/apply", d.handleUpdateApply)
	mux.HandleFunc("GET /node/remote-admin", d.handleRemoteAdminGet)
	mux.HandleFunc("PATCH /node/remote-admin", d.handleRemoteAdminPatch)
	mux.HandleFunc("POST /node/remote-admin/allow", d.handleRemoteAdminAllowPost)
	mux.HandleFunc("POST /node/remote-admin/deny", d.handleRemoteAdminDenyPost)
	mux.HandleFunc("DELETE /node/remote-admin/allow/{id}", d.handleRemoteAdminAllowDelete)
	mux.HandleFunc("DELETE /node/remote-admin/deny/{id}", d.handleRemoteAdminDenyDelete)
	mux.HandleFunc("GET /node/address-book", d.handleAddressBookGet)
	mux.HandleFunc("PUT /node/address-book", d.handleAddressBookPut)

	// Mount Web UI assets and the AID proxy outside withMiddleware:
	// - Web UI HTML/JS/CSS contain no sensitive data; auth happens at the API call level.
	// - AID proxy must accept arbitrary Content-Types and requests without an API token.
	outer := http.NewServeMux()
	registerWebUIRoutes(outer)
	outer.Handle("/aid/", d.newAIDProxy())
	outer.Handle("/", d.withMiddleware(mux))
	return outer
}

// isDataPlaneRoute reports whether r targets a local endpoint that carries raw
// bytes rather than control-plane JSON. Kept as an explicit allowlist so that
// exempting a route from the body cap is a deliberate act, visible next to the
// guards it skips.
//
// Currently the only member is object upload: POST /agents/{aid}/cas.
func isDataPlaneRoute(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	p := strings.TrimSuffix(r.URL.Path, "/")
	return strings.HasPrefix(p, "/agents/") && strings.HasSuffix(p, "/cas")
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
// individual handler functions. Filling it also gates what these routes may
// disclose about an identity — including the pending-mail count on
// GET /agents/{aid} — because the whole resource becomes unreachable to a
// caller not authorised for that AID.
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
		// The body cap and the JSON content-type rule below are control-plane
		// guards: they keep a JSON endpoint from being used to make the daemon
		// buffer arbitrary memory. Data-plane routes carry raw object bytes and
		// stream them straight to disk, so neither guard applies — an object's
		// size is bounded by the sandbox's disk, not by a limit meant for
		// request JSON. Auth and the Host check stay on every route: there is
		// still exactly one place that decides who may call the local API.
		streaming := isDataPlaneRoute(r)
		if !streaming {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}

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
		switch {
		case streaming:
		case r.Method == http.MethodGet, r.Method == http.MethodHead, r.Method == http.MethodOptions:
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
	out := d.execStatus()
	addPendingHitch(out, d.pendingSnapshot(context.Background(), nil))
	writeJSON(w, out)
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
	ListenAddr       *string                    `json:"listen_addr,omitempty"`
	QUICListenAddr   *string                    `json:"quic_listen_addr,omitempty"`
	Bootstrap        *[]string                  `json:"bootstrap,omitempty"`
	DisableUPnP      *bool                      `json:"disable_upnp,omitempty"`
	FallbackHost     *string                    `json:"fallback_host,omitempty"`
	MinObservedPeers *int                       `json:"min_observed_peers,omitempty"`
	APIAddr          *string                    `json:"api_addr,omitempty"`
	APIToken         *string                    `json:"api_token,omitempty"`
	KeyDir           *string                    `json:"key_dir,omitempty"`
	LogFormat        *string                    `json:"log_format,omitempty"`
	LogLevel         *string                    `json:"log_level,omitempty"`
	AutoPublish      *bool                      `json:"auto_publish,omitempty"`
	TURNServers      *[]config.TURNServerConfig `json:"turn_servers,omitempty"`
	DisableRelay     *bool                      `json:"disable_relay,omitempty"`
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
	out := map[string]any{"agents": d.execAgentsList()}
	addPendingHitch(out, d.pendingSnapshot(context.Background(), nil))
	writeJSON(w, out)
}

// addPendingHitch puts a pending-mail snapshot on a response, leaving any field
// the handler already produced untouched.
//
// Scope is the caller's choice, and it follows the endpoint: the overview
// endpoints pass every visible identity, GET /agents/{aid} passes only the
// identity it is about. The rendered shape is the same either way, so a client
// parses "pending" identically wherever it appears.
func addPendingHitch(out map[string]any, pending map[string]any) {
	if len(pending) == 0 {
		return
	}
	if _, taken := out["pending"]; taken {
		return
	}
	out["pending"] = pending
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
	if aid, perr := a2al.ParseAddress(r.PathValue("aid")); perr == nil {
		addPendingHitch(out, d.pendingFor(aid))
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
	msgID, err := d.execMailboxSend(ctx, r.PathValue("aid"), req.Recipient, req.MsgType, body)
	if err != nil {
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
	writeJSON(w, map[string]any{"ok": true, "message_id": msgID})
}

func (d *Daemon) handleAgentsMailboxList(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	msgs, err := d.execMailboxList(ctx, r.PathValue("aid"))
	if err != nil {
		switch {
		case errors.Is(err, errBadAID):
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			http.Error(w, `{"error":"mailbox list failed"}`, http.StatusBadGateway)
		}
		return
	}
	writeJSON(w, map[string]any{"messages": msgs})
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
	AccessToken  string `json:"access_token,omitempty"`
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
	res, err := d.execConnect(ctx, r.PathValue("aid"), body)
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
		case errors.Is(err, protocol.ErrNoInbound):
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "no inbound"})
		case errors.Is(err, protocol.ErrInboundUnreachable):
			writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": "inbound unreachable"})
		default:
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, res)
}

// ── Tunnel handlers ────────────────────────────────────────────────────────

func (d *Daemon) handleTunnelOpen(w http.ResponseWriter, r *http.Request) {
	var req tunnelOpenReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	entry, _, err := d.execTunnelOpen(ctx, r.PathValue("aid"), req)
	if err != nil {
		switch {
		case errors.Is(err, errBadAID):
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad aid"})
		case errors.Is(err, errResolve):
			writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": "resolve failed"})
		case errors.Is(err, errBadLocalPort):
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad local_port"})
		case errors.Is(err, errPortInUse):
			writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "port_in_use"})
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

// handleTunnelReset forcibly invalidates the QUIC connection backing the tunnel
// identified by {id}. The tunnel will self-close once its QUIC connection dies;
// reopen it with POST /tunnel/{aid} to establish a fresh connection.
func (d *Daemon) handleTunnelReset(w http.ResponseWriter, r *http.Request) {
	e, ok := d.tunnels.get(r.PathValue("id"))
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "tunnel not found"})
		return
	}
	d.connPool.invalidate(e.localAID, e.remoteAID, e.noRelay)
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
	writeJSON(w, v.(*sessionInfo).snapshot())
}

// mustParseAddress parses an AID string, panicking only in unreachable cases
// (callers already validated the AID before calling this).
func mustParseAddress(s string) a2al.Address {
	addr, _ := a2al.ParseAddress(s)
	return addr
}

// handleAgentEvents streams SSE events for a specific agent AID.
//
// Query params:
//   - types=mailbox.received,...  — filter by EventLog type (empty = all)
//   - last_event_id=N             — replay missed events with seq > N before live stream
//
// W3C Last-Event-ID header is also honoured on reconnect (browser EventSource
// sends it automatically). Logged frames carry id: <seq>; the optional first
// event: pending envelope and keepalive comments do not, so they never move
// the resume cursor. types= filters the log only — pending still goes out.
func (d *Daemon) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	aidStr := r.PathValue("aid")
	aid, err := a2al.ParseAddress(aidStr)
	if err != nil {
		http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
		return
	}
	types := parseTypesParam(r.URL.Query().Get("types"))
	if _, ok := r.URL.Query()["after_seq"]; ok {
		http.Error(w, `{"error":"SSE replay cursor is last_event_id (and Last-Event-ID); after_seq belongs to events_poll"}`, http.StatusBadRequest)
		return
	}

	// Determine the replay cursor: prefer Last-Event-ID (browser reconnect),
	// then ?last_event_id=, then 0 (stream from live only).
	afterSeq := parseAfterSeq(r.Header.Get("Last-Event-ID"))
	if afterSeq == 0 {
		afterSeq = parseAfterSeq(r.URL.Query().Get("last_event_id"))
	}

	// SSE live stream is driven by EventLog.Watch, not EventBus, to eliminate
	// the race between the EventBus→EventLog mirror goroutine and the SSE
	// subscriber receiving the same event before it has been written to the log.
	// The types filter is applied server-side when pulling from EventLog.Since.
	if d.subMgr != nil {
		d.subMgr.Acquire(aid)
		defer d.subMgr.Release(aid)
	}

	serveSSEWithReplay(w, r, aid, afterSeq, types, d.evtLog, d.pendingFor(aid))
}

// handleGlobalEvents streams SSE events for all agents (CLI-friendly, loopback-only in practice).
// Accepts optional ?types=... to filter EventLog types. An event: pending
// envelope may precede the live stream (same shape as GET /status); it is not
// an EventLog entry and is not filtered by types=.
func (d *Daemon) handleGlobalEvents(w http.ResponseWriter, r *http.Request) {
	types := parseTypesParam(r.URL.Query().Get("types"))
	ch, cancel := d.bus.Subscribe(Filter{Types: types})
	defer cancel()
	serveSSE(w, r, ch, d.pendingSnapshot(r.Context(), nil))
}

// parseAfterSeq parses a cursor string into a uint64; returns 0 on error.
func parseAfterSeq(s string) uint64 {
	if s == "" {
		return 0
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

// sseLiveKeepaliveInterval is the interval at which a comment heartbeat is sent
// on idle SSE connections. Keeps proxies alive and lets clients self-detect dead
// connections without waiting for a TCP timeout.
const sseLiveKeepaliveInterval = 15 * time.Second

// serveSSEWithReplay writes W3C SSE headers, optionally an event: pending
// envelope (local inventory, no id:), replays buffered events with seq >
// afterSeq, then live-streams from EventLog.Watch so logged frames carry
// id: <seq>.
//
// Using EventLog.Watch instead of an EventBus channel eliminates the race where
// the SSE goroutine receives a bus event before the mirror goroutine has written
// it to the log (making seq unavailable). The mirror goroutine writes to the log
// first; Watch is notified after the append completes.
func serveSSEWithReplay(w http.ResponseWriter, r *http.Request, aid a2al.Address, afterSeq uint64, types []string, evtLog *EventLog, pending map[string]any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}

	ctx := r.Context()

	// W3C SSE: instruct clients to reconnect after 3 s on disconnect.
	fmt.Fprintf(w, "retry: 3000\n\n")
	fl.Flush()

	// Register a watcher BEFORE replay to avoid missing events that arrive
	// between the replay scan and the live-loop start.
	watchCh, unwatch := evtLog.Watch(aid)
	defer unwatch()

	// Hitch the local inventory onto this subscribe. Envelope, not an EventLog
	// entry: no id:, so Last-Event-ID is unchanged and reconnect still sees
	// the current count until mailbox_poll consumes it.
	if writePendingSSE(w, pending) {
		fl.Flush()
	}

	// Replay buffered events (seq > afterSeq). Omit last_event_id (afterSeq=0)
	// means live only: start the cursor at the current head so the first Watch
	// notification cannot Since(0) and dump the buffer.
	lastSentSeq := afterSeq
	if afterSeq == 0 {
		lastSentSeq = evtLog.LastSeq(aid)
	} else {
		missed, oldest, truncated := evtLog.Since(aid, afterSeq)
		if truncated {
			// Cursor is too old; client should do a full resync.
			fmt.Fprintf(w, "event: log.truncated\ndata: {\"oldest_seq\":%d}\n\n", oldest)
			fl.Flush()
		}
		for _, le := range missed {
			if matchesTypes(le.Type, types) {
				writeLoggedEventSSE(w, le)
			}
			lastSentSeq = le.Seq
		}
		fl.Flush()
	}

	// Live stream driven by EventLog.Watch.
	keepalive := time.NewTicker(sseLiveKeepaliveInterval)
	defer keepalive.Stop()

	sendNew := func() {
		events, _, _ := evtLog.Since(aid, lastSentSeq)
		for _, le := range events {
			if matchesTypes(le.Type, types) {
				writeLoggedEventSSE(w, le)
			}
			lastSentSeq = le.Seq
		}
		fl.Flush()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-watchCh:
			sendNew()
		case <-keepalive.C:
			// W3C SSE comment — passes through proxies without triggering event handlers.
			fmt.Fprintf(w, ": keepalive\n\n")
			fl.Flush()
		}
	}
}

// matchesTypes reports whether evtType matches the filter list.
// An empty filter list means "all types".
func matchesTypes(evtType string, types []string) bool {
	if len(types) == 0 {
		return true
	}
	for _, t := range types {
		if t == evtType {
			return true
		}
	}
	return false
}

// writePendingSSE writes the local pending snapshot as an SSE envelope frame.
// No id: — this is not a log event and must not move Last-Event-ID.
// Returns whether a frame was written.
func writePendingSSE(w http.ResponseWriter, pending map[string]any) bool {
	if len(pending) == 0 {
		return false
	}
	payload, err := json.Marshal(pending)
	if err != nil {
		return false
	}
	fmt.Fprintf(w, "event: pending\ndata: %s\n\n", payload)
	return true
}

// writeLoggedEventSSE writes a single replayed LoggedEvent as an SSE frame with id:.
func writeLoggedEventSSE(w http.ResponseWriter, le LoggedEvent) {
	payload, err := json.Marshal(map[string]any{
		"type": le.Type,
		"at":   time.UnixMilli(le.Ts).UTC().Format(time.RFC3339), // RFC 3339: W3C SSE convention
		"data": le.Data,
	})
	if err != nil {
		return
	}
	fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", le.Seq, le.Type, payload)
}

// serveSSE writes W3C SSE headers, optionally an event: pending envelope
// (no id:), then streams live bus events from ch until the client disconnects.
func serveSSE(w http.ResponseWriter, r *http.Request, ch <-chan Event, pending map[string]any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}
	writePendingSSE(w, pending)
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
		"at":   evt.At.UTC().Format(time.RFC3339), // RFC 3339: W3C SSE / CloudEvents convention
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

// mcpLocalSession returns (or lazily creates) a persistent in-process
// ClientSession backed by the daemon's own MCP server. Used by handleMCPCall.
func (d *Daemon) mcpLocalSession() *mcp.ClientSession {
	d.mcpLocalOnce.Do(func() {
		ct, st := mcp.NewInMemoryTransports()
		srv := d.mcpInstance()
		// Run server side in background; it lives for the process lifetime.
		go func() { _ = srv.Run(context.Background(), st) }()
		c := mcp.NewClient(&mcp.Implementation{Name: "a2al-cli-bridge", Version: "0"}, nil)
		cs, err := c.Connect(context.Background(), ct)
		if err != nil {
			d.log.Error("mcp local session init failed", "err", err)
			return
		}
		d.mcpLocalSess = cs
	})
	return d.mcpLocalSess
}

// handleMCPCall handles POST /mcp/call — a thin REST shim that lets the CLI
// invoke any registered MCP tool without speaking the MCP protocol directly.
//
// Request body:  {"tool": "<name>", "args": {…}}
// Response 200:  the tool's structured result as JSON
// Response 422:  {"error": "<tool error text>"} when IsError is true
func (d *Daemon) handleMCPCall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tool string         `json:"tool"`
		Args map[string]any `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	if req.Tool == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "tool name is required"})
		return
	}
	cs := d.mcpLocalSession()
	if cs == nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "mcp local session not available"})
		return
	}
	result, err := cs.CallTool(r.Context(), &mcp.CallToolParams{
		Name:      req.Tool,
		Arguments: req.Args,
	})
	if err != nil {
		// Protocol-level error (tool not found, etc.)
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if result.IsError {
		// Tool returned a business-logic error; extract text from Content[].
		msg := "tool returned an error"
		for _, c := range result.Content {
			if b, jerr := c.MarshalJSON(); jerr == nil {
				var tc struct {
					Text string `json:"text"`
				}
				if jerr2 := json.Unmarshal(b, &tc); jerr2 == nil && tc.Text != "" {
					msg = tc.Text
					break
				}
			}
		}
		writeJSONStatus(w, http.StatusUnprocessableEntity, map[string]string{"error": msg})
		return
	}
	writeJSON(w, result.StructuredContent)
}
