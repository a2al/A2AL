// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/config"
)

func (d *Daemon) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", d.handleHealth)
	mux.HandleFunc("GET /status", d.handleStatus)
	mux.HandleFunc("GET /config", d.handleGetConfig)
	mux.HandleFunc("PATCH /config", d.handlePatchConfig)
	mux.HandleFunc("GET /config/schema", d.handleConfigSchema)
	mux.HandleFunc("POST /identity/generate", d.handleIdentityGenerate)
	mux.HandleFunc("POST /agents", d.handleAgentsPost)
	mux.HandleFunc("POST /agents/generate", d.handleAgentsGenerate)
	mux.HandleFunc("POST /agents/ethereum/delegation-message", d.handleEthDelegationMessage)
	mux.HandleFunc("POST /agents/ethereum/register", d.handleEthRegister)
	mux.HandleFunc("POST /agents/ethereum/proof", d.handleEthProof)
	mux.HandleFunc("GET /agents", d.handleAgentsList)
	mux.HandleFunc("GET /agents/{aid}", d.handleAgentsGet)
	mux.HandleFunc("PATCH /agents/{aid}", d.withAgentMiddleware(d.handleAgentsPatch))
	mux.HandleFunc("POST /agents/{aid}/heartbeat", d.withAgentMiddleware(d.handleAgentHeartbeat))
	mux.HandleFunc("POST /agents/{aid}/publish", d.withAgentMiddleware(d.handleAgentsPublish))
	mux.HandleFunc("POST /agents/{aid}/records", d.withAgentMiddleware(d.handleAgentsRecordsPost))
	mux.HandleFunc("POST /agents/{aid}/mailbox/send", d.withAgentMiddleware(d.handleAgentsMailboxSend))
	mux.HandleFunc("POST /agents/{aid}/mailbox/poll", d.withAgentMiddleware(d.handleAgentsMailboxPoll))
	mux.HandleFunc("POST /agents/{aid}/services", d.withAgentMiddleware(d.handleAgentsTopicsPost))
	mux.HandleFunc("DELETE /agents/{aid}/services/{service...}", d.withAgentMiddleware(d.handleAgentsTopicsDelete))
	mux.HandleFunc("POST /discover", d.handleDiscover)
	mux.HandleFunc("DELETE /agents/{aid}", d.withAgentMiddleware(d.handleAgentsDelete))
	mux.HandleFunc("GET /resolve/{aid}/records", d.handleResolveRecords)
	mux.HandleFunc("POST /resolve/{aid}", d.handleResolve)
	mux.HandleFunc("POST /connect/{aid}", d.handleConnect)
	mux.Handle("/debug/", d.h.DebugHTTPHandler())
	mux.Handle("/mcp/", d.mcpHTTPHandler())
	registerWebUIRoutes(mux)
	return d.withMiddleware(mux)
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
		if d.cfg.APIToken != "" {
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
	ListenAddr       *string   `json:"listen_addr,omitempty"`
	QUICListenAddr   *string   `json:"quic_listen_addr,omitempty"`
	Bootstrap        *[]string `json:"bootstrap,omitempty"`
	DisableUPnP      *bool     `json:"disable_upnp,omitempty"`
	FallbackHost     *string   `json:"fallback_host,omitempty"`
	MinObservedPeers *int      `json:"min_observed_peers,omitempty"`
	APIAddr          *string   `json:"api_addr,omitempty"`
	APIToken         *string   `json:"api_token,omitempty"`
	KeyDir           *string   `json:"key_dir,omitempty"`
	LogFormat        *string   `json:"log_format,omitempty"`
	LogLevel         *string   `json:"log_level,omitempty"`
	AutoPublish      *bool     `json:"auto_publish,omitempty"`
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
    "auto_publish": {"type": "boolean", "description": "Publish node AID to DHT on a schedule (default true)"}
  }
}`
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(schema))
}

type identityGenResp struct {
	MasterPrivateKeyHex      string `json:"master_private_key_hex"`
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	AID                      string `json:"aid"`
	Warning                  string `json:"warning"`
}

func (d *Daemon) handleIdentityGenerate(w http.ResponseWriter, _ *http.Request) {
	out, err := d.execIdentityGenerate()
	if err != nil {
		http.Error(w, `{"error":"keygen"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

type registerAgentReq struct {
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	ServiceTCP               string `json:"service_tcp"`
}

type patchAgentReq struct {
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	ServiceTCP               string `json:"service_tcp"`
}

func probeTCP(addr string, d time.Duration) bool {
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

func (d *Daemon) handleAgentsGenerate(w http.ResponseWriter, r *http.Request) {
	var req agentsGenerateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if req.Chain != "" && req.Chain != "ethereum" {
		http.Error(w, `{"error":"unsupported chain"}`, http.StatusBadRequest)
		return
	}
	out, err := d.execEthereumIdentityGenerate()
	if err != nil {
		http.Error(w, `{"error":"generate failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
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
	LocalAID string `json:"local_aid,omitempty"`
}

func (d *Daemon) pickLocalAgent(body connectReq) (a2al.Address, error) {
	if body.LocalAID != "" {
		return a2al.ParseAddress(body.LocalAID)
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
		case errors.Is(err, errConnectQUIC):
			http.Error(w, `{"error":"quic connect failed"}`, http.StatusBadGateway)
		default:
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, map[string]string{"tunnel": tun})
}
