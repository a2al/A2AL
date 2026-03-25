// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/cmd/a2ald/internal/registry"
	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/host"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"log/slog"
)

type daemon struct {
	dataDir  string
	cfgPath  string
	cfg      *config.Config
	log      *slog.Logger
	h        *host.Host
	reg      *registry.Registry
	nodeAddr a2al.Address
	regMu    sync.RWMutex // agent registry + Host.RegisterAgent consistency
	mcpOnce sync.Once
	mcpSrv  *mcp.Server

	// mailboxSeenMu guards mailboxSeen: per-agent set of already-returned message
	// fingerprints. Prevents duplicate delivery within a daemon session when the
	// same DHT records are fetched repeatedly before TTL expiry.
	mailboxSeenMu sync.Mutex
	mailboxSeen   map[string]map[string]struct{} // aidStr → set of msgKey
}

func (d *daemon) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.handleWebUIRoot)
	mux.HandleFunc("GET /health", d.handleHealth)
	mux.HandleFunc("GET /config", d.handleGetConfig)
	mux.HandleFunc("PATCH /config", d.handlePatchConfig)
	mux.HandleFunc("GET /config/schema", d.handleConfigSchema)
	mux.HandleFunc("POST /identity/generate", d.handleIdentityGenerate)
	mux.HandleFunc("POST /agents", d.handleAgentsPost)
	mux.HandleFunc("GET /agents", d.handleAgentsList)
	mux.HandleFunc("GET /agents/{aid}", d.handleAgentsGet)
	mux.HandleFunc("PATCH /agents/{aid}", d.handleAgentsPatch)
	mux.HandleFunc("POST /agents/{aid}/publish", d.handleAgentsPublish)
	mux.HandleFunc("POST /agents/{aid}/records", d.handleAgentsRecordsPost)
	mux.HandleFunc("POST /agents/{aid}/mailbox/send", d.handleAgentsMailboxSend)
	mux.HandleFunc("POST /agents/{aid}/mailbox/poll", d.handleAgentsMailboxPoll)
	mux.HandleFunc("POST /agents/{aid}/topics", d.handleAgentsTopicsPost)
	mux.HandleFunc("DELETE /agents/{aid}/topics/{topic...}", d.handleAgentsTopicsDelete)
	mux.HandleFunc("POST /discover", d.handleDiscover)
	mux.HandleFunc("DELETE /agents/{aid}", d.handleAgentsDelete)
	mux.HandleFunc("GET /resolve/{aid}/records", d.handleResolveRecords)
	mux.HandleFunc("POST /resolve/{aid}", d.handleResolve)
	mux.HandleFunc("POST /connect/{aid}", d.handleConnect)
	mux.Handle("/debug/", d.h.DebugHTTPHandler())
	mux.Handle("/mcp/", d.mcpHTTPHandler())
	return d.withMiddleware(mux)
}

func (d *daemon) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d.cfg.APIToken != "" {
			if r.Header.Get("Authorization") != "Bearer "+d.cfg.APIToken {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// no Content-Type requirement
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

func (d *daemon) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func (d *daemon) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
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
}

func (d *daemon) handlePatchConfig(w http.ResponseWriter, r *http.Request) {
	var req patchConfigReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	// Work on a copy so a validation failure cannot corrupt the live config.
	cfg := *d.cfg
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
	if err := cfg.Validate(); err != nil {
		http.Error(w, `{"error":"invalid config"}`, http.StatusBadRequest)
		return
	}
	if err := config.Save(d.cfgPath, cfg); err != nil {
		http.Error(w, `{"error":"save failed"}`, http.StatusInternalServerError)
		return
	}
	*d.cfg = cfg
	writeJSON(w, map[string]any{"ok": true, "restart_required": restart})
}

func (d *daemon) handleConfigSchema(w http.ResponseWriter, _ *http.Request) {
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
    "log_level": {"type": "string"}
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

func (d *daemon) handleIdentityGenerate(w http.ResponseWriter, _ *http.Request) {
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
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	network := "tcp"
	dialAddr := addr
	if ip := net.ParseIP(host); ip != nil {
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

func (d *daemon) handleAgentsPost(w http.ResponseWriter, r *http.Request) {
	var req registerAgentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	aid, err := d.execAgentRegister(req)
	if err != nil {
		if errors.Is(err, errBadDelegationHex) {
			http.Error(w, `{"error":"bad delegation_proof_hex"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errDelegationParse) {
			http.Error(w, `{"error":"delegation parse"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errBadOpKeyHex) {
			http.Error(w, `{"error":"bad operational_private_key_hex"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errDelegationVerify) {
			http.Error(w, `{"error":"delegation verify"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errAID) {
			http.Error(w, `{"error":"aid"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errNodeAsAgent) {
			http.Error(w, `{"error":"cannot register node identity as agent"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errServiceTCPRequired) {
			http.Error(w, `{"error":"service_tcp required"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errServiceTCPUnreachable) {
			http.Error(w, `{"error":"service_tcp unreachable"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errPersist) {
			http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
			return
		}
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]string{"aid": aid.String(), "status": "registered"})
}

func (d *daemon) handleAgentsList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"agents": d.execAgentsList()})
}

func (d *daemon) handleAgentsGet(w http.ResponseWriter, r *http.Request) {
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

func (d *daemon) handleAgentsPatch(w http.ResponseWriter, r *http.Request) {
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
		case errors.Is(err, errServiceTCPRequired):
			http.Error(w, `{"error":"service_tcp required"}`, http.StatusBadRequest)
		case errors.Is(err, errBadOpKeyHex):
			http.Error(w, `{"error":"bad operational_private_key_hex"}`, http.StatusBadRequest)
		case errors.Is(err, errOpKeyMismatch):
			http.Error(w, `{"error":"operational key mismatch"}`, http.StatusForbidden)
		case errors.Is(err, errServiceTCPUnreachable):
			http.Error(w, `{"error":"service_tcp unreachable"}`, http.StatusBadRequest)
		case errors.Is(err, errPersist):
			http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		default:
			http.Error(w, `{"error":"patch failed"}`, http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, map[string]string{"status": "updated"})
}

func (d *daemon) handleAgentsPublish(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	seq, err := d.execAgentPublish(ctx, r.PathValue("aid"))
	if err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errNotFound) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		if errors.Is(err, errServiceTCPUnreachable) {
			http.Error(w, `{"error":"service_tcp unreachable"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"publish failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "seq": seq})
}

func (d *daemon) handleAgentsRecordsPost(w http.ResponseWriter, r *http.Request) {
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

func (d *daemon) handleResolveRecords(w http.ResponseWriter, r *http.Request) {
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

func (d *daemon) handleAgentsMailboxSend(w http.ResponseWriter, r *http.Request) {
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
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errNotFound) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"mailbox send failed"}`, http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *daemon) handleAgentsMailboxPoll(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	msgs, err := d.execMailboxPoll(ctx, r.PathValue("aid"))
	if err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errNotFound) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"mailbox poll failed"}`, http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"messages": msgs})
}

func (d *daemon) handleAgentsTopicsPost(w http.ResponseWriter, r *http.Request) {
	var req topicRegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := d.execTopicRegister(ctx, r.PathValue("aid"), req); err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errTopicsRequired) {
			http.Error(w, `{"error":"topics required"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errNotFound) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"topic register failed"}`, http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *daemon) handleAgentsTopicsDelete(w http.ResponseWriter, r *http.Request) {
	topic := r.PathValue("topic")
	if topic == "" {
		http.Error(w, `{"error":"topic required"}`, http.StatusBadRequest)
		return
	}
	if err := d.execTopicUnregister(r.PathValue("aid"), topic); err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errNotFound) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *daemon) handleDiscover(w http.ResponseWriter, r *http.Request) {
	var req discoverReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	entries, err := d.execDiscover(ctx, req)
	if err != nil {
		if errors.Is(err, errTopicsRequired) {
			http.Error(w, `{"error":"topics required"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"discover failed"}`, http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"entries": entries})
}

func (d *daemon) handleAgentsDelete(w http.ResponseWriter, r *http.Request) {
	if err := d.execAgentDelete(r.PathValue("aid")); err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errDeleteNode) {
			http.Error(w, `{"error":"cannot delete node identity"}`, http.StatusBadRequest)
			return
		}
		http.Error(w, `{"error":"persist"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (d *daemon) handleResolve(w http.ResponseWriter, r *http.Request) {
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

func (d *daemon) pickLocalAgent(body connectReq) (a2al.Address, error) {
	if body.LocalAID != "" {
		return a2al.ParseAddress(body.LocalAID)
	}
	d.regMu.RLock()
	list := d.reg.List()
	d.regMu.RUnlock()
	if len(list) == 1 {
		return list[0].AID, nil
	}
	if len(list) == 0 {
		return a2al.Address{}, errNoLocalAgent
	}
	return a2al.Address{}, errAmbiguousLocal
}

var errNoLocalAgent = errors.New("no registered agents")
var errAmbiguousLocal = errors.New("local_aid required when multiple agents")

func (d *daemon) handleConnect(w http.ResponseWriter, r *http.Request) {
	var body connectReq
	_ = json.NewDecoder(r.Body).Decode(&body)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	tun, err := d.execConnect(ctx, r.PathValue("aid"), body)
	if err != nil {
		if errors.Is(err, errBadAID) {
			http.Error(w, `{"error":"bad aid"}`, http.StatusBadRequest)
			return
		}
		if errors.Is(err, errNoLocalAgent) || errors.Is(err, errAmbiguousLocal) {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, errResolve) {
			http.Error(w, `{"error":"resolve failed"}`, http.StatusNotFound)
			return
		}
		if errors.Is(err, errListen) {
			http.Error(w, `{"error":"listen failed"}`, http.StatusInternalServerError)
			return
		}
		if errors.Is(err, errConnectQUIC) {
			http.Error(w, `{"error":"quic connect failed"}`, http.StatusBadGateway)
			return
		}
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]string{"tunnel": tun})
}
