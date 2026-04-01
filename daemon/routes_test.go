// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/nodeks"
	"github.com/a2al/a2al/internal/registry"
	"log/slog"
)

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	dir := t.TempDir()
	ks, err := nodeks.LoadOrGenerate(filepath.Join(dir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := host.New(host.Config{
		KeyStore:         ks,
		ListenAddr:       "127.0.0.1:0",
		QUICListenAddr:   "127.0.0.1:0",
		MinObservedPeers: 1,
		FallbackHost:     "127.0.0.1",
		DisableUPnP:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	reg, err := registry.Load(filepath.Join(dir, "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	return &Daemon{
		dataDir:          dir,
		cfgPath:          filepath.Join(dir, "config.toml"),
		cfg:              &cfg,
		log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		h:                h,
		reg:              reg,
		nodeAddr:         ks.Address(),
		agentLastPublish: make(map[a2al.Address]time.Time),
		heartbeatAt:      make(map[a2al.Address]time.Time),
		mailboxSeen:      make(map[string]map[string]time.Time),
	}
}

func TestAPI_health(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("%#v", body)
	}
}

func TestAPI_getConfig_masksToken(t *testing.T) {
	d := newTestDaemon(t)
	d.cfg.APIToken = "secret"
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/config", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var c config.Config
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		t.Fatal(err)
	}
	if c.APIToken != "***" {
		t.Fatalf("token not masked: %q", c.APIToken)
	}
}

func TestAPI_middleware_token(t *testing.T) {
	d := newTestDaemon(t)
	d.cfg.APIToken = "tok"
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without bearer: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with bearer: %d", resp.StatusCode)
	}
}

func TestAPI_contentTypeJSON(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/identity/generate", nil)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("POST without json CT: %d", resp.StatusCode)
	}
}

func TestAPI_identityGenerate(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/identity/generate", nil)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out identityGenResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.AID == "" || out.MasterPrivateKeyHex == "" || out.DelegationProofHex == "" {
		t.Fatalf("incomplete response: %+v", out)
	}
}

func TestAPI_mailboxPoll_notRegistered(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/agents/"+d.nodeAddr.String()+"/mailbox/poll", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestAPI_agentRecords_notRegistered(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	body := bytes.NewBufferString(`{"rec_type":2,"payload_base64":"oA==","ttl":3600}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/agents/"+d.nodeAddr.String()+"/records", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestAPI_resolveRecords_empty(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/resolve/"+d.nodeAddr.String()+"/records", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var out struct {
		Records []any `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Records == nil {
		t.Fatal("want non-nil records slice")
	}
}

func TestAPI_register_emptyServiceTCP(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	client := &http.Client{Timeout: 30 * time.Second}

	genReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/identity/generate", nil)
	genReq.Header.Set("Content-Type", "application/json")
	genResp, err := client.Do(genReq)
	if err != nil {
		t.Fatal(err)
	}
	defer genResp.Body.Close()
	if genResp.StatusCode != http.StatusOK {
		t.Fatalf("generate: %d", genResp.StatusCode)
	}
	var gen identityGenResp
	if err := json.NewDecoder(genResp.Body).Decode(&gen); err != nil {
		t.Fatal(err)
	}

	regBody := map[string]string{
		"operational_private_key_hex": gen.OperationalPrivateKeyHex,
		"delegation_proof_hex":        gen.DelegationProofHex,
		"service_tcp":                 "",
	}
	b, _ := json.Marshal(regBody)
	regReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/agents", bytes.NewReader(b))
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := client.Do(regReq)
	if err != nil {
		t.Fatal(err)
	}
	defer regResp.Body.Close()
	if regResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(regResp.Body)
		t.Fatalf("register: %d %s", regResp.StatusCode, body)
	}

	listResp, err := client.Get(srv.URL + "/agents")
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	var list struct {
		Agents []map[string]any `json:"agents"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Agents) != 1 {
		t.Fatalf("agents len %d", len(list.Agents))
	}
	ag := list.Agents[0]
	if ag["service_tcp"] != "" {
		t.Fatalf("service_tcp %#v", ag["service_tcp"])
	}
	if _, ok := ag["service_tcp_ok"]; ok && ag["service_tcp_ok"] != nil {
		t.Fatalf("service_tcp_ok should be null when unset, got %#v", ag["service_tcp_ok"])
	}
}

func TestAPI_touchHeartbeat_nilMapSafe(t *testing.T) {
	d := &Daemon{}
	aid, err := a2al.ParseAddress(strings.ToLower("A0" + strings.Repeat("ef", 20)))
	if err != nil {
		t.Fatal(err)
	}
	d.touchHeartbeat(aid)
	if d.heartbeatAt == nil {
		t.Fatal("heartbeatAt should be allocated")
	}
	if _, ok := d.heartbeatAt[aid]; !ok {
		t.Fatal("missing entry")
	}
}
