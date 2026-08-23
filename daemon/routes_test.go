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
	d := &Daemon{
		dataDir:          dir,
		cfgPath:          filepath.Join(dir, "config.toml"),
		cfg:              &cfg,
		log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		h:                h,
		reg:              reg,
		nodeAddr:         ks.Address(),
		startedAt:        time.Now(),
		agentLastPublish: make(map[a2al.Address]time.Time),
		heartbeatAt:      make(map[a2al.Address]time.Time),
		mboxStore:        newMailboxStore(filepath.Join(dir, "mailbox_store.cbor"), slog.New(slog.NewTextHandler(io.Discard, nil))),
		mboxStoreStop:    make(chan struct{}),
		bus:              NewEventBus(slog.New(slog.NewTextHandler(io.Discard, nil))),
		tunnels:          newTunnelRegistry(),
	}
	d.initRemoteAdmin()
	d.initAddressBook()
	d.aclIP = newACLIPGate()
	h.SetDecideAccess(d.decideAccess)
	return d
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
	t.Run("loopback_bypass_default", func(t *testing.T) {
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
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("want 200, got %d", resp.StatusCode)
		}
	})

	t.Run("loopback_forced_no_bearer", func(t *testing.T) {
		d := newTestDaemon(t)
		d.cfg.APIToken = "tok"
		d.cfg.RequireLocalToken = true
		srv := httptest.NewServer(d.routes())
		defer srv.Close()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", resp.StatusCode)
		}
	})

	t.Run("loopback_forced_with_bearer", func(t *testing.T) {
		d := newTestDaemon(t)
		d.cfg.APIToken = "tok"
		d.cfg.RequireLocalToken = true
		srv := httptest.NewServer(d.routes())
		defer srv.Close()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
		req.Header.Set("Authorization", "Bearer tok")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("want 200, got %d", resp.StatusCode)
		}
	})
}

func TestAPI_middleware_hostHeader(t *testing.T) {
	t.Run("rebinding_rejected", func(t *testing.T) {
		d := newTestDaemon(t)
		srv := httptest.NewServer(d.routes())
		defer srv.Close()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
		req.Host = "evil.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", resp.StatusCode)
		}
	})

	t.Run("no_host_header_allowed", func(t *testing.T) {
		// HTTP/1.0 or raw clients that omit Host should not be rejected.
		d := newTestDaemon(t)
		srv := httptest.NewServer(d.routes())
		defer srv.Close()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
		req.Host = "" // force empty Host header
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("want 200, got %d", resp.StatusCode)
		}
	})
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
	if _, ok := ag["service_tcp_ok"]; ok {
		t.Fatalf("service_tcp_ok should not appear in list response, got %#v", ag["service_tcp_ok"])
	}
}

func TestAPI_acl_crud(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	visitor := newTestAgent(t, d)
	blocked := newTestAgent(t, d)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	base := srv.URL + "/agents/" + aid.String()

	getJSON := func(t *testing.T, path string) map[string]any {
		t.Helper()
		resp, err := client.Get(path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
		var m map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	doJSON := func(t *testing.T, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, path, rdr)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return resp.StatusCode, m
	}

	acl := getJSON(t, base+"/acl")
	if acl["default"] != "public" {
		t.Fatalf("default %#v", acl["default"])
	}
	ag := getJSON(t, base)
	if ag["acl"] == nil {
		t.Fatal("GET agent missing acl")
	}

	if st, _ := doJSON(t, http.MethodPatch, base+"/acl", map[string]string{"default": "deny"}); st != http.StatusOK {
		t.Fatalf("patch default %d", st)
	}
	acl = getJSON(t, base+"/acl")
	if acl["default"] != "deny" {
		t.Fatalf("after patch %#v", acl["default"])
	}

	st, created := doJSON(t, http.MethodPost, base+"/acl/allow", map[string]string{"aid": visitor.String()})
	if st != http.StatusCreated {
		t.Fatalf("allow post %d %#v", st, created)
	}
	allowID, _ := created["id"].(string)
	if allowID == "" {
		t.Fatal("missing allow id")
	}

	st, _ = doJSON(t, http.MethodPost, base+"/acl/deny", map[string]string{"aid": ""})
	if st != http.StatusBadRequest {
		t.Fatalf("empty deny aid want 400 got %d", st)
	}
	if st, _ = doJSON(t, http.MethodPost, base+"/acl/deny", map[string]string{"aid": visitor.String()}); st != http.StatusBadRequest {
		t.Fatalf("deny overlapping allow want 400 got %d", st)
	}
	st, denied := doJSON(t, http.MethodPost, base+"/acl/deny", map[string]string{"aid": blocked.String()})
	if st != http.StatusCreated {
		t.Fatalf("deny post %d %#v", st, denied)
	}
	denyID, _ := denied["id"].(string)

	st, join := doJSON(t, http.MethodPost, base+"/acl/allow", map[string]string{"secret": "s3cret"})
	if st != http.StatusCreated {
		t.Fatalf("join password post %d %#v", st, join)
	}
	if join["secret"] != "s3cret" {
		t.Fatalf("create should echo secret %#v", join)
	}
	if st, _ = doJSON(t, http.MethodPost, base+"/acl/allow", map[string]string{}); st != http.StatusBadRequest {
		t.Fatalf("empty join want 400 got %d", st)
	}
	acl = getJSON(t, base+"/acl")
	foundSecret := false
	for _, item := range acl["allow"].([]any) {
		m := item.(map[string]any)
		if m["secret_set"] == true {
			if m["secret"] != "s3cret" {
				t.Fatalf("editor GET should return join secret %#v", m)
			}
			if m["aid"] != nil {
				t.Fatal("join password should have no aid")
			}
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Fatal("secret entry missing")
	}
	ag = getJSON(t, base)
	raw, _ := json.Marshal(ag)
	if strings.Contains(string(raw), "s3cret") {
		t.Fatal("secret leaked on GET agent")
	}

	if st, _ = doJSON(t, http.MethodDelete, base+"/acl/allow/"+allowID, nil); st != http.StatusOK {
		t.Fatalf("del allow %d", st)
	}
	if st, _ = doJSON(t, http.MethodDelete, base+"/acl/deny/"+denyID, nil); st != http.StatusOK {
		t.Fatalf("del deny %d", st)
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
