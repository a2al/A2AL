// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/a2al/a2al/cmd/a2ald/internal/nodeks"
	"github.com/a2al/a2al/cmd/a2ald/internal/registry"
	"github.com/a2al/a2al/config"
	"github.com/a2al/a2al/host"
	"log/slog"
)

func newTestDaemon(t *testing.T) *daemon {
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
	return &daemon{
		dataDir:  dir,
		cfgPath:  filepath.Join(dir, "config.toml"),
		cfg:      &cfg,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		h:        h,
		reg:      reg,
		nodeAddr: ks.Address(),
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
