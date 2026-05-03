// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── prepareFetch ──────────────────────────────────────────────────────────────

func TestPrepareFetch_defaults(t *testing.T) {
	pf, err := prepareFetch(fetchReq{Path: "/api"})
	if err != nil {
		t.Fatal(err)
	}
	if pf.method != http.MethodGet {
		t.Errorf("method = %q, want GET", pf.method)
	}
	if pf.path != "/api" {
		t.Errorf("path = %q, want /api", pf.path)
	}
}

func TestPrepareFetch_addsLeadingSlash(t *testing.T) {
	pf, err := prepareFetch(fetchReq{Path: "status"})
	if err != nil {
		t.Fatal(err)
	}
	if pf.path != "/status" {
		t.Errorf("path = %q, want /status", pf.path)
	}
}

func TestPrepareFetch_invalidBodyBase64(t *testing.T) {
	_, err := prepareFetch(fetchReq{Path: "/", BodyBase64: "not-base64!!!"})
	if err == nil {
		t.Fatal("expected error for invalid body_base64")
	}
}

func TestPrepareFetch_extractsHostHeader(t *testing.T) {
	pf, err := prepareFetch(fetchReq{
		Path:    "/",
		Headers: map[string][]string{"Host": {"example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pf.host != "example.com" {
		t.Errorf("host = %q, want example.com", pf.host)
	}
}

// ── execFetchDirect ───────────────────────────────────────────────────────────

func TestExecFetchDirect_get(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/hello" {
			t.Errorf("path = %s, want /hello", r.URL.Path)
		}
		w.Header().Set("X-Custom", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("world"))
	}))
	defer srv.Close()

	resp, err := execFetchDirect(context.Background(), strings.TrimPrefix(srv.URL, "http://"), fetchReq{
		Path: "/hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.Status)
	}
	if resp.Truncated {
		t.Error("unexpected truncated=true")
	}
	body, err := base64.StdEncoding.DecodeString(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "world" {
		t.Errorf("body = %q, want %q", string(body), "world")
	}
	if vals := resp.Headers["X-Custom"]; len(vals) == 0 || vals[0] != "yes" {
		t.Errorf("X-Custom header missing or wrong: %v", resp.Headers["X-Custom"])
	}
}

func TestExecFetchDirect_hostHeaderOverride(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := execFetchDirect(context.Background(), strings.TrimPrefix(srv.URL, "http://"), fetchReq{
		Path:    "/",
		Headers: map[string][]string{"Host": {"myservice.internal"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotHost != "myservice.internal" {
		t.Errorf("Host header = %q, want myservice.internal", gotHost)
	}
}

func TestExecFetchDirect_multiValueHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := execFetchDirect(context.Background(), strings.TrimPrefix(srv.URL, "http://"), fetchReq{Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Headers["Set-Cookie"]) != 2 {
		t.Errorf("Set-Cookie values = %v, want 2 entries", resp.Headers["Set-Cookie"])
	}
}

func TestExecFetchDirect_truncation(t *testing.T) {
	bigBody := strings.Repeat("x", fetchMaxBody+100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(bigBody))
	}))
	defer srv.Close()

	resp, err := execFetchDirect(context.Background(), strings.TrimPrefix(srv.URL, "http://"), fetchReq{Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Truncated {
		t.Error("expected truncated=true for oversized body")
	}
	body, _ := base64.StdEncoding.DecodeString(resp.Body)
	if len(body) != fetchMaxBody {
		t.Errorf("body len = %d, want %d", len(body), fetchMaxBody)
	}
}

func TestExecFetchDirect_postWithBody(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		gotBody, _ = json.Marshal(map[string]string{"echo": r.Method})
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(gotBody)
	}))
	defer srv.Close()

	payload := base64.StdEncoding.EncodeToString([]byte(`{"key":"value"}`))
	resp, err := execFetchDirect(context.Background(), strings.TrimPrefix(srv.URL, "http://"), fetchReq{
		Method:     "POST",
		Path:       "/submit",
		BodyBase64: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.Status)
	}
}

func TestExecFetchDirect_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	resp, err := execFetchDirect(context.Background(), strings.TrimPrefix(srv.URL, "http://"), fetchReq{Path: "/gone"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.Status)
	}
}
