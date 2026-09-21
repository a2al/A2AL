// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestPickInboundAID(t *testing.T) {
	t.Parallel()
	if _, err := pickInboundAID(nil, ""); err == nil || !strings.Contains(err.Error(), "register") {
		t.Fatalf("empty: %v", err)
	}
	got, err := pickInboundAID([]string{"a"}, "")
	if err != nil || got != "a" {
		t.Fatalf("one: got %q %v", got, err)
	}
	if _, err := pickInboundAID([]string{"a", "b"}, ""); err == nil || !strings.Contains(err.Error(), "--aid") {
		t.Fatalf("many: %v", err)
	}
	got, err = pickInboundAID([]string{"a", "b"}, "b")
	if err != nil || got != "b" {
		t.Fatalf("flag: got %q %v", got, err)
	}
	if _, err := pickInboundAID([]string{"a"}, "z"); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("missing flag: %v", err)
	}
}

func TestCanonicalHostPortLoopback(t *testing.T) {
	t.Parallel()
	want := "127.0.0.1:2121"
	for _, in := range []string{"127.0.0.1:2121", "localhost:2121", "http://127.0.0.1:2121", "0.0.0.0:2121"} {
		got, err := canonicalHostPort(in)
		if err != nil || got != want {
			t.Fatalf("%s → %q %v, want %s", in, got, err, want)
		}
	}
	if _, err := serviceTCPDialAddr("127.0.0.1:8080/v1"); err != errServiceTCPPath {
		t.Fatalf("path: %v", err)
	}
	if _, err := serviceTCPDialAddr(""); err != errNeedAddr {
		t.Fatalf("empty: %v", err)
	}
}

func TestInboundShareText(t *testing.T) {
	t.Parallel()
	s := inboundShareText("aid-1", "http://127.0.0.1:2121")
	for _, want := range []string{
		"AID: aid-1",
		"a2al_fetch",
		"a2al_mailbox_send",
		"a2al_tunnel_open",
		"their own HTTP path",
		"http://127.0.0.1:2121/aid/aid-1/",
		"http://127.0.0.1:2121/aid/aid-1/v1",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("share missing %q\n%s", want, s)
		}
	}
}

type inboundStub struct {
	mu     sync.Mutex
	patchN int
	last   map[string]any
	aids   []string
	api    string
}

func stubInbound(t *testing.T, s *inboundStub) *Client {
	t.Helper()
	if s.api == "" {
		s.api = "127.0.0.1:2121"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agents", func(w http.ResponseWriter, _ *http.Request) {
		agents := make([]map[string]any, len(s.aids))
		for i, a := range s.aids {
			agents[i] = map[string]any{"aid": a}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"agents": agents})
	})
	mux.HandleFunc("GET /config", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"api_addr": s.api})
	})
	mux.HandleFunc("PATCH /agents/{aid}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.patchN++
		_ = json.NewDecoder(r.Body).Decode(&s.last)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return newClient(srv.URL, "", false)
}

func TestInboundBindHappyPath(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	st := &inboundStub{aids: []string{"aid-1"}}
	cli := stubInbound(t, st)
	res, err := inboundBind(cli, addr, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.AID != "aid-1" || res.ServiceTCP != addr {
		t.Fatalf("result %+v", res)
	}
	if !strings.HasSuffix(res.InboundURL, "/aid/aid-1/") {
		t.Fatalf("inbound_url %s", res.InboundURL)
	}
	st.mu.Lock()
	n, tcp := st.patchN, st.last["service_tcp"]
	st.mu.Unlock()
	if n != 1 || tcp != addr {
		t.Fatalf("patch n=%d tcp=%v", n, tcp)
	}
}

func TestInboundBindRefuseDaemonAPI(t *testing.T) {
	st := &inboundStub{aids: []string{"aid-1"}, api: "127.0.0.1:2121"}
	cli := stubInbound(t, st)
	_, err := inboundBind(cli, "127.0.0.1:2121", "")
	if err == nil || !strings.Contains(err.Error(), "api_addr") {
		t.Fatalf("want api_addr refuse, got %v", err)
	}
	u, _ := url.Parse(cli.Base)
	_, err = inboundBind(cli, u.Host, "")
	if err == nil || !strings.Contains(err.Error(), "api_addr") {
		t.Fatalf("want client base refuse, got %v", err)
	}
	st.mu.Lock()
	n := st.patchN
	st.mu.Unlock()
	if n != 0 {
		t.Fatalf("patched %d times", n)
	}
}

func TestInboundBindUnreachable(t *testing.T) {
	st := &inboundStub{aids: []string{"aid-1"}}
	cli := stubInbound(t, st)
	_, err := inboundBind(cli, "127.0.0.1:1", "")
	if err == nil || !strings.Contains(err.Error(), "nothing listens") {
		t.Fatalf("want unreachable, got %v", err)
	}
	st.mu.Lock()
	n := st.patchN
	st.mu.Unlock()
	if n != 0 {
		t.Fatalf("patched %d times", n)
	}
}

func TestInboundBindPathRejected(t *testing.T) {
	st := &inboundStub{aids: []string{"aid-1"}}
	cli := stubInbound(t, st)
	_, err := inboundBind(cli, "127.0.0.1:8080/v1", "")
	if err != errServiceTCPPath {
		t.Fatalf("got %v", err)
	}
}
