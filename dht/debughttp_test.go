// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/a2al/a2al/transport"
)

func TestDebugHTTP_endpoints(t *testing.T) {
	netw := transport.NewMemNetwork()
	tr, err := netw.NewTransport("x")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	ks := newMemKS(t)
	n, err := NewNode(Config{Transport: tr, Keystore: ks})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.Start()

	srv := httptest.NewServer(n.DebugHTTPHandler())
	defer srv.Close()

	paths := []string{"/debug/identity", "/debug/routing", "/debug/store", "/debug/stats"}
	for _, p := range paths {
		res, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusOK {
			_ = res.Body.Close()
			t.Fatalf("%s: %s", p, res.Status)
		}
		var raw json.RawMessage
		if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
			_ = res.Body.Close()
			t.Fatalf("%s decode: %v", p, err)
		}
		_ = res.Body.Close()
	}
}
