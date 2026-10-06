// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoRequest_mutatingSendsJSONContentType(t *testing.T) {
	var gotCT, gotBody string
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	c := newClient(srv.URL, "", false)
	if _, _, err := c.DoRequest(http.MethodDelete, "/tunnel/x", nil, new(map[string]any)); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete || gotCT != "application/json" || gotBody != "{}" {
		t.Fatalf("DELETE method=%s ct=%q body=%q", gotMethod, gotCT, gotBody)
	}

	if _, _, err := c.DoRequest(http.MethodGet, "/status", nil, new(map[string]any)); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodGet || gotCT != "" {
		t.Fatalf("GET method=%s ct=%q", gotMethod, gotCT)
	}
}
