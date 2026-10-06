// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/group"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/registry"
)

func TestCASGrantAdmitsDenyDefault(t *testing.T) {
	d := newTestDaemon(t)
	holder := newTestAgent(t, d)
	peer := newTestAgent(t, d)
	e := d.reg.Get(holder)
	e.ACL = &registry.ACLPolicy{Default: registry.ACLDefaultDeny}
	if err := d.reg.Put(e); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("grant-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(holder, path)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := d.ensureShareGrant(holder, id)
	if err != nil || grant == "" {
		t.Fatalf("grant %q err=%v", grant, err)
	}

	roundtrip := func(token string) (admitted bool, status int, body string) {
		c, s := net.Pipe()
		defer c.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer s.Close()
			var magic [4]byte
			if _, err := io.ReadFull(s, magic[:]); err != nil {
				return
			}
			d.handleCASStream(holder, peer, nil, s)
		}()
		if err := host.WriteCASAdmission(c, token); err != nil {
			t.Fatal(err)
		}
		ok, _, err := host.ReadAccessResult(c)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			<-done
			return false, 0, ""
		}
		req, _ := http.NewRequest(http.MethodGet, "http://cas"+group.CASPath(id), nil)
		if err := req.Write(c); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		<-done
		return true, resp.StatusCode, string(b)
	}

	if ok, _, _ := roundtrip(""); ok {
		t.Fatal("empty token must not admit deny-default")
	}
	ok, status, body := roundtrip(grant)
	if !ok || status != 200 || body != "grant-bytes" {
		t.Fatalf("grant admit ok=%v status=%d body=%q", ok, status, body)
	}
	ok, status, _ = roundtrip("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	if !ok {
		t.Fatal("non-empty wrong grant should open the stream")
	}
	if status != http.StatusForbidden {
		t.Fatalf("wrong grant status %d, want 403", status)
	}

	rec, _ := d.casRec(holder, id)
	if len(rec.Served) != 1 || rec.Served[0] != peer.String() {
		t.Fatalf("served %v", rec.Served)
	}
}

func TestCASDenyListBlocksGrant(t *testing.T) {
	d := newTestDaemon(t)
	holder := newTestAgent(t, d)
	peer := newTestAgent(t, d)
	e := d.reg.Get(holder)
	e.ACL = &registry.ACLPolicy{
		Default: registry.ACLDefaultDeny,
		Deny:    []registry.ACLEntry{{AID: peer.String()}},
	}
	if err := d.reg.Put(e); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(holder, path)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := d.ensureShareGrant(holder, id)
	if err != nil {
		t.Fatal(err)
	}

	c, s := net.Pipe()
	defer c.Close()
	go func() {
		defer s.Close()
		var magic [4]byte
		_, _ = io.ReadFull(s, magic[:])
		d.handleCASStream(holder, peer, nil, s)
	}()
	if err := host.WriteCASAdmission(c, grant); err != nil {
		t.Fatal(err)
	}
	ok, _, err := host.ReadAccessResult(c)
	if err != nil || ok {
		t.Fatalf("deny-list must block grant ok=%v err=%v", ok, err)
	}
}

func TestCASTransparentGetSameDaemon(t *testing.T) {
	d := newTestDaemon(t)
	a := newTestAgent(t, d)
	b := newTestAgent(t, d)
	path := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(path, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, size, _, err := d.registerLocalObject(a, path)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := d.ensureShareGrant(a, id)
	if err != nil {
		t.Fatal(err)
	}
	d.rememberObjectRef(b, id, grant, a, size)

	got, n, err := d.ensureObjectLocal(context.Background(), b, id, a, false, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if n != size {
		t.Fatalf("size %d want %d", n, size)
	}
	body, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "shared" {
		t.Fatalf("body %q", body)
	}
	rec, ok := d.casRec(a, id)
	if !ok || len(rec.Served) != 1 || rec.Served[0] != b.String() {
		t.Fatalf("served after copy %+v", rec.Served)
	}
	if _, _, err := d.ensureObjectLocal(context.Background(), b, id, a, false, true, ""); err != nil {
		t.Fatal(err)
	}
	rec, _ = d.casRec(a, id)
	if len(rec.Served) != 1 {
		t.Fatalf("served duplicated %v", rec.Served)
	}
	d.noteCASServed(a, a, id)
	rec, _ = d.casRec(a, id)
	if len(rec.Served) != 1 {
		t.Fatalf("self served %v", rec.Served)
	}

	if err := d.patchCasRec(a, id, func(rec *casRec) { rec.Served = nil }); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/agents/" + b.String() + "/cas/" + hex.EncodeToString(id[:]))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(out) != "shared" {
		t.Fatalf("identity get status=%d body=%q", resp.StatusCode, out)
	}
	rec, ok = d.casRec(a, id)
	if !ok || len(rec.Served) != 1 || rec.Served[0] != b.String() {
		t.Fatalf("served after identity get %+v", rec.Served)
	}
}

func TestCASMapObjectPreservesGrant(t *testing.T) {
	d := newTestDaemon(t)
	aid := newTestAgent(t, d)
	var id [32]byte
	id[0] = 9
	d.rememberObjectRef(aid, id, "abc", a2al.Address{}, 0)
	path := filepath.Join(t.TempDir(), "p.bin")
	if err := os.WriteFile(path, []byte("z"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.mapObject(aid, id, path, 1); err != nil {
		t.Fatal(err)
	}
	rec, ok := d.casRec(aid, id)
	if !ok || rec.Grant != "abc" || rec.Path != path {
		t.Fatalf("%+v ok=%v", rec, ok)
	}
}

func TestCASHTTPServedOnlyOnGET200(t *testing.T) {
	d := newTestDaemon(t)
	holder := newTestAgent(t, d)
	peer := newTestAgent(t, d)
	e := d.reg.Get(holder)
	e.ACL = &registry.ACLPolicy{Default: registry.ACLDefaultDeny}
	if err := d.reg.Put(e); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(holder, path)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := d.ensureShareGrant(holder, id)
	if err != nil {
		t.Fatal(err)
	}

	do := func(method string) int {
		t.Helper()
		c, s := net.Pipe()
		defer c.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer s.Close()
			var magic [4]byte
			_, _ = io.ReadFull(s, magic[:])
			d.handleCASStream(holder, peer, nil, s)
		}()
		if err := host.WriteCASAdmission(c, grant); err != nil {
			t.Fatal(err)
		}
		ok, _, err := host.ReadAccessResult(c)
		if err != nil || !ok {
			t.Fatalf("admit ok=%v err=%v", ok, err)
		}
		req, _ := http.NewRequest(method, "http://cas"+group.CASPath(id), nil)
		if err := req.Write(c); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		<-done
		return resp.StatusCode
	}

	if code := do(http.MethodHead); code != http.StatusOK {
		t.Fatalf("HEAD %d", code)
	}
	rec, _ := d.casRec(holder, id)
	if len(rec.Served) != 0 {
		t.Fatalf("HEAD served %v", rec.Served)
	}

	if err := os.WriteFile(path, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := do(http.MethodGet); code != http.StatusGone {
		t.Fatalf("GET gone %d", code)
	}
	rec, _ = d.casRec(holder, id)
	if len(rec.Served) != 0 {
		t.Fatalf("410 served %v", rec.Served)
	}

	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := do(http.MethodGet); code != http.StatusOK {
		t.Fatalf("GET %d", code)
	}
	rec, _ = d.casRec(holder, id)
	if len(rec.Served) != 1 || rec.Served[0] != peer.String() {
		t.Fatalf("GET served %v", rec.Served)
	}
}
