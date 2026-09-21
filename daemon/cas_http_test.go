// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/a2al/a2al/group"
	"github.com/a2al/a2al/host"
)

func TestCASHTTPRoundTrip(t *testing.T) {
	d := newTestDaemon(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "blob.bin")
	payload := []byte("cas-http-payload")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(d.nodeAddr, path)
	if err != nil {
		t.Fatal(err)
	}

	c, s := net.Pipe()
	defer c.Close()
	go func() {
		defer s.Close()
		d.serveCASHTTP(s, d.nodeAddr)
	}()

	req, err := http.NewRequest(http.MethodGet, "http://cas"+group.CASPath(id), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("body %q", got)
	}
}

func TestCASHTTPNotFound(t *testing.T) {
	d := newTestDaemon(t)
	c, s := net.Pipe()
	defer c.Close()
	go func() {
		defer s.Close()
		d.serveCASHTTP(s, d.nodeAddr)
	}()
	var id [32]byte
	id[0] = 1
	req, _ := http.NewRequest(http.MethodGet, "http://cas"+group.CASPath(id), nil)
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestExecFetchCASLocal(t *testing.T) {
	d := newTestDaemon(t)
	path := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(path, []byte("hello-cas"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(d.nodeAddr, path)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := d.execFetchCAS(t.Context(), d.nodeAddr, d.nodeAddr, fetchReq{Path: group.CASPath(id)})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d", resp.Status)
	}
	got, err := base64.StdEncoding.DecodeString(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello-cas" {
		t.Fatalf("body %q", got)
	}
}

func TestCASAdmissionThenHTTP(t *testing.T) {
	d := newTestDaemon(t)
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("xy"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(d.nodeAddr, path)
	if err != nil {
		t.Fatal(err)
	}

	c, s := net.Pipe()
	defer c.Close()
	go func() {
		defer s.Close()
		var magic [4]byte
		if _, err := io.ReadFull(s, magic[:]); err != nil {
			return
		}
		d.handleCASStream(d.nodeAddr, d.nodeAddr, nil, s)
	}()

	if err := host.WriteCASAdmission(c, ""); err != nil {
		t.Fatal(err)
	}
	ok, _, err := host.ReadAccessResult(c)
	if err != nil || !ok {
		t.Fatalf("access ok=%v err=%v", ok, err)
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
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "xy" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestCASHTTPGoneOnSizeChange(t *testing.T) {
	d := newTestDaemon(t)
	path := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := d.registerLocalObject(d.nodeAddr, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}

	c, s := net.Pipe()
	defer c.Close()
	go func() {
		defer s.Close()
		d.serveCASHTTP(s, d.nodeAddr)
	}()
	req, _ := http.NewRequest(http.MethodGet, "http://cas"+group.CASPath(id), nil)
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status %d, want 410", resp.StatusCode)
	}
}
