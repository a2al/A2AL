// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package peerscache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_missing(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "nope.cache"))
	if err != nil || got != nil {
		t.Fatalf("missing file: err=%v peers=%v", err, got)
	}
}

func TestLoad_invalidJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte(`{`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	if err == nil {
		t.Fatal("want unmarshal error")
	}
}

func TestSaveLoad_roundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "peers.cache")
	in := []string{"127.0.0.1:5001", "10.0.0.2:5001"}
	if err := Save(p, in); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != in[0] || got[1] != in[1] {
		t.Fatalf("got %#v", got)
	}
	var f File
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Peers) != 2 {
		t.Fatal(f.Peers)
	}
}

func TestSave_capsAt64(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.cache")
	in := make([]string, 70)
	for i := range in {
		in[i] = "127.0.0.1:5001"
	}
	if err := Save(p, in); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 64 {
		t.Fatalf("len got %d", len(got))
	}
}
