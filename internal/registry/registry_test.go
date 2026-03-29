// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package registry

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
)

func testEntry(t *testing.T) *Entry {
	t.Helper()
	mpub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := crypto.AddressFromPublicKey(mpub)
	if err != nil {
		t.Fatal(err)
	}
	_, opPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Entry{
		AID:            aid,
		ServiceTCP:     "127.0.0.1:9",
		OpPriv:         opPriv,
		DelegationCBOR: []byte{0xde, 0xad},
		Seq:            7,
	}
}

func TestRegistry_PutGetListDelete(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agents.json")
	r := New(p)
	e := testEntry(t)
	if err := r.Put(e); err != nil {
		t.Fatal(err)
	}
	got := r.Get(e.AID)
	if got == nil || got.ServiceTCP != e.ServiceTCP || got.Seq != e.Seq {
		t.Fatal("Get mismatch")
	}
	list := r.List()
	if len(list) != 1 {
		t.Fatalf("List len %d", len(list))
	}
	if err := r.Delete(e.AID); err != nil {
		t.Fatal(err)
	}
	if r.Get(e.AID) != nil {
		t.Fatal("after Delete")
	}
}

func TestLoad_roundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agents.json")
	e := testEntry(t)
	r := New(p)
	if err := r.Put(e); err != nil {
		t.Fatal(err)
	}
	r2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	got := r2.Get(e.AID)
	if got == nil || got.ServiceTCP != e.ServiceTCP {
		t.Fatal("reload Get")
	}
	if len(got.OpPriv) != ed25519.PrivateKeySize {
		t.Fatal("OpPriv len")
	}
	if string(got.DelegationCBOR) != string(e.DelegationCBOR) {
		t.Fatal("DelegationCBOR")
	}
}

func TestLoad_missingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "none.json")
	r, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.List()) != 0 {
		t.Fatal("want empty")
	}
}

func TestLoad_skipsBadRows(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agents.json")
	raw := `{"agents":[{"aid":"not-a-valid-aid","service_tcp":"x","op_private_key_hex":"00","delegation_proof_hex":""}]}`
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.List()) != 0 {
		t.Fatalf("bad row should be skipped, got %d", len(r.List()))
	}
}

func TestDelete_missingNoError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.json")
	r := New(p)
	var zero a2al.Address
	if err := r.Delete(zero); err != nil {
		t.Fatal(err)
	}
}
