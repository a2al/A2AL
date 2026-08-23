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

func TestACL_Allows(t *testing.T) {
	a := testEntry(t).AID
	b := testEntry(t).AID
	aStr := a.String()

	if !((*ACLPolicy)(nil)).Allows(a, "") {
		t.Fatal("nil policy must allow")
	}
	if !(&ACLPolicy{}).Allows(a, "") {
		t.Fatal("empty policy default public")
	}
	denyAll := &ACLPolicy{Default: ACLDefaultDeny}
	if denyAll.Allows(a, "") {
		t.Fatal("default deny, empty lists")
	}
	blacklist := &ACLPolicy{
		Default: ACLDefaultPublic,
		Deny:    []ACLEntry{{ID: "1", AID: aStr}},
	}
	if blacklist.Allows(a, "") {
		t.Fatal("deny list hit")
	}
	if !blacklist.Allows(b, "") {
		t.Fatal("deny list miss should allow")
	}
	whitelist := &ACLPolicy{
		Default: ACLDefaultDeny,
		Allow:   []ACLEntry{{ID: "1", AID: aStr}},
	}
	if !whitelist.Allows(a, "") {
		t.Fatal("allow list hit")
	}
	if whitelist.Allows(b, "") {
		t.Fatal("allow list miss should deny")
	}
	both := &ACLPolicy{
		Default: ACLDefaultDeny,
		Deny:    []ACLEntry{{ID: "d", AID: aStr}},
		Allow:   []ACLEntry{{ID: "a", AID: aStr}},
	}
	if both.Allows(a, "") {
		t.Fatal("deny must beat allow")
	}
	if err := (&ACLPolicy{Deny: []ACLEntry{{ID: "x"}}}).Validate(); err == nil {
		t.Fatal("deny without aid")
	}
	if err := (&ACLPolicy{Default: "maybe"}).Validate(); err == nil {
		t.Fatal("bad default")
	}

	join := &ACLPolicy{
		Default: ACLDefaultDeny,
		Allow:   []ACLEntry{{ID: "j", Secret: "room"}},
	}
	if !join.Allows(a, "room") {
		t.Fatal("join password should allow")
	}
	if join.Allows(a, "wrong") || join.Allows(a, "") {
		t.Fatal("wrong join password")
	}
	if err := (&ACLPolicy{Allow: []ACLEntry{{ID: "j"}}}).Validate(); err == nil {
		t.Fatal("empty join secret")
	}
	if err := (&ACLPolicy{Allow: []ACLEntry{{ID: "n", AID: aStr, Secret: "x"}}}).Validate(); err == nil {
		t.Fatal("named+secret")
	}
	if err := (&ACLPolicy{
		Deny:  []ACLEntry{{ID: "d", AID: aStr}},
		Allow: []ACLEntry{{ID: "a", AID: aStr}},
	}).Validate(); err == nil {
		t.Fatal("same aid both lists")
	}
}

func TestACL_roundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agents.json")
	e := testEntry(t)
	visitor := testEntry(t).AID
	e.ACL = &ACLPolicy{
		Default: ACLDefaultDeny,
		Allow:   []ACLEntry{{ID: "ab", AID: visitor.String()}},
		Deny:    []ACLEntry{{ID: "no", AID: e.AID.String()}},
	}
	r := New(p)
	if err := r.Put(e); err != nil {
		t.Fatal(err)
	}
	r2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	got := r2.Get(e.AID)
	if got == nil || got.ACL == nil || got.ACL.Default != ACLDefaultDeny {
		t.Fatal("acl not reloaded")
	}
	if len(got.ACL.Allow) != 1 || got.ACL.Allow[0].AID != visitor.String() {
		t.Fatal("allow list")
	}
	if !got.ACL.Allows(visitor, "") {
		t.Fatal("reloaded allow")
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
