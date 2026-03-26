// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nodeks

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
)

func TestLoadOrGenerate_createsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.key")
	s1, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	var zeroAddr a2al.Address
	if s1.Address() == zeroAddr {
		t.Fatal("address should be non-zero")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytesTrimSpace(b)) != ed25519.PrivateKeySize*2 {
		t.Fatalf("hex file len %d", len(b))
	}
	s2, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	if s1.Address() != s2.Address() {
		t.Fatalf("reload address mismatch %v %v", s1.Address(), s2.Address())
	}
}

func TestLoadOrGenerate_invalidHex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	if err := os.WriteFile(path, []byte("zz"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrGenerate(path)
	if err == nil {
		t.Fatal("want decode error")
	}
}

func TestLoadOrGenerate_wrongKeyLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(make([]byte, 16))), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrGenerate(path)
	if err == nil {
		t.Fatal("want length error")
	}
}

func TestStore_KeyStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	s, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	addr := s.Address()
	list, err := s.List()
	if err != nil || len(list) != 1 || list[0] != addr {
		t.Fatalf("List: %v %v", list, err)
	}
	pub, err := s.PublicKey(addr)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatal("PublicKey", err)
	}
	msg := []byte("hello")
	sig, err := s.Sign(addr, msg)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatal("Sign", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature verify")
	}
	wrong := addr
	wrong[0] ^= 0xff
	if _, err := s.Sign(wrong, msg); err == nil {
		t.Fatal("Sign wrong addr")
	}
	priv, err := s.Ed25519PrivateKey(addr)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		t.Fatal("Ed25519PrivateKey", err)
	}
	if _, err := s.Generate(crypto.KeyTypeEd25519); err == nil {
		t.Fatal("Generate should fail")
	}
}

func TestLoadOrGenerate_trimWhitespace(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := crypto.AddressFromPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "node.key")
	h := hex.EncodeToString(priv)
	if err := os.WriteFile(path, []byte("  \n"+h+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Address() != addr {
		t.Fatal("trim load mismatch")
	}
}
