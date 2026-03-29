// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package nodeks loads or creates the daemon DHT node identity (node.key).
package nodeks

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
)

// Store is a single-identity crypto.KeyStore for the DHT node (not an app Agent).
type Store struct {
	priv ed25519.PrivateKey
	addr a2al.Address
}

// LoadOrGenerate reads hex-encoded 64-byte Ed25519 private key from path, or creates one.
func LoadOrGenerate(keyPath string) (*Store, error) {
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(keyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		addr, err := crypto.AddressFromPublicKey(pub)
		if err != nil {
			return nil, err
		}
		h := hex.EncodeToString(priv)
		if err := os.WriteFile(keyPath, []byte(h), 0o600); err != nil {
			return nil, err
		}
		return &Store{priv: priv, addr: addr}, nil
	}
	raw, err := hex.DecodeString(string(bytesTrimSpace(b)))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("nodeks: invalid private key length")
	}
	priv := ed25519.PrivateKey(raw)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("nodeks: bad public key")
	}
	addr, err := crypto.AddressFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &Store{priv: priv, addr: addr}, nil
}

func bytesTrimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}

// Address returns the node's A2AL address (DHT identity).
func (s *Store) Address() a2al.Address { return s.addr }

// PrivateKey returns the node's Ed25519 private key for QUIC.
func (s *Store) PrivateKey() ed25519.PrivateKey { return s.priv }

// Generate implements crypto.KeyStore (unsupported).
func (s *Store) Generate(crypto.KeyType) (crypto.PrivateKey, error) {
	return nil, errors.New("nodeks: generate not supported")
}

// Sign implements crypto.KeyStore.
func (s *Store) Sign(addr a2al.Address, data []byte) ([]byte, error) {
	if addr != s.addr {
		return nil, errors.New("nodeks: wrong address")
	}
	return ed25519.Sign(s.priv, data), nil
}

// PublicKey implements crypto.KeyStore.
func (s *Store) PublicKey(addr a2al.Address) ([]byte, error) {
	if addr != s.addr {
		return nil, errors.New("nodeks: wrong address")
	}
	pub := s.priv.Public().(ed25519.PublicKey)
	out := make([]byte, len(pub))
	copy(out, pub)
	return out, nil
}

// List implements crypto.KeyStore.
func (s *Store) List() ([]a2al.Address, error) {
	return []a2al.Address{s.addr}, nil
}

// Ed25519PrivateKey implements the optional host.KeyStore exporter.
func (s *Store) Ed25519PrivateKey(addr a2al.Address) (ed25519.PrivateKey, error) {
	if addr != s.addr {
		return nil, errors.New("nodeks: wrong address")
	}
	out := make(ed25519.PrivateKey, len(s.priv))
	copy(out, s.priv)
	return out, nil
}
