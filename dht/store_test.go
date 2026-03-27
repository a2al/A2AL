// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/a2al/a2al"
	acrypto "github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/protocol"
)

func TestStore_Put_noAuth(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	now := time.Unix(1700000000, 0)
	sr, _ := protocol.SignEndpointRecord(priv, addr, protocol.EndpointPayload{Endpoints: []string{"quic://x:1"}}, 1, uint64(now.Unix()), 60)

	s := NewStore(nil, 0)
	if err := s.Put(a2al.NodeID{}, sr, now); err != nil {
		t.Fatal(err)
	}
}

func TestStore_Put_authAllow(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	now := time.Unix(1700000000, 0)
	sr, _ := protocol.SignEndpointRecord(priv, addr, protocol.EndpointPayload{Endpoints: []string{"quic://x:1"}}, 1, uint64(now.Unix()), 60)

	allow := func(a2al.NodeID, protocol.SignedRecord, time.Time) error { return nil }
	s := NewStore(allow, 0)
	if err := s.Put(a2al.NodeID{}, sr, now); err != nil {
		t.Fatal(err)
	}
}

func TestStore_Put_authReject(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	now := time.Unix(1700000000, 0)
	sr, _ := protocol.SignEndpointRecord(priv, addr, protocol.EndpointPayload{Endpoints: []string{"quic://x:1"}}, 1, uint64(now.Unix()), 60)

	reject := func(a2al.NodeID, protocol.SignedRecord, time.Time) error { return errors.New("not authorized") }
	s := NewStore(reject, 0)
	if err := s.Put(a2al.NodeID{}, sr, now); err == nil {
		t.Fatal("expected auth rejection")
	}
}
