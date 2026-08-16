// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/a2al/a2al"
	acrypto "github.com/a2al/a2al/crypto"
	"github.com/a2al/a2al/protocol"
)

func storeHasSoftExpiry(s *Store, key a2al.NodeID, recType uint8) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.softExpiry[softExpiryKey(key, recType)]
	return ok
}

type sovSigner struct {
	priv ed25519.PrivateKey
	addr a2al.Address
	key  a2al.NodeID
}

func newSovSigner(t *testing.T) sovSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := acrypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sovSigner{priv: priv, addr: addr, key: a2al.NodeIDFromAddress(addr)}
}

func (g sovSigner) sign02(t *testing.T, seq uint64, ts time.Time, ttl uint32) protocol.SignedRecord {
	t.Helper()
	sr, err := protocol.SignRecord(g.priv, g.addr, protocol.RecTypeAgentProfile, []byte{0xa0}, seq, uint64(ts.Unix()), ttl)
	if err != nil {
		t.Fatal(err)
	}
	return sr
}

func TestStore_SoftExpiry_boundaries(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	g := newSovSigner(t)
	sr := g.sign02(t, 1, t0, 3600)
	s := NewStore(nil, 0)
	if err := s.Put(g.key, sr, t0); err != nil {
		t.Fatal(err)
	}
	deadline := t0.Add(pathCacheSoftTTL)
	s.SetSoftExpiry(g.key, sr.RecType, deadline)

	if got := s.GetAll(g.key, sr.RecType, deadline.Add(-time.Nanosecond)); len(got) != 1 {
		t.Fatal("hidden before soft deadline")
	}
	if got := s.GetAll(g.key, sr.RecType, deadline); len(got) != 1 {
		t.Fatal("hidden at soft deadline (After is exclusive)")
	}
	if got := s.GetAll(g.key, sr.RecType, deadline.Add(time.Nanosecond)); len(got) != 0 {
		t.Fatal("still visible after soft deadline")
	}
	if s.Get(g.key, deadline.Add(time.Nanosecond)) != nil {
		t.Fatal("Get still returns after soft deadline")
	}
}

func TestStore_SoftExpiry_independentOfSignedTTL(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	g := newSovSigner(t)
	sr := g.sign02(t, 1, t0, 3600)
	s := NewStore(nil, 0)
	if err := s.Put(g.key, sr, t0); err != nil {
		t.Fatal(err)
	}

	if got := s.GetAll(g.key, sr.RecType, t0.Add(3601*time.Second)); len(got) != 0 {
		t.Fatal("signed-TTL expiry did not hide record")
	}

	s.SetSoftExpiry(g.key, sr.RecType, t0.Add(pathCacheSoftTTL))
	if got := s.GetAll(g.key, sr.RecType, t0.Add(pathCacheSoftTTL+time.Second)); len(got) != 0 {
		t.Fatal("soft expiry did not hide record while signed TTL still valid")
	}
	if got := s.GetAll(g.key, sr.RecType, t0.Add(pathCacheSoftTTL-time.Second)); len(got) != 1 {
		t.Fatal("soft-expiry window hid record too early")
	}
}

func TestStore_SoftExpiry_getPutSplit(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	g := newSovSigner(t)
	sr := g.sign02(t, 1, t0, 3600)
	s := NewStore(nil, 0)
	if err := s.Put(g.key, sr, t0); err != nil {
		t.Fatal(err)
	}
	s.SetSoftExpiry(g.key, sr.RecType, t0.Add(-time.Second))

	now := t0.Add(time.Second)
	if got := s.GetAll(g.key, sr.RecType, now); len(got) != 0 {
		t.Fatal("GetAll should hide soft-expired record")
	}
	newer := g.sign02(t, 2, now, 3600)
	if err := s.Put(g.key, newer, now); err != nil {
		t.Fatalf("Put into soft-expired slot: %v", err)
	}
	if got := s.GetAll(g.key, sr.RecType, now); len(got) != 0 {
		t.Fatal("GetAll became visible without ClearSoftExpiry")
	}
	s.ClearSoftExpiry(g.key, sr.RecType)
	if got := s.GetAll(g.key, sr.RecType, now); len(got) != 1 || got[0].Seq != 2 {
		t.Fatal("ClearSoftExpiry did not restore the newer record")
	}
}

func TestStore_SoftExpiry_clearRestores(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	g := newSovSigner(t)
	sr := g.sign02(t, 1, t0, 3600)
	s := NewStore(nil, 0)
	if err := s.Put(g.key, sr, t0); err != nil {
		t.Fatal(err)
	}
	s.SetSoftExpiry(g.key, sr.RecType, t0)
	past := t0.Add(time.Second)
	if len(s.GetAll(g.key, sr.RecType, past)) != 0 {
		t.Fatal("expected hidden")
	}
	s.ClearSoftExpiry(g.key, sr.RecType)
	if storeHasSoftExpiry(s, g.key, sr.RecType) {
		t.Fatal("soft expiry still armed after Clear")
	}
	if len(s.GetAll(g.key, sr.RecType, past)) != 1 {
		t.Fatal("record not visible after ClearSoftExpiry")
	}
}
