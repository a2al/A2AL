// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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

func TestStore_Put_topic_same_pubkey_replaces(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	key := protocol.TopicNodeID("ai/test")
	now := time.Unix(1700000000, 0)
	payload, err := protocol.MarshalTopicPayload(protocol.TopicPayload{Topic: "ai/test", Version: 1})
	if err != nil {
		t.Fatal(err)
	}

	s := NewStore(nil, 0)
	r1, err := protocol.SignRecord(priv, addr, protocol.RecTypeTopic, payload, 1, uint64(now.Unix()), 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(key, r1, now); err != nil {
		t.Fatal(err)
	}
	r2, err := protocol.SignRecord(priv, addr, protocol.RecTypeTopic, payload, 2, uint64(now.Unix()), 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(key, r2, now); err != nil {
		t.Fatal(err)
	}
	all := s.GetAll(key, protocol.RecTypeTopic, now)
	if len(all) != 1 || all[0].Seq != 2 {
		t.Fatalf("got %+v", all)
	}
}

func TestStore_Put_sovereign_wrong_key_rejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	now := time.Unix(1700000000, 0)
	payload := []byte{0xa0}
	r, err := protocol.SignRecord(priv, addr, 0x02, payload, 1, uint64(now.Unix()), 60)
	if err != nil {
		t.Fatal(err)
	}
	var wrong a2al.NodeID
	wrong[0] = 0xff
	s := NewStore(nil, 0)
	if err := s.Put(wrong, r, now); err == nil {
		t.Fatal("expected error")
	}
}
