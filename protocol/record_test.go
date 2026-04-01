// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	acrypto "github.com/a2al/a2al/crypto"
)

func TestSignVerify_endpointRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := acrypto.AddressFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1700000000, 0)
	sr, err := SignEndpointRecord(priv, addr, EndpointPayload{
		Endpoints: []string{"quic://127.0.0.1:4001"},
		NatType:   NATFullCone,
	}, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedRecord(sr, now); err != nil {
		t.Fatal(err)
	}
	er, err := ParseEndpointRecord(sr)
	if err != nil {
		t.Fatal(err)
	}
	if len(er.Endpoints) != 1 || er.Endpoints[0] != "quic://127.0.0.1:4001" {
		t.Fatal(er.Endpoints)
	}
}

func TestVerify_tamperRecord(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	now := time.Unix(1700000000, 0)
	sr, err := SignEndpointRecord(priv, addr, EndpointPayload{Endpoints: []string{"quic://a:1"}, NatType: NATUnknown}, 1, uint64(now.Unix()), 60)
	if err != nil {
		t.Fatal(err)
	}
	sr.Seq = 999
	if VerifySignedRecord(sr, now) == nil {
		t.Fatal("expected verify fail after tamper")
	}
}

func TestVerify_expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	sr, err := SignEndpointRecord(priv, addr, EndpointPayload{Endpoints: nil, NatType: NATUnknown}, 1, 1700000000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if VerifySignedRecord(sr, time.Unix(1700001000, 0)) != ErrRecordExpired {
		t.Fatal("expected expired")
	}
}

func TestRecordIsNewer(t *testing.T) {
	a := SignedRecord{Seq: 2, Timestamp: 100}
	b := SignedRecord{Seq: 1, Timestamp: 200}
	if !RecordIsNewer(a, b) {
		t.Fatal("seq should win")
	}
	c := SignedRecord{Seq: 2, Timestamp: 50}
	d := SignedRecord{Seq: 2, Timestamp: 51}
	if RecordIsNewer(c, d) {
		t.Fatal("timestamp tie-break")
	}
	if !RecordIsNewer(d, c) {
		t.Fatal("d newer by time")
	}
}

func TestStoreMessage_carriesSignedRecord(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	addr, _ := acrypto.AddressFromPublicKey(pub)
	tx := make([]byte, txIDLen)
	rand.Read(tx)
	now := time.Unix(1700000000, 0)
	sr, err := SignEndpointRecord(priv, addr, EndpointPayload{Endpoints: []string{"quic://1.1.1.1:1"}, NatType: NATUnknown}, 3, uint64(now.Unix()), 120)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalSignedMessage(
		Header{Version: ProtocolVersion, MsgType: MsgStore, TxID: tx},
		&BodyStore{Record: sr},
		priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := VerifyAndDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	bs := dec.Body.(*BodyStore)
	if err := VerifySignedRecord(bs.Record, now); err != nil {
		t.Fatal(err)
	}
}

// TestSignVerify_delegatedEndpoint verifies that SignEndpointRecordDelegated produces
// a record whose signature passes VerifySignedRecord (cryptographic integrity only;
// authority is checked separately via dht.Config.RecordAuth at the store layer).
func TestSignVerify_delegatedEndpoint(t *testing.T) {
	_, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	masterPub, _, _ := ed25519.GenerateKey(rand.Reader)
	agentAddr, _ := acrypto.AddressFromPublicKey(masterPub)
	now := time.Unix(1700000000, 0)

	fakeDel := []byte("placeholder-proof") // authority not checked here
	sr, err := SignEndpointRecordDelegated(opPriv, fakeDel, agentAddr, EndpointPayload{Endpoints: []string{"quic://x:1"}, NatType: NATUnknown}, 1, uint64(now.Unix()), 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedRecord(sr, now); err != nil {
		t.Fatal(err)
	}
	er, err := ParseEndpointRecord(sr)
	if err != nil {
		t.Fatal(err)
	}
	if er.Address != agentAddr {
		t.Fatal(er.Address)
	}
	if string(sr.Delegation) != "placeholder-proof" {
		t.Fatal("delegation not embedded")
	}
}

func TestSign_selfSignedNoMismatch(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	masterPub, _, _ := ed25519.GenerateKey(rand.Reader)
	wrongAddr, _ := acrypto.AddressFromPublicKey(masterPub)
	_, err := SignEndpointRecord(priv, wrongAddr, EndpointPayload{}, 1, 1700000000, 60)
	if err == nil {
		t.Fatal("expected address/key mismatch error")
	}
}
