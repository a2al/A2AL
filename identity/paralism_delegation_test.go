// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func buildParalismTestFixture(t *testing.T) (a2al.Address, *secp256k1.PrivateKey, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	btcPriv, err := crypto.GenerateSecp256k1PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	opPub, opPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var aid a2al.Address
	aid[0] = a2al.VersionParalism
	a20, err := crypto.Secp256k1PubKeyToHash160(btcPriv.PubKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	copy(aid[1:], a20[:])
	return aid, btcPriv, opPub, opPriv
}

func TestParalismDelegation_roundTrip(t *testing.T) {
	aid, btcPriv, opPub, opPriv := buildParalismTestFixture(t)
	now := uint64(time.Now().Unix())
	p, err := SignParalismDelegation(btcPriv, opPub, aid, now, 0, ScopeNetworkOps)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeDelegationProof(p)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := ParseDelegationProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegation(p2, now+1, opPriv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegation(p2, now+1, nil); err != nil {
		t.Fatal(err)
	}
}

func TestParalismDelegation_import(t *testing.T) {
	aid, btcPriv, opPub, opPriv := buildParalismTestFixture(t)
	now := uint64(time.Now().Unix())
	msg := BuildParalismDelegationMessage(opPub, aid, now, 0, ScopeNetworkOps)
	sig, err := crypto.SignCompactMessage(btcPriv, msg, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ImportParalismDelegation(sig, msg, opPub, aid, now, 0, ScopeNetworkOps)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegation(p, now, opPriv); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateParalismIdentity(t *testing.T) {
	btcPriv, opPriv, proof, err := GenerateParalismIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if btcPriv == nil || len(opPriv) != ed25519.PrivateKeySize {
		t.Fatal("bad keys")
	}
	now := uint64(time.Now().Unix())
	if err := VerifyDelegation(proof, now, opPriv); err != nil {
		t.Fatal(err)
	}
}

func TestParalismDelegation_expired(t *testing.T) {
	aid, btcPriv, opPub, opPriv := buildParalismTestFixture(t)
	now := uint64(1000)
	p, err := SignParalismDelegation(btcPriv, opPub, aid, now, now+10, ScopeNetworkOps)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegation(p, now+5, opPriv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegation(p, now+10, opPriv); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestParalismDelegation_opKeyMismatch(t *testing.T) {
	aid, btcPriv, opPub, _ := buildParalismTestFixture(t)
	now := uint64(time.Now().Unix())
	p, err := SignParalismDelegation(btcPriv, opPub, aid, now, 0, ScopeNetworkOps)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongOpPriv, _ := ed25519.GenerateKey(nil)
	if err := VerifyDelegation(p, now+1, wrongOpPriv); err == nil {
		t.Fatal("expected op key mismatch error")
	}
}
