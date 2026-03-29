// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
)

func TestEthereumDelegation_roundTrip(t *testing.T) {
	ethPriv, err := crypto.GenerateSecp256k1PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, opPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var aid a2al.Address
	aid[0] = a2al.VersionEthereum
	addr20, err2 := crypto.EthPubKeyToAddress20(ethPriv.PubKey())
	if err2 != nil {
		t.Fatal(err2)
	}
	copy(aid[1:], addr20[:])
	now := uint64(time.Now().Unix())
	p, err := SignEthDelegation(ethPriv, opPriv.Public().(ed25519.PublicKey), aid, now, 0, ScopeNetworkOps)
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

func TestEthereumDelegation_import(t *testing.T) {
	ethPriv, err := crypto.GenerateSecp256k1PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, opPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var aid a2al.Address
	aid[0] = a2al.VersionEthereum
	addr20, err2 := crypto.EthPubKeyToAddress20(ethPriv.PubKey())
	if err2 != nil {
		t.Fatal(err2)
	}
	copy(aid[1:], addr20[:])
	now := uint64(time.Now().Unix())
	msg := BuildEthereumDelegationMessage(opPriv.Public().(ed25519.PublicKey), aid, now, 0, ScopeNetworkOps)
	sig, err := crypto.SignEIP191(ethPriv, msg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ImportBlockchainDelegation(sig, msg, opPriv.Public().(ed25519.PublicKey), aid, now, 0, ScopeNetworkOps)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegation(p, now, opPriv); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateEthereumIdentity(t *testing.T) {
	ethPriv, opPriv, proof, err := GenerateEthereumIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if ethPriv == nil || len(opPriv) != ed25519.PrivateKeySize {
		t.Fatal("bad keys")
	}
	now := uint64(time.Now().Unix())
	if err := VerifyDelegation(proof, now, opPriv); err != nil {
		t.Fatal(err)
	}
}
