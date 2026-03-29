// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/a2al/a2al/crypto"
)

func TestSignVerifyDelegation(t *testing.T) {
	mPub, mPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oPub, oPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := crypto.AddressFromPublicKey(mPub)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	p, err := SignDelegation(mPriv, oPub, aid, now, 0, ScopeNetworkOps)
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
	if err := VerifyDelegation(p2, now+1, oPriv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegation(p2, now+1, nil); err != nil {
		t.Fatal(err)
	}
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	if err := VerifyDelegation(p2, now+1, wrongPriv); err == nil {
		t.Fatal("expected op key mismatch")
	}
}

func TestDelegationExpiry(t *testing.T) {
	mPub, mPriv, _ := ed25519.GenerateKey(nil)
	oPub, oPriv, _ := ed25519.GenerateKey(nil)
	aid, _ := crypto.AddressFromPublicKey(mPub)
	now := uint64(1000)
	p, err := SignDelegation(mPriv, oPub, aid, now, now+10, ScopeNetworkOps)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegation(p, now+5, oPriv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegation(p, now+10, oPriv); err == nil {
		t.Fatal("expected expired")
	}
}
