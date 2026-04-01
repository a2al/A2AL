// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"testing"
)

func TestCompactMessage_roundTrip(t *testing.T) {
	priv, err := GenerateSecp256k1PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := "hello paralism delegation"
	sig, err := SignCompactMessage(priv, msg, true)
	if err != nil {
		t.Fatal(err)
	}
	addr20, err := Secp256k1PubKeyToHash160(priv.PubKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCompactMessageSignature(addr20, msg, sig); err != nil {
		t.Fatal(err)
	}
	if VerifyCompactMessageSignature(addr20, "wrong", sig) == nil {
		t.Fatal("expected fail on wrong message")
	}
}
