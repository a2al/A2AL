// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"testing"
)

func TestEIP191_signRecover(t *testing.T) {
	priv, err := GenerateSecp256k1PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := "hello a2al"
	sig, err := SignEIP191(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	want, err2 := EthPubKeyToAddress20(priv.PubKey())
	if err2 != nil {
		t.Fatal(err2)
	}
	if err := VerifyEIP191Signature(want, msg, sig); err != nil {
		t.Fatal(err)
	}
	if VerifyEIP191Signature([20]byte{1}, msg, sig) == nil {
		t.Fatal("expected wrong address to fail")
	}
}
