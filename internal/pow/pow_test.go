// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package pow

import (
	"context"
	"testing"
	"time"

	"github.com/a2al/a2al"
)

func TestVerify_zeroBitsAlwaysOK(t *testing.T) {
	var from, to a2al.Address
	from[0], to[0] = 1, 2
	if !Verify("chat.invite", from, to, 1, nil, 0) {
		t.Fatal("bits=0 must verify")
	}
}

func TestSolveVerify_roundtrip(t *testing.T) {
	var from, to a2al.Address
	from[0], to[0] = 1, 2
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nonce, err := Solve(ctx, "chat.invite", from, to, 42, DefaultBits)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify("chat.invite", from, to, 42, nonce, DefaultBits) {
		t.Fatal("solved nonce must verify")
	}
	if Verify("acl.join", from, to, 42, nonce, DefaultBits) {
		t.Fatal("different purpose must not verify")
	}
	if Verify("chat.invite", to, from, 42, nonce, DefaultBits) {
		t.Fatal("swapped AIDs must not verify")
	}
}

func TestLeadingZeros(t *testing.T) {
	var z [32]byte
	if LeadingZeros(z) != 256 {
		t.Fatalf("all-zero: %d", LeadingZeros(z))
	}
	z[0] = 0x0f
	if LeadingZeros(z) != 4 {
		t.Fatalf("0x0f: %d", LeadingZeros(z))
	}
}
