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
	want := Hash("chat.invite", from, to, 42, nonce)
	if Hash("acl.join", from, to, 42, nonce) == want {
		t.Fatal("purpose must bind")
	}
	if Hash("chat.invite", to, from, 42, nonce) == want {
		t.Fatal("from/to must bind")
	}
}

func TestVerify_matchesHash(t *testing.T) {
	var from, to a2al.Address
	from[0], to[0] = 1, 2
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	cases := []struct {
		purpose string
		a, b    a2al.Address
		ts      int64
	}{
		{"chat.invite", from, to, 42},
		{"acl.join", from, to, 42},
		{"chat.invite", to, from, 42},
		{"chat.invite", from, to, 43},
	}
	for _, c := range cases {
		got := Verify(c.purpose, c.a, c.b, c.ts, nonce, DefaultBits)
		n := LeadingZeros(Hash(c.purpose, c.a, c.b, c.ts, nonce))
		if got != (n >= DefaultBits) {
			t.Fatalf("%s zeros=%d Verify=%v", c.purpose, n, got)
		}
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
