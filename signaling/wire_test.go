// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package signaling

import "testing"

func TestFrameRoundTrip_cred(t *testing.T) {
	f := Frame{T: "cred", U: "myufrag", P: "mypwd"}
	b, err := EncodeFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.T != "cred" || got.U != "myufrag" || got.P != "mypwd" {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestFrameRoundTrip_cand(t *testing.T) {
	f := Frame{T: "cand", C: "candidate:1 1 UDP 2122194687 192.168.1.1 5000 typ host"}
	b, err := EncodeFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.T != "cand" || got.C != f.C {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestFrameRoundTrip_eoc(t *testing.T) {
	f := Frame{T: "eoc"}
	b, err := EncodeFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.T != "eoc" {
		t.Fatalf("mismatch: %+v", got)
	}
}
