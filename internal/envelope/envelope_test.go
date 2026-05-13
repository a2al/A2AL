// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package envelope_test

import (
	"errors"
	"testing"

	"github.com/a2al/a2al/internal/envelope"
)

func TestSealOpen_roundtrip(t *testing.T) {
	plain := []byte("operational-private-key-hex-abc123")
	sealed, err := envelope.Seal(plain, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !envelope.IsEnvelope(sealed) {
		t.Fatal("IsEnvelope false")
	}
	got, err := envelope.Open(sealed, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}

func TestOpen_wrongPassword(t *testing.T) {
	sealed, _ := envelope.Seal([]byte("secret"), "correct")
	_, err := envelope.Open(sealed, "wrong")
	if !errors.Is(err, envelope.ErrWrongPassword) {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestIsEnvelope_negative(t *testing.T) {
	for _, s := range []string{"", "plaintext", `{"other":"json"}`} {
		if envelope.IsEnvelope(s) {
			t.Fatalf("expected false for %q", s)
		}
	}
}

func TestSeal_deterministicSalt(t *testing.T) {
	// Two seals of the same data must produce different ciphertexts (random salt/iv).
	a, _ := envelope.Seal([]byte("x"), "pw")
	b, _ := envelope.Seal([]byte("x"), "pw")
	if a == b {
		t.Fatal("two seals produced identical output (salt/iv not random)")
	}
}
