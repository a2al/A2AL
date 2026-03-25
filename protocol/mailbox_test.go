// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/a2al/a2al/crypto"
)

func TestOpenMailboxRecord_wrongRecipient(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, privC, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addrA, _ := crypto.AddressFromPublicKey(pubA)
	addrB, _ := crypto.AddressFromPublicKey(pubB)
	addrC, _ := crypto.AddressFromPublicKey(privC.Public().(ed25519.PublicKey))

	payload, err := EncodeMailboxPayload(addrA, addrB, pubB, MailboxMsgText, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rec, err := SignRecord(privA, addrA, RecTypeMailbox, payload, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	// C is not the intended recipient — must fail.
	if _, err := OpenMailboxRecord(privC, addrC, rec); err == nil {
		t.Fatal("expected error for wrong recipient")
	}
}

func TestMailboxEncodeOpen_roundtrip(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addrA, err := crypto.AddressFromPublicKey(pubA)
	if err != nil {
		t.Fatal(err)
	}
	addrB, err := crypto.AddressFromPublicKey(pubB)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeMailboxPayload(addrA, addrB, pubB, MailboxMsgText, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rec, err := SignRecord(privA, addrA, RecTypeMailbox, payload, 1, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedRecord(rec, now); err != nil {
		t.Fatal(err)
	}
	msg, err := OpenMailboxRecord(privB, addrB, rec)
	if err != nil {
		t.Fatal(err)
	}
	if msg.MsgType != MailboxMsgText || string(msg.Body) != "hello" || msg.Sender != addrA {
		t.Fatalf("got %+v", msg)
	}
}
