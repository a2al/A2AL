// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

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

	inner, err := EncodeEnvelopeInner("chat.invite", []byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	payload, err = EncodeMailboxPayload(addrA, addrB, pubB, MailboxMsgEnvelope, inner)
	if err != nil {
		t.Fatal(err)
	}
	rec, err = SignRecord(privA, addrA, RecTypeMailbox, payload, 2, uint64(now.Unix()), 3600)
	if err != nil {
		t.Fatal(err)
	}
	msg, err = OpenMailboxRecord(privB, addrB, rec)
	if err != nil {
		t.Fatal(err)
	}
	if msg.MsgType != MailboxMsgEnvelope {
		t.Fatalf("msg_type %d", msg.MsgType)
	}
	kind, body, err := SplitEnvelopeInner(msg.Body)
	if err != nil || kind != "chat.invite" || string(body) != `{"n":1}` {
		t.Fatalf("envelope note kind=%q body=%q err=%v", kind, body, err)
	}
}

func TestMaxMailboxTextBody(t *testing.T) {
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addrA, _ := crypto.AddressFromPublicKey(pubA)
	addrB, _ := crypto.AddressFromPublicKey(pubB)
	lo, hi, best := 0, MaxMailboxPayloadCBOR, 0
	for lo <= hi {
		mid := (lo + hi) / 2
		body := make([]byte, mid)
		for i := range body {
			body[i] = 'a'
		}
		if _, err := EncodeMailboxPayload(addrA, addrB, pubB, MailboxMsgText, body); err != nil {
			hi = mid - 1
			continue
		}
		best = mid
		lo = mid + 1
	}
	if best != 389 {
		t.Fatalf("max note body %d bytes, want 389", best)
	}
}
