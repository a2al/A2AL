// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package chat

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/a2al/a2al/internal/pow"
	"github.com/a2al/a2al/protocol"
)

func TestWire_inviteRoundtripAndPow(t *testing.T) {
	from, to := addr(1), addr(2)
	ts := time.Now().Unix()
	nonce, err := pow.Solve(context.Background(), PurposeInvite, from, to, ts, pow.DefaultBits)
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeInvite(Invite{TS: ts, Nonce: NonceB64(nonce), Bits: pow.DefaultBits, Note: strings.Repeat("你", NoteMaxRunes+10)})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := DecodeInvite(body)
	if err != nil {
		t.Fatal(err)
	}
	if got := []rune(inv.Note); len(got) != NoteMaxRunes {
		t.Fatalf("note runes %d", len(got))
	}
	if !VerifyInvite(from, to, inv, ts) {
		t.Fatal("pow")
	}
	if VerifyInvite(from, to, inv, ts+int64(PowMaxAge.Seconds())+10) {
		t.Fatal("stale")
	}
}

func TestWire_msgSizeAndAuthor(t *testing.T) {
	m := Msg{Seq: 1, TS: 1, K: MsgText, Body: "hi"}
	b, err := EncodeMsg(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeMsg(b)
	if err != nil || got.Body != "hi" {
		t.Fatal(err)
	}
	huge := Msg{Seq: 1, TS: 1, K: MsgText, Body: strings.Repeat("x", protocol.MaxEnvelopeInner)}
	if _, err := EncodeMsg(huge); err != ErrTooLarge {
		t.Fatalf("err=%v", err)
	}
	peer := addr(3)
	if _, err := RecFromMsg(Msg{Seq: 1, TS: 1, K: MsgText, Author: addr(4).String()}, peer); err == nil {
		t.Fatal("author mismatch")
	}
}
