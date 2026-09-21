// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"io"
	"testing"

	"github.com/a2al/a2al"
)

func TestSendDialerMsgsHintOnly(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		_ = sendDialerMsgs(pw, a2al.Address{1}, 7)
	}()
	held, tok, err := readDialerMsgs(pr)
	if err != nil {
		t.Fatal(err)
	}
	if held != 7 || tok != "" {
		t.Fatalf("held=%d tok=%q", held, tok)
	}
}

func TestSendAcceptorMsgsAdvertisesServiceStream(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		_ = sendAcceptorMsgs(pw, nil, nil, 0)
	}()
	_, _, caps, err := readAcceptorMsgs(pr)
	if err != nil {
		t.Fatal(err)
	}
	if !caps.Service {
		t.Fatal("want 0x06 ServiceStream")
	}
	if !caps.Envelope {
		t.Fatal("want 0x08 EnvelopeStream")
	}
}

func TestReadAcceptorMsgsSkipsUnknownWithoutServiceStream(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		_ = writeCtrlMsg(pw, 0x99, []byte("x"))
		_ = pw.Close()
	}()
	_, _, caps, err := readAcceptorMsgs(pr)
	if err != nil {
		t.Fatal(err)
	}
	if caps.Service {
		t.Fatal("want no ServiceStream without 0x06")
	}
	if caps.Envelope {
		t.Fatal("want no EnvelopeStream without 0x08")
	}
}
