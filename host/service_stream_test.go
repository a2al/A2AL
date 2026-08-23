// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"bytes"
	"io"
	"testing"

	"github.com/a2al/a2al/protocol"
)

func TestServiceAdmissionRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteServiceAdmission(&buf, "room-pw"); err != nil {
		t.Fatal(err)
	}
	magic := make([]byte, 4)
	if _, err := io.ReadFull(&buf, magic); err != nil {
		t.Fatal(err)
	}
	if string(magic) != protocol.MagicServiceStream {
		t.Fatalf("magic=%q", magic)
	}
	tok, err := ReadServiceAdmission(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "room-pw" {
		t.Fatalf("tok=%q", tok)
	}
}

func TestServiceAdmissionEmptyToken(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteServiceAdmission(&buf, ""); err != nil {
		t.Fatal(err)
	}
	_, _ = buf.Read(make([]byte, 4))
	tok, err := ReadServiceAdmission(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		t.Fatalf("tok=%q", tok)
	}
}

func TestServiceAdmissionSkipsUnknownUntilKeysDone(t *testing.T) {
	var buf bytes.Buffer
	if _, err := io.WriteString(&buf, protocol.MagicServiceStream); err != nil {
		t.Fatal(err)
	}
	if err := writeCtrlMsg(&buf, 0x99, []byte("future-key")); err != nil {
		t.Fatal(err)
	}
	if err := writeCtrlMsg(&buf, ctrlMsgKeysDone, nil); err != nil {
		t.Fatal(err)
	}
	_, _ = buf.Read(make([]byte, 4))
	tok, err := ReadServiceAdmission(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		t.Fatalf("tok=%q", tok)
	}
}

func TestAccessResultRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteAccessResult(&buf, false, "denied"); err != nil {
		t.Fatal(err)
	}
	ok, reason, err := ReadAccessResult(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if ok || reason != "denied" {
		t.Fatalf("ok=%v reason=%q", ok, reason)
	}
}
