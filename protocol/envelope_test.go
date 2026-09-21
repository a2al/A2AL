// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"bytes"
	"testing"
)

func TestEnvelopeInner_roundtrip(t *testing.T) {
	inner, err := EncodeEnvelopeInner("chat.invite", []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	kind, body, err := SplitEnvelopeInner(inner)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "chat.invite" || string(body) != "hi" {
		t.Fatalf("kind=%q body=%q", kind, body)
	}
}

func TestEnvelopeFrame_roundtrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteEnvelopeFrame(&buf, "chat.ding", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	if string(got[:4]) != MagicEnvelope {
		t.Fatalf("magic %q", got[:4])
	}
	kind, body, err := ReadEnvelopeFrameBody(bytes.NewReader(got[4:]))
	if err != nil {
		t.Fatal(err)
	}
	if kind != "chat.ding" || !bytes.Equal(body, []byte{1, 2, 3}) {
		t.Fatalf("kind=%q body=%x", kind, body)
	}
}

func TestNormalizeEnvelopeCode_unknownIsDenied(t *testing.T) {
	if NormalizeEnvelopeCode(0) != EnvelopeDenied {
		t.Fatal("0")
	}
	if NormalizeEnvelopeCode(9) != EnvelopeDenied {
		t.Fatal("9")
	}
	if NormalizeEnvelopeCode(EnvelopePending) != EnvelopePending {
		t.Fatal("pending")
	}
}

func TestEnvelopeResult_roundtrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteEnvelopeResult(&buf, EnvelopePowRequired, []byte{8}); err != nil {
		t.Fatal(err)
	}
	code, extra, err := ReadEnvelopeResult(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if code != EnvelopePowRequired || !bytes.Equal(extra, []byte{8}) {
		t.Fatalf("code=%d extra=%x", code, extra)
	}
}

func TestEncodeEnvelopeInner_rejectsEmptyKind(t *testing.T) {
	if _, err := EncodeEnvelopeInner("", nil); err == nil {
		t.Fatal("expected error")
	}
}
