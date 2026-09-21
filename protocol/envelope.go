// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MagicEnvelope identifies a QUIC stream carrying a data-plane envelope RPC.
const MagicEnvelope = "a2en"

const (
	MaxEnvelopeKind   = 64
	MaxEnvelopeInner  = 16 << 10
	maxEnvelopeKind   = MaxEnvelopeKind
	envelopeResultMax = 256
)

// Envelope result codes on the wire. Unknown codes are treated as denied.
const (
	EnvelopeOK          uint8 = 1
	EnvelopePending     uint8 = 2
	EnvelopeDenied      uint8 = 3
	EnvelopePowRequired uint8 = 4
	EnvelopeRetryLater  uint8 = 5
)

// NormalizeEnvelopeCode maps unknown codes to EnvelopeDenied.
func NormalizeEnvelopeCode(code uint8) uint8 {
	switch code {
	case EnvelopeOK, EnvelopePending, EnvelopeDenied, EnvelopePowRequired, EnvelopeRetryLater:
		return code
	default:
		return EnvelopeDenied
	}
}

// EncodeEnvelopeInner packs kind+body for the hot frame and mailbox 0x04.
//
//	[u8 kindLen][kind][u32 bodyLen][body]
func EncodeEnvelopeInner(kind string, body []byte) ([]byte, error) {
	if kind == "" || len(kind) > maxEnvelopeKind {
		return nil, fmt.Errorf("envelope: bad kind length %d", len(kind))
	}
	if len(body) > MaxEnvelopeInner {
		return nil, fmt.Errorf("envelope: body too large (%d bytes)", len(body))
	}
	out := make([]byte, 1+len(kind)+4+len(body))
	out[0] = byte(len(kind))
	copy(out[1:], kind)
	binary.BigEndian.PutUint32(out[1+len(kind):], uint32(len(body)))
	copy(out[1+len(kind)+4:], body)
	if len(out) > MaxEnvelopeInner {
		return nil, fmt.Errorf("envelope: inner too large (%d bytes)", len(out))
	}
	return out, nil
}

// SplitEnvelopeInner unpacks EncodeEnvelopeInner.
func SplitEnvelopeInner(p []byte) (kind string, body []byte, err error) {
	if len(p) < 5 {
		return "", nil, fmt.Errorf("envelope: inner too short")
	}
	klen := int(p[0])
	if klen == 0 || klen > maxEnvelopeKind || len(p) < 1+klen+4 {
		return "", nil, fmt.Errorf("envelope: bad kind")
	}
	kind = string(p[1 : 1+klen])
	blen := binary.BigEndian.Uint32(p[1+klen:])
	rest := p[1+klen+4:]
	if uint32(len(rest)) != blen {
		return "", nil, fmt.Errorf("envelope: body length mismatch")
	}
	if len(p) > MaxEnvelopeInner {
		return "", nil, fmt.Errorf("envelope: inner too large")
	}
	body = rest
	return kind, body, nil
}

// WriteEnvelopeFrame writes magic + inner to w.
func WriteEnvelopeFrame(w io.Writer, kind string, body []byte) error {
	inner, err := EncodeEnvelopeInner(kind, body)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, MagicEnvelope); err != nil {
		return err
	}
	_, err = w.Write(inner)
	return err
}

// ReadEnvelopeFrameBody reads inner after the 4-byte magic has been consumed.
func ReadEnvelopeFrameBody(r io.Reader) (kind string, body []byte, err error) {
	var hdr [1]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", nil, fmt.Errorf("envelope: kind len: %w", err)
	}
	klen := int(hdr[0])
	if klen == 0 || klen > maxEnvelopeKind {
		return "", nil, fmt.Errorf("envelope: bad kind length %d", klen)
	}
	kbuf := make([]byte, klen)
	if _, err := io.ReadFull(r, kbuf); err != nil {
		return "", nil, fmt.Errorf("envelope: kind: %w", err)
	}
	var blenBuf [4]byte
	if _, err := io.ReadFull(r, blenBuf[:]); err != nil {
		return "", nil, fmt.Errorf("envelope: body len: %w", err)
	}
	blen := binary.BigEndian.Uint32(blenBuf[:])
	if int(blen) > MaxEnvelopeInner {
		return "", nil, fmt.Errorf("envelope: body too large (%d bytes)", blen)
	}
	var b []byte
	if blen > 0 {
		b = make([]byte, blen)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", nil, fmt.Errorf("envelope: body: %w", err)
		}
	}
	innerLen := 1 + klen + 4 + int(blen)
	if innerLen > MaxEnvelopeInner {
		return "", nil, fmt.Errorf("envelope: inner too large")
	}
	return string(kbuf), b, nil
}

// WriteEnvelopeResult writes a coarse code and optional extra (e.g. PoW bits).
func WriteEnvelopeResult(w io.Writer, code uint8, extra []byte) error {
	code = NormalizeEnvelopeCode(code)
	if len(extra) > envelopeResultMax {
		return fmt.Errorf("envelope: extra too large")
	}
	var hdr [3]byte
	hdr[0] = code
	binary.BigEndian.PutUint16(hdr[1:], uint16(len(extra)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(extra) == 0 {
		return nil
	}
	_, err := w.Write(extra)
	return err
}

// ReadEnvelopeResult reads the result frame. Unknown codes become denied.
func ReadEnvelopeResult(r io.Reader) (code uint8, extra []byte, err error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("envelope: result hdr: %w", err)
	}
	code = NormalizeEnvelopeCode(hdr[0])
	n := binary.BigEndian.Uint16(hdr[1:])
	if n > envelopeResultMax {
		return 0, nil, fmt.Errorf("envelope: extra too large")
	}
	if n == 0 {
		return code, nil, nil
	}
	extra = make([]byte, n)
	if _, err := io.ReadFull(r, extra); err != nil {
		return 0, nil, fmt.Errorf("envelope: extra: %w", err)
	}
	return code, extra, nil
}
