// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package a2al

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const nativeHexLen = 42 // 21 bytes × 2

// nativeCodec handles A2AL native hex addresses (version 0xA0–0xAF, SHA-256 checksum).
type nativeCodec struct{}

func (nativeCodec) CanParse(s string) bool {
	if len(s) != nativeHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// parseWithVersion returns the version byte and the 20-byte payload separately,
// because native addresses encode the version inside the hex string itself.
func (nativeCodec) parseWithVersion(s string) (byte, [20]byte, error) {
	var z [20]byte
	if len(s) != nativeHexLen {
		return 0, z, fmt.Errorf("want %d hex chars", nativeHexLen)
	}
	lower := toLowerHex(s)
	raw, err := hex.DecodeString(lower)
	if err != nil || len(raw) != 21 {
		return 0, z, ErrInvalidAddress
	}
	if raw[0] < 0xA0 || raw[0] > 0xAF {
		return 0, z, ErrInvalidAddress
	}
	expected := nativeChecksumHex(lower)
	if s != expected && s != lower {
		return 0, z, ErrInvalidAddress
	}
	copy(z[:], raw[1:])
	return raw[0], z, nil
}

// nativeFormatAddress formats a full 21-byte native address with SHA-256 checksum.
func nativeFormatAddress(a Address) string {
	lower := fmt.Sprintf("%x", a[:])
	return nativeChecksumHex(lower)
}

func toLowerHex(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'F' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func nativeChecksumHex(lower string) string {
	h := sha256.Sum256([]byte(lower))
	out := make([]byte, 0, nativeHexLen)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c >= '0' && c <= '9' {
			out = append(out, c)
			continue
		}
		v := h[i/2]
		var nib byte
		if i%2 == 0 {
			nib = v >> 4
		} else {
			nib = v & 0x0f
		}
		if nib >= 8 {
			out = append(out, c-('a'-'A'))
		} else {
			out = append(out, c)
		}
	}
	return string(out)
}
