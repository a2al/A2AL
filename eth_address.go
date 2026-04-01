// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package a2al

import (
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/sha3"
)

// ethereumCodec handles Ethereum "0x"/"0X" + 40 hex addresses with EIP-55 Keccak checksum.
type ethereumCodec struct{}

func (ethereumCodec) Version() byte { return VersionEthereum }

func (ethereumCodec) CanParse(s string) bool {
	return len(s) == 42 && (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X"))
}

func (ethereumCodec) Parse(s string) ([20]byte, error) {
	var z [20]byte
	if len(s) != 42 || !(strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) {
		return z, errors.New("invalid ethereum address")
	}
	hexPart := s[2:]
	for _, c := range hexPart {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return z, errors.New("invalid hex in ethereum address")
		}
	}
	lower := strings.ToLower(hexPart)
	raw, err := hex.DecodeString(lower)
	if err != nil || len(raw) != 20 {
		return z, errors.New("invalid ethereum address")
	}
	if hexPart != lower {
		var addr [20]byte
		copy(addr[:], raw)
		if s[2:] != ethEIP55Body(addr) {
			return z, errors.New("EIP-55 checksum mismatch")
		}
	}
	copy(z[:], raw)
	return z, nil
}

func (ethereumCodec) Format(addr20 [20]byte) string {
	return "0x" + ethEIP55Body(addr20)
}

// ethEIP55Body returns the 40-char mixed-case hex (without 0x prefix).
func ethEIP55Body(addr20 [20]byte) string {
	lower := hex.EncodeToString(addr20[:])
	h := ethKeccak256([]byte(lower))
	out := make([]byte, 0, 40)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c >= '0' && c <= '9' {
			out = append(out, c)
			continue
		}
		hashByte := h[i/2]
		var nib byte
		if i%2 == 0 {
			nib = hashByte >> 4
		} else {
			nib = hashByte & 0x0f
		}
		if nib >= 8 {
			out = append(out, c+'A'-'a')
		} else {
			out = append(out, c)
		}
	}
	return string(out)
}

func ethKeccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(b)
	out := make([]byte, 0, 32)
	return h.Sum(out)
}
