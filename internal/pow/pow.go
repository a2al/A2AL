// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package pow is the shared leading-zero SHA-256 work unit.
// purpose is only a label; bits are the cost. Not used in handshakes or DHT.
package pow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"github.com/a2al/a2al"
)

const (
	// Domain is the hash prefix. A trailing 0x00 separates it from purpose.
	Domain = "a2al-pow-v1"
	// DefaultBits is the system default difficulty. 0 means off.
	DefaultBits = 8
)

// Hash is SHA256(Domain || 0x00 || purpose || 0x00 || from || to || tsBE8 || nonce).
func Hash(purpose string, from, to a2al.Address, ts int64, nonce []byte) [32]byte {
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(ts))
	h := sha256.New()
	_, _ = h.Write([]byte(Domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(purpose))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(from[:])
	_, _ = h.Write(to[:])
	_, _ = h.Write(tsBuf[:])
	_, _ = h.Write(nonce)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// LeadingZeros returns the number of leading zero bits in sum.
func LeadingZeros(sum [32]byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				return n
			}
			n++
		}
	}
	return n
}

// Verify reports whether nonce meets bits for this (purpose, from, to, ts).
// bits <= 0 always succeeds (PoW off).
func Verify(purpose string, from, to a2al.Address, ts int64, nonce []byte, bits int) bool {
	if bits <= 0 {
		return true
	}
	return LeadingZeros(Hash(purpose, from, to, ts, nonce)) >= bits
}

// Solve searches for a nonce with at least bits leading zeros.
// bits <= 0 returns a nil nonce without hashing.
func Solve(ctx context.Context, purpose string, from, to a2al.Address, ts int64, bits int) ([]byte, error) {
	if bits <= 0 {
		return nil, nil
	}
	nonce := make([]byte, 8)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		if LeadingZeros(Hash(purpose, from, to, ts, nonce)) >= bits {
			out := make([]byte, len(nonce))
			copy(out, nonce)
			return out, nil
		}
	}
}
