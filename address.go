// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package a2al

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"strings"
)

const (
	// VersionEd25519 is the version byte for Ed25519-derived addresses (spec §6.1).
	VersionEd25519 byte = 0xA0
	// VersionP256 is reserved for P-256–derived addresses (spec §6.2).
	VersionP256 byte = 0xA1
	// VersionParalism is reserved for Paralism / Bitcoin HASH160 addresses (spec §6.2).
	VersionParalism byte = 0xA2
	// VersionEthereum is the version byte for Ethereum 20-byte addresses (spec §6.2).
	VersionEthereum byte = 0xA3
)

// Address is a 21-byte logical address: version byte + 20-byte hash (spec §6.1).
type Address [21]byte

// NodeID is a 256-bit DHT routing key (spec §6.1).
type NodeID [32]byte

// NodeIDFromAddress returns SHA-256(version_byte || hash_20bytes).
func NodeIDFromAddress(addr Address) NodeID {
	var b [1 + 20]byte
	b[0] = addr[0]
	copy(b[1:], addr[1:])
	return sha256.Sum256(b[:])
}

// Distance is the XOR metric d(A,B) = NodeID_A ⊕ NodeID_B (spec §3.3).
func Distance(a, b NodeID) NodeID {
	var d NodeID
	for i := range d {
		d[i] = a[i] ^ b[i]
	}
	return d
}

// CommonPrefixLen returns the number of leading bits where a and b agree (MSB first).
// If a == b, returns 256.
func CommonPrefixLen(a, b NodeID) int {
	x := Distance(a, b)
	for i := 0; i < len(x); i++ {
		if x[i] != 0 {
			return i*8 + bits.LeadingZeros8(x[i])
		}
	}
	return 256
}

// ---------------------------------------------------------------------------
// AddressCodec registry (spec §6.3 parsing priority)
// ---------------------------------------------------------------------------

// AddressCodec handles string↔internal conversion for one blockchain address type.
type AddressCodec interface {
	Version() byte
	CanParse(s string) bool
	Parse(s string) ([20]byte, error)
	Format(addr20 [20]byte) string
}

// chainCodecs: ordered list of chain-specific codecs. First CanParse match wins.
var chainCodecs = []AddressCodec{
	ethereumCodec{},
	paralismCodec{},
}

// codecByVersion maps version byte → chain codec (excludes native).
var codecByVersion map[byte]AddressCodec

func init() {
	codecByVersion = make(map[byte]AddressCodec, len(chainCodecs))
	for _, c := range chainCodecs {
		codecByVersion[c.Version()] = c
	}
}

// String returns the canonical display form, dispatched by version byte.
func (a Address) String() string {
	if c, ok := codecByVersion[a[0]]; ok {
		var raw [20]byte
		copy(raw[:], a[1:])
		return c.Format(raw)
	}
	return nativeFormatAddress(a)
}

// ParseAddress parses any supported address string (spec §6.3 priority order).
func ParseAddress(s string) (Address, error) {
	s = strings.TrimSpace(s)
	for _, c := range chainCodecs {
		if c.CanParse(s) {
			raw, err := c.Parse(s)
			if err != nil {
				return Address{}, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
			}
			var out Address
			out[0] = c.Version()
			copy(out[1:], raw[:])
			return out, nil
		}
	}
	// Fallback: A2AL native hex (multi-version catch-all)
	nc := nativeCodec{}
	if nc.CanParse(s) {
		return nativeParseFull(s)
	}
	return Address{}, ErrInvalidAddress
}

// ParseEthereumAddress is a convenience shortcut for Ethereum "0x" addresses.
func ParseEthereumAddress(s string) (Address, error) {
	s = strings.TrimSpace(s)
	c := ethereumCodec{}
	raw, err := c.Parse(s)
	if err != nil {
		return Address{}, ErrInvalidAddress
	}
	var out Address
	out[0] = VersionEthereum
	copy(out[1:], raw[:])
	return out, nil
}

// nativeParseFull parses a 42-char hex string and returns the full 21-byte Address
// (version byte is embedded in the hex, unlike chain codecs where version is fixed).
func nativeParseFull(s string) (Address, error) {
	nc := nativeCodec{}
	version, payload, err := nc.parseWithVersion(s)
	if err != nil {
		return Address{}, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	var out Address
	out[0] = version
	copy(out[1:], payload[:])
	return out, nil
}
