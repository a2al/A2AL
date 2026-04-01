// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package a2al

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

func TestNodeIDFromAddress_deterministic(t *testing.T) {
	var addr Address
	addr[0] = VersionEd25519
	copy(addr[1:], bytes.Repeat([]byte{0xab}, 20))
	id1 := NodeIDFromAddress(addr)
	id2 := NodeIDFromAddress(addr)
	if id1 != id2 {
		t.Fatal("NodeID not deterministic")
	}
	var manual [32]byte
	var input [21]byte
	copy(input[:], addr[:])
	manual = sha256.Sum256(input[:])
	if id1 != manual {
		t.Fatalf("NodeID mismatch: got %x want %x", id1[:], manual[:])
	}
}

func TestDistance_symmetric(t *testing.T) {
	var a, b NodeID
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(255 - i)
	}
	dab := Distance(a, b)
	dba := Distance(b, a)
	if dab != dba {
		t.Fatal("XOR distance not symmetric")
	}
	var zero NodeID
	if Distance(zero, zero) != zero {
		t.Fatal("self-distance not zero")
	}
}

func TestCommonPrefixLen(t *testing.T) {
	var a, b NodeID
	if CommonPrefixLen(a, b) != 256 {
		t.Fatal("identical IDs should have CPL 256")
	}
	a[0] = 0x80
	b[0] = 0x00
	if CommonPrefixLen(a, b) != 0 {
		t.Fatalf("want CPL 0, got %d", CommonPrefixLen(a, b))
	}
	a[0] = 0x40
	b[0] = 0x00
	if CommonPrefixLen(a, b) != 1 {
		t.Fatalf("want CPL 1, got %d", CommonPrefixLen(a, b))
	}
}

func TestAddressString_roundTrip(t *testing.T) {
	var addr Address
	addr[0] = VersionEd25519
	copy(addr[1:], bytes.Repeat([]byte{0xcd}, 20))
	s := addr.String()
	if len(s) != nativeHexLen {
		t.Fatalf("len %d", len(s))
	}
	back, err := ParseAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	if back != addr {
		t.Fatalf("round trip: got %x want %x", back[:], addr[:])
	}
}

func TestParseAddress_lowercaseAccepted(t *testing.T) {
	lower := strings.ToLower("A0" + strings.Repeat("cd", 20))
	addr, err := ParseAddress(lower)
	if err != nil {
		t.Fatal(err)
	}
	if addr[0] != VersionEd25519 {
		t.Fatal(addr[0])
	}
}

func TestParseAddress_badChecksum(t *testing.T) {
	var addr Address
	addr[0] = VersionEd25519
	copy(addr[1:], bytes.Repeat([]byte{0xef}, 20))
	good := addr.String()
	// flip case on one letter that should be lower
	bad := []byte(good)
	for i, c := range bad {
		if c >= 'A' && c <= 'F' {
			bad[i] = c - 'A' + 'a'
			break
		}
	}
	_, err := ParseAddress(string(bad))
	if err == nil {
		t.Fatal("expected error for bad checksum")
	}
}

func TestParseAddress_paralism_p2pkh_base58(t *testing.T) {
	var h [20]byte
	copy(h[:], bytes.Repeat([]byte{0x01}, 20))
	addrStr := base58.CheckEncode(h[:], paralismP2PKHVersionByte)
	addr, err := ParseAddress(addrStr)
	if err != nil {
		t.Fatal(err)
	}
	if addr[0] != VersionParalism {
		t.Fatalf("want VersionParalism, got 0x%02x", addr[0])
	}
	var got [20]byte
	copy(got[:], addr[1:])
	if got != h {
		t.Fatalf("hash mismatch: got %x want %x", got, h)
	}
	// Format produces bech32 (bc1q...) as preferred output.
	if !strings.HasPrefix(addr.String(), "bc1") {
		t.Fatalf("format: %s", addr.String())
	}
}

func TestParseAddress_paralism_bech32_bc_pr_sameAID(t *testing.T) {
	var h [20]byte
	copy(h[:], bytes.Repeat([]byte{0x42}, 20))
	witness := append([]byte{0x00}, h[:]...)
	sbc, err := bech32.EncodeFromBase256("bc", witness)
	if err != nil {
		t.Fatal(err)
	}
	spr, err := bech32.EncodeFromBase256("pr", witness)
	if err != nil {
		t.Fatal(err)
	}
	addrBC, err := ParseAddress(sbc)
	if err != nil {
		t.Fatal(err)
	}
	if addrBC[0] != VersionParalism {
		t.Fatal(addrBC[0])
	}
	addrPR, err := ParseAddress(spr)
	if err != nil {
		t.Fatal(err)
	}
	if addrBC != addrPR {
		t.Fatalf("bc vs pr: %x vs %x", addrBC[:], addrPR[:])
	}
	if !strings.HasPrefix(addrBC.String(), "bc1") {
		t.Fatalf("format: %s", addrBC.String())
	}
}

func TestParseAddress_ethereum_roundTrip(t *testing.T) {
	// Known test vector: all-zero address (valid checksum is lowercase only)
	var addr Address
	addr[0] = VersionEthereum
	s := addr.String()
	if s[:2] != "0x" || len(s) != 42 {
		t.Fatalf("ethereum string: %q", s)
	}
	back, err := ParseAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	if back != addr {
		t.Fatalf("got %v want %v", back, addr)
	}
}

func TestParseAddress_invalidVersion(t *testing.T) {
	raw := make([]byte, 21)
	raw[0] = 0x99
	s := hex.EncodeToString(raw)
	_, err := ParseAddress(s)
	if err == nil {
		t.Fatal("expected error")
	}
}
