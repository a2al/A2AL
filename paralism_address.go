// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package a2al

import (
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// Paralism P2PKH / WIF use Bitcoin mainnet version bytes (Paralism node matches Bitcoin-style params).
const (
	paralismP2PKHVersionByte byte = 0x00
)

// ParalismBech32HRPs lists accepted Bech32 human-readable parts (extend for new Paralism HRPs).
var ParalismBech32HRPs = []string{"bc", "pr"}

// ParalismBech32PreferredHRP is used when formatting Address.String() for version Paralism.
var ParalismBech32PreferredHRP = "bc"

func paralismHRPAllowed(hrp string) bool {
	h := strings.ToLower(hrp)
	for _, x := range ParalismBech32HRPs {
		if h == strings.ToLower(x) {
			return true
		}
	}
	return false
}

type paralismCodec struct{}

func (paralismCodec) Version() byte { return VersionParalism }

func (paralismCodec) CanParse(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(strings.ToLower(s), "0x") {
		return false
	}
	ls := strings.ToLower(s)
	for _, hrp := range ParalismBech32HRPs {
		if strings.HasPrefix(ls, strings.ToLower(hrp)+"1") {
			return true
		}
	}
	// P2PKH mainnet Base58Check: starts with '1', typical length 26–34.
	// This is best-effort; Parse performs the authoritative checksum and version-byte check.
	if len(s) >= 26 && len(s) <= 35 && s[0] == '1' {
		return true
	}
	return false
}

func (paralismCodec) Parse(s string) ([20]byte, error) {
	s = strings.TrimSpace(s)
	ls := strings.ToLower(s)
	for _, hrp := range ParalismBech32HRPs {
		prefix := strings.ToLower(hrp) + "1"
		if strings.HasPrefix(ls, prefix) {
			return parseParalismBech32(s)
		}
	}
	return parseParalismP2PKHBase58(s)
}

func parseParalismBech32(s string) ([20]byte, error) {
	var z [20]byte
	hrp, data, err := bech32.DecodeToBase256(s)
	if err != nil {
		return z, err
	}
	if !paralismHRPAllowed(hrp) {
		return z, errors.New("invalid bech32 hrp for Paralism")
	}
	// Witness v0 P2WPKH: 1 byte version + 20-byte program
	if len(data) != 21 || data[0] != 0x00 {
		return z, errors.New("want witness v0 pubkey hash (20 bytes)")
	}
	copy(z[:], data[1:])
	return z, nil
}

func parseParalismP2PKHBase58(s string) ([20]byte, error) {
	var z [20]byte
	payload, version, err := base58.CheckDecode(s)
	if err != nil {
		return z, err
	}
	if version != paralismP2PKHVersionByte || len(payload) != 20 {
		return z, errors.New("invalid P2PKH address")
	}
	copy(z[:], payload)
	return z, nil
}

func (paralismCodec) Format(addr20 [20]byte) string {
	h := ParalismBech32PreferredHRP
	if !paralismHRPAllowed(h) {
		h = ParalismBech32HRPs[0]
	}
	witness := append([]byte{0x00}, addr20[:]...)
	out, err := bech32.EncodeFromBase256(h, witness)
	if err != nil {
		// Fallback: P2PKH Base58
		return base58.CheckEncode(addr20[:], paralismP2PKHVersionByte)
	}
	return out
}

// ParseParalismAddress parses a Paralism/Bitcoin-style address string into a VersionParalism Address.
func ParseParalismAddress(s string) (Address, error) {
	s = strings.TrimSpace(s)
	c := paralismCodec{}
	if !c.CanParse(s) {
		return Address{}, ErrInvalidAddress
	}
	raw, err := c.Parse(s)
	if err != nil {
		return Address{}, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	var out Address
	out[0] = VersionParalism
	copy(out[1:], raw[:])
	return out, nil
}
