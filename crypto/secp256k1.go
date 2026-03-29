// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160"
)

// GenerateSecp256k1PrivateKey creates a random secp256k1 private key.
func GenerateSecp256k1PrivateKey() (*secp256k1.PrivateKey, error) {
	return secp256k1.GeneratePrivateKey()
}

// compactSignMessageMagic is the signed-message prefix used by Bitcoin-compatible chains (Paralism included).
// The value is fixed by the interoperability protocol and must not change.
const compactSignMessageMagic = "Bitcoin Signed Message:\n"

// CompactSignedMessageHash returns double-SHA256 of the varint-prefixed magic + message,
// matching the Bitcoin Core / Paralism signmessage format.
func CompactSignedMessageHash(message string) []byte {
	var buf bytes.Buffer
	_ = wire.WriteVarString(&buf, 0, compactSignMessageMagic)
	_ = wire.WriteVarString(&buf, 0, message)
	return chainhash.DoubleHashB(buf.Bytes())
}

// Hash160 returns RIPEMD160(SHA256(b)).
func Hash160(b []byte) [20]byte {
	h := sha256.Sum256(b)
	r := ripemd160.New()
	_, _ = r.Write(h[:])
	var out [20]byte
	copy(out[:], r.Sum(nil))
	return out
}

// Secp256k1PubKeyToHash160 returns HASH160 of the compressed or uncompressed secp256k1 pubkey serialization.
func Secp256k1PubKeyToHash160(pub *secp256k1.PublicKey, compressed bool) ([20]byte, error) {
	if pub == nil {
		return [20]byte{}, errors.New("a2al/crypto: nil secp256k1 public key")
	}
	var ser []byte
	if compressed {
		ser = pub.SerializeCompressed()
	} else {
		ser = pub.SerializeUncompressed()
	}
	return Hash160(ser), nil
}

// SignCompactMessage signs message using the Bitcoin/Paralism compact signmessage format.
// Returns a 65-byte compact signature (recovery||r||s).
func SignCompactMessage(priv *secp256k1.PrivateKey, message string, compressedPubKey bool) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("a2al/crypto: nil secp256k1 private key")
	}
	h := CompactSignedMessageHash(message)
	return ecdsa.SignCompact(priv, h, compressedPubKey), nil
}

// VerifyCompactMessageSignature verifies a compact signature against CompactSignedMessageHash(message)
// and checks that the recovered address matches addr20 (HASH160 of pubkey).
func VerifyCompactMessageSignature(addr20 [20]byte, message string, sig65 []byte) error {
	if len(sig65) != 65 {
		return fmt.Errorf("a2al/crypto: want 65-byte signature, got %d", len(sig65))
	}
	h := CompactSignedMessageHash(message)
	pub, wasCompressed, err := ecdsa.RecoverCompact(sig65, h)
	if err != nil {
		return err
	}
	got, err2 := Secp256k1PubKeyToHash160(pub, wasCompressed)
	if err2 != nil {
		return err2
	}
	if got != addr20 {
		return errors.New("a2al/crypto: compact message address mismatch")
	}
	return nil
}
