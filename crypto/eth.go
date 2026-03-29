// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Keccak256 returns the Keccak-256 hash (Ethereum precompile, not SHA3-256).
func Keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(b)
	out := make([]byte, 0, 32)
	return h.Sum(out)
}

// EthPubKeyToAddress20 derives the 20-byte Ethereum address from an uncompressed secp256k1 public key.
func EthPubKeyToAddress20(pub *secp256k1.PublicKey) ([20]byte, error) {
	if pub == nil {
		return [20]byte{}, errors.New("a2al/crypto: nil secp256k1 public key")
	}
	unc := pub.SerializeUncompressed()
	if len(unc) != 65 || unc[0] != 0x04 {
		return [20]byte{}, errors.New("a2al/crypto: invalid uncompressed public key")
	}
	h := Keccak256(unc[1:])
	var out [20]byte
	copy(out[:], h[12:])
	return out, nil
}

// EIP191Hash is Keccak256("\x19Ethereum Signed Message:\n" + len + message) per EIP-191.
func EIP191Hash(message string) []byte {
	prefix := "\x19Ethereum Signed Message:\n"
	m := strconv.Itoa(len(message))
	data := make([]byte, 0, len(prefix)+len(m)+len(message))
	data = append(data, prefix...)
	data = append(data, m...)
	data = append(data, message...)
	return Keccak256(data)
}

// SignEIP191 signs message with Ethereum personal_sign semantics. Returns 65-byte r||s||v (v ∈ {27,28}).
func SignEIP191(priv *secp256k1.PrivateKey, message string) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("a2al/crypto: nil secp256k1 private key")
	}
	hash := EIP191Hash(message)
	compact := ecdsa.SignCompact(priv, hash, false)
	if len(compact) != 65 {
		return nil, errors.New("a2al/crypto: unexpected compact signature size")
	}
	out := make([]byte, 65)
	copy(out[0:32], compact[1:33])
	copy(out[32:64], compact[33:65])
	out[64] = compact[0]
	return out, nil
}

// RecoverEthereumPubKey recovers the signer public key from an EIP-191 signature (r||s||v, v=27|28).
func RecoverEthereumPubKey(message string, sig65 []byte) (*secp256k1.PublicKey, error) {
	if len(sig65) != 65 {
		return nil, fmt.Errorf("a2al/crypto: want 65-byte signature, got %d", len(sig65))
	}
	v := sig65[64]
	// Normalize v: some wallets (e.g. Ledger certain firmware) return v ∈ {0,1} instead of {27,28}.
	if v < 27 {
		v += 27
	}
	if v != 27 && v != 28 {
		return nil, fmt.Errorf("a2al/crypto: invalid recovery id %d", v)
	}
	compact := make([]byte, 65)
	compact[0] = v
	copy(compact[1:33], sig65[0:32])
	copy(compact[33:65], sig65[32:64])
	hash := EIP191Hash(message)
	pub, _, err := ecdsa.RecoverCompact(compact, hash)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// VerifyEIP191Signature checks that sig is a valid personal_sign for message from addr20.
func VerifyEIP191Signature(addr20 [20]byte, message string, sig65 []byte) error {
	pub, err := RecoverEthereumPubKey(message, sig65)
	if err != nil {
		return err
	}
	got, err2 := EthPubKeyToAddress20(pub)
	if err2 != nil {
		return err2
	}
	if got != addr20 {
		return errors.New("a2al/crypto: ecrecover address mismatch")
	}
	return nil
}
