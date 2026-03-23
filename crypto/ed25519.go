// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"github.com/a2al/a2al"
)

// AddressFromPublicKey derives the A2AL Address for an Ed25519 public key (spec §6.1).
func AddressFromPublicKey(pub ed25519.PublicKey) (a2al.Address, error) {
	if len(pub) != ed25519.PublicKeySize {
		return a2al.Address{}, errors.New("a2al/crypto: invalid ed25519 public key")
	}
	h := sha256.Sum256(pub)
	var a a2al.Address
	a[0] = a2al.VersionEd25519
	copy(a[1:], h[:20])
	return a, nil
}

// GenerateEd25519 returns a new Ed25519 key pair (private, public).
func GenerateEd25519() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// SignDetached signs message with the private key (Ed25519).
func SignDetached(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

// VerifyDetached verifies an Ed25519 signature.
func VerifyDetached(pub ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(pub, message, sig)
}
