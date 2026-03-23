// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"github.com/a2al/a2al"
)

// KeyType identifies the asymmetric algorithm used for an Agent identity.
type KeyType byte

const (
	// KeyTypeEd25519 is the Phase 1 default (spec §6.1).
	KeyTypeEd25519 KeyType = 0x01
)

// PrivateKey is Ed25519 private key material (64 bytes, per crypto/ed25519).
type PrivateKey []byte

// KeyStore persists signing keys and performs signatures (spec §1.6).
type KeyStore interface {
	Generate(keyType KeyType) (PrivateKey, error)
	Sign(address a2al.Address, data []byte) ([]byte, error)
	PublicKey(address a2al.Address) ([]byte, error)
	List() ([]a2al.Address, error)
}
