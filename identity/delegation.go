// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package identity holds Phase 3 delegation proofs (master → operational key).
package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/fxamacker/cbor/v2"
)

const signPrefix = "a2al-del\x00"

// ScopeNetworkOps is the only delegation scope in Phase 3 (QUIC/DHT signing).
const ScopeNetworkOps uint8 = 1

var (
	delCanonical cbor.EncMode

	// ErrInvalidDelegation is returned when structure, signature, or key binding fails.
	ErrInvalidDelegation = errors.New("a2al/identity: invalid delegation proof")
)

func init() {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	delCanonical = em
}

// delegationSignFields is the signed CBOR map (keys 1–6).
type delegationSignFields struct {
	MasterPub []byte `cbor:"1,keyasint"`
	OpPub     []byte `cbor:"2,keyasint"`
	AgentAddr []byte `cbor:"3,keyasint"`
	IssuedAt  uint64 `cbor:"4,keyasint"`
	ExpiresAt uint64 `cbor:"5,keyasint"`
	Scope     uint8  `cbor:"6,keyasint"`
}

// DelegationProof is the full CBOR object including signature (key 7).
// Ethereum (and other blockchain) proofs omit MasterPub (key 1) and set Message (key 8).
type DelegationProof struct {
	MasterPub []byte `cbor:"1,keyasint,omitempty"`
	OpPub     []byte `cbor:"2,keyasint"`
	AgentAddr []byte `cbor:"3,keyasint"`
	IssuedAt  uint64 `cbor:"4,keyasint"`
	ExpiresAt uint64 `cbor:"5,keyasint"`
	Scope     uint8  `cbor:"6,keyasint"`
	Signature []byte `cbor:"7,keyasint"`
	Message   string `cbor:"8,keyasint,omitempty"`
}

// SignDelegation builds a proof: master authorizes op key for AID and scope.
// expiresAt 0 means no expiry. issuedAt is Unix seconds.
func SignDelegation(masterPriv ed25519.PrivateKey, opPub ed25519.PublicKey, aid a2al.Address, issuedAt, expiresAt uint64, scope uint8) (DelegationProof, error) {
	if len(masterPriv) != ed25519.PrivateKeySize {
		return DelegationProof{}, fmt.Errorf("%w: master private key", ErrInvalidDelegation)
	}
	if len(opPub) != ed25519.PublicKeySize {
		return DelegationProof{}, fmt.Errorf("%w: op public key", ErrInvalidDelegation)
	}
	masterPub := masterPriv.Public().(ed25519.PublicKey)
	wantAID, err := crypto.AddressFromPublicKey(masterPub)
	if err != nil {
		return DelegationProof{}, err
	}
	if wantAID != aid {
		return DelegationProof{}, fmt.Errorf("%w: AID does not match master pubkey", ErrInvalidDelegation)
	}
	fields := delegationSignFields{
		MasterPub: masterPub,
		OpPub:     opPub,
		AgentAddr: aid[:],
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Scope:     scope,
	}
	signBytes, err := delCanonical.Marshal(fields)
	if err != nil {
		return DelegationProof{}, err
	}
	msg := bytes.Join([][]byte{[]byte(signPrefix), signBytes}, nil)
	sig := ed25519.Sign(masterPriv, msg)
	return DelegationProof{
		MasterPub: masterPub,
		OpPub:     opPub,
		AgentAddr: aid[:],
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Scope:     scope,
		Signature: sig,
	}, nil
}

// EncodeDelegationProof encodes the full proof (including signature) to canonical CBOR.
func EncodeDelegationProof(p DelegationProof) ([]byte, error) {
	return delCanonical.Marshal(p)
}

// ParseDelegationProof decodes CBOR bytes into DelegationProof.
func ParseDelegationProof(b []byte) (DelegationProof, error) {
	var p DelegationProof
	if err := cbor.Unmarshal(b, &p); err != nil {
		return DelegationProof{}, err
	}
	if len(p.AgentAddr) != len(a2al.Address{}) {
		return DelegationProof{}, ErrInvalidDelegation
	}
	if len(p.OpPub) != ed25519.PublicKeySize {
		return DelegationProof{}, ErrInvalidDelegation
	}
	v := p.AgentAddr[0]
	switch v {
	case a2al.VersionEd25519:
		if len(p.MasterPub) != ed25519.PublicKeySize || len(p.Signature) != ed25519.SignatureSize {
			return DelegationProof{}, ErrInvalidDelegation
		}
		if p.Message != "" {
			return DelegationProof{}, ErrInvalidDelegation
		}
	case a2al.VersionEthereum:
		if len(p.MasterPub) != 0 {
			return DelegationProof{}, ErrInvalidDelegation
		}
		if len(p.Signature) != 65 || p.Message == "" {
			return DelegationProof{}, ErrInvalidDelegation
		}
	default:
		return DelegationProof{}, fmt.Errorf("%w: unsupported agent address version 0x%02x", ErrInvalidDelegation, v)
	}
	return p, nil
}

// VerifyDelegation checks the proof (Ed25519 master or Ethereum EIP-191) and optional op key binding.
func VerifyDelegation(p DelegationProof, nowUnix uint64, opPriv ed25519.PrivateKey) error {
	if len(p.AgentAddr) != len(a2al.Address{}) {
		return ErrInvalidDelegation
	}
	switch p.AgentAddr[0] {
	case a2al.VersionEthereum:
		return verifyEthereumDelegation(p, nowUnix, opPriv)
	default:
		return verifyEd25519Delegation(p, nowUnix, opPriv)
	}
}

func verifyEd25519Delegation(p DelegationProof, nowUnix uint64, opPriv ed25519.PrivateKey) error {
	if p.AgentAddr[0] != a2al.VersionEd25519 {
		return ErrInvalidDelegation
	}
	fields := delegationSignFields{
		MasterPub: p.MasterPub,
		OpPub:     p.OpPub,
		AgentAddr: p.AgentAddr,
		IssuedAt:  p.IssuedAt,
		ExpiresAt: p.ExpiresAt,
		Scope:     p.Scope,
	}
	signBytes, err := delCanonical.Marshal(fields)
	if err != nil {
		return err
	}
	msg := bytes.Join([][]byte{[]byte(signPrefix), signBytes}, nil)
	if !ed25519.Verify(p.MasterPub, msg, p.Signature) {
		return fmt.Errorf("%w: bad signature", ErrInvalidDelegation)
	}
	var aid a2al.Address
	copy(aid[:], p.AgentAddr)
	gotAID, err := crypto.AddressFromPublicKey(p.MasterPub)
	if err != nil || gotAID != aid {
		return fmt.Errorf("%w: AID/master mismatch", ErrInvalidDelegation)
	}
	if p.ExpiresAt != 0 && nowUnix >= p.ExpiresAt {
		return fmt.Errorf("%w: expired", ErrInvalidDelegation)
	}
	if p.Scope != ScopeNetworkOps {
		return fmt.Errorf("%w: unsupported scope", ErrInvalidDelegation)
	}
	if opPriv != nil {
		if len(opPriv) != ed25519.PrivateKeySize {
			return fmt.Errorf("%w: op private key", ErrInvalidDelegation)
		}
		if !bytes.Equal(opPriv.Public().(ed25519.PublicKey), p.OpPub) {
			return fmt.Errorf("%w: op key mismatch", ErrInvalidDelegation)
		}
	}
	return nil
}

// AgentAID returns the AID (master identity) embedded in the proof.
func (p DelegationProof) AgentAID() (a2al.Address, error) {
	if len(p.AgentAddr) != len(a2al.Address{}) {
		return a2al.Address{}, ErrInvalidDelegation
	}
	var a a2al.Address
	copy(a[:], p.AgentAddr)
	return a, nil
}
