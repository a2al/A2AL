// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// BuildParalismDelegationMessage returns the exact UTF-8 string for Bitcoin-style message signing (Phase 4 §6.5).
func BuildParalismDelegationMessage(opPub ed25519.PublicKey, aid a2al.Address, issuedAt, expiresAt uint64, scope uint8) string {
	var b strings.Builder
	b.WriteString("A2AL Delegation Authorization\n")
	b.WriteString("Authorize this Ed25519 key to operate on behalf of your Paralism address.\n\n")
	fmt.Fprintf(&b, "op_key:%x\n", opPub)
	fmt.Fprintf(&b, "agent:%s\n", aid.String())
	fmt.Fprintf(&b, "scope:%d\n", scope)
	fmt.Fprintf(&b, "issued_at:%d\n", issuedAt)
	fmt.Fprintf(&b, "expires_at:%d\n", expiresAt)
	return b.String()
}

func verifyParalismDelegation(p DelegationProof, nowUnix uint64, opPriv ed25519.PrivateKey) error {
	var aid a2al.Address
	copy(aid[:], p.AgentAddr)
	if aid[0] != a2al.VersionParalism {
		return ErrInvalidDelegation
	}
	var addr20 [20]byte
	copy(addr20[:], aid[1:])
	if err := crypto.VerifyCompactMessageSignature(addr20, p.Message, p.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDelegation, err)
	}
	mf, err := ParseDelegationMessageFields(p.Message)
	if err != nil {
		return fmt.Errorf("%w: message parse: %v", ErrInvalidDelegation, err)
	}
	opRaw, err := decodeOpKeyHex(mf.OpKeyHex)
	if err != nil || len(opRaw) != ed25519.PublicKeySize || !bytes.Equal(opRaw, p.OpPub) {
		return fmt.Errorf("%w: op_key mismatch", ErrInvalidDelegation)
	}
	agentAddr, err := a2al.ParseAddress(mf.Agent)
	if err != nil || agentAddr != aid {
		return fmt.Errorf("%w: agent mismatch", ErrInvalidDelegation)
	}
	if mf.Scope != p.Scope || mf.IssuedAt != p.IssuedAt || mf.Expires != p.ExpiresAt {
		return fmt.Errorf("%w: message/proof field mismatch", ErrInvalidDelegation)
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

// SignParalismDelegation builds a Paralism DelegationProof (local key; compressed pubkey address).
func SignParalismDelegation(btcPriv *secp256k1.PrivateKey, opPub ed25519.PublicKey, aid a2al.Address, issuedAt, expiresAt uint64, scope uint8) (DelegationProof, error) {
	if btcPriv == nil {
		return DelegationProof{}, fmt.Errorf("%w: nil secp256k1 key", ErrInvalidDelegation)
	}
	if aid[0] != a2al.VersionParalism {
		return DelegationProof{}, fmt.Errorf("%w: AID must be Paralism version", ErrInvalidDelegation)
	}
	got, err := crypto.Secp256k1PubKeyToHash160(btcPriv.PubKey(), true)
	if err != nil {
		return DelegationProof{}, err
	}
	var want [20]byte
	copy(want[:], aid[1:])
	if got != want {
		return DelegationProof{}, fmt.Errorf("%w: AID does not match private key", ErrInvalidDelegation)
	}
	msg := BuildParalismDelegationMessage(opPub, aid, issuedAt, expiresAt, scope)
	sig, err := crypto.SignCompactMessage(btcPriv, msg, true)
	if err != nil {
		return DelegationProof{}, err
	}
	return DelegationProof{
		MasterPub: nil,
		OpPub:     opPub,
		AgentAddr: aid[:],
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Scope:     scope,
		Signature: sig,
		Message:   msg,
	}, nil
}

// ImportParalismDelegation builds a proof from an external Bitcoin-style message signature (65-byte compact).
func ImportParalismDelegation(sig []byte, message string, opPub ed25519.PublicKey, aid a2al.Address, issuedAt, expiresAt uint64, scope uint8) (DelegationProof, error) {
	if len(sig) != 65 {
		return DelegationProof{}, fmt.Errorf("%w: signature length", ErrInvalidDelegation)
	}
	if aid[0] != a2al.VersionParalism {
		return DelegationProof{}, fmt.Errorf("%w: AID must be Paralism version", ErrInvalidDelegation)
	}
	return DelegationProof{
		MasterPub: nil,
		OpPub:     opPub,
		AgentAddr: aid[:],
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Scope:     scope,
		Signature: append([]byte(nil), sig...),
		Message:   message,
	}, nil
}

// GenerateParalismIdentity creates random secp256k1 + Ed25519 op key and DelegationProof (expiresAt=0).
func GenerateParalismIdentity() (btcPriv *secp256k1.PrivateKey, opPriv ed25519.PrivateKey, proof DelegationProof, err error) {
	btcPriv, err = crypto.GenerateSecp256k1PrivateKey()
	if err != nil {
		return nil, nil, DelegationProof{}, err
	}
	_, opPriv, err = ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, DelegationProof{}, err
	}
	var aid a2al.Address
	aid[0] = a2al.VersionParalism
	addr20, err2 := crypto.Secp256k1PubKeyToHash160(btcPriv.PubKey(), true)
	if err2 != nil {
		return nil, nil, DelegationProof{}, err2
	}
	copy(aid[1:], addr20[:])
	now := uint64(time.Now().Unix())
	proof, err = SignParalismDelegation(btcPriv, opPriv.Public().(ed25519.PublicKey), aid, now, 0, ScopeNetworkOps)
	if err != nil {
		return nil, nil, DelegationProof{}, err
	}
	return btcPriv, opPriv, proof, nil
}
