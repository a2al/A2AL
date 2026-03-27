// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// BuildEthereumDelegationMessage returns the exact UTF-8 string for EIP-191 personal_sign (spec §6.3.1).
func BuildEthereumDelegationMessage(opPub ed25519.PublicKey, aid a2al.Address, issuedAt, expiresAt uint64, scope uint8) string {
	var b strings.Builder
	b.WriteString("A2AL Delegation Authorization\n")
	b.WriteString("Authorize this Ed25519 key to operate on behalf of your Ethereum address.\n\n")
	fmt.Fprintf(&b, "op_key:%x\n", opPub)
	fmt.Fprintf(&b, "agent:%s\n", aid.String())
	fmt.Fprintf(&b, "scope:%d\n", scope)
	fmt.Fprintf(&b, "issued_at:%d\n", issuedAt)
	fmt.Fprintf(&b, "expires_at:%d\n", expiresAt)
	return b.String()
}

// EthDelegationMessageFields are the structured lines from BuildEthereumDelegationMessage.
type EthDelegationMessageFields struct {
	OpKeyHex string
	Agent    string
	Scope    uint8
	IssuedAt uint64
	Expires  uint64
}

// ParseEthereumDelegationMessageFields parses key:value lines from a delegation message body.
func ParseEthereumDelegationMessageFields(msg string) (EthDelegationMessageFields, error) {
	var f EthDelegationMessageFields
	var seenOp, seenAgent, seenScope, seenIssued, seenExp bool
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "op_key":
			f.OpKeyHex = v
			seenOp = true
		case "agent":
			f.Agent = v
			seenAgent = true
		case "scope":
			sv, err := strconv.ParseUint(v, 10, 8)
			if err != nil {
				return f, err
			}
			f.Scope = uint8(sv)
			seenScope = true
		case "issued_at":
			u, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return f, err
			}
			f.IssuedAt = u
			seenIssued = true
		case "expires_at":
			u, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return f, err
			}
			f.Expires = u
			seenExp = true
		}
	}
	if !seenOp || !seenAgent || !seenScope || !seenIssued || !seenExp {
		return f, errors.New("a2al/identity: incomplete delegation message")
	}
	return f, nil
}

func decodeOpKeyHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

func verifyEthereumDelegation(p DelegationProof, nowUnix uint64, opPriv ed25519.PrivateKey) error {
	var aid a2al.Address
	copy(aid[:], p.AgentAddr)
	if aid[0] != a2al.VersionEthereum {
		return ErrInvalidDelegation
	}
	var addr20 [20]byte
	copy(addr20[:], aid[1:])
	if err := crypto.VerifyEIP191Signature(addr20, p.Message, p.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDelegation, err)
	}
	mf, err := ParseEthereumDelegationMessageFields(p.Message)
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

// SignEthDelegation builds an Ethereum DelegationProof (CLI/tests; production wallets sign externally).
func SignEthDelegation(ethPriv *secp256k1.PrivateKey, opPub ed25519.PublicKey, aid a2al.Address, issuedAt, expiresAt uint64, scope uint8) (DelegationProof, error) {
	if ethPriv == nil {
		return DelegationProof{}, fmt.Errorf("%w: nil eth key", ErrInvalidDelegation)
	}
	if aid[0] != a2al.VersionEthereum {
		return DelegationProof{}, fmt.Errorf("%w: AID must be Ethereum version", ErrInvalidDelegation)
	}
	got, err := crypto.EthPubKeyToAddress20(ethPriv.PubKey())
	if err != nil {
		return DelegationProof{}, err
	}
	if !bytes.Equal(got[:], aid[1:]) {
		return DelegationProof{}, fmt.Errorf("%w: AID does not match eth private key", ErrInvalidDelegation)
	}
	msg := BuildEthereumDelegationMessage(opPub, aid, issuedAt, expiresAt, scope)
	sig, err := crypto.SignEIP191(ethPriv, msg)
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

// ImportBlockchainDelegation builds a proof from an external wallet EIP-191 signature (65-byte r||s||v).
func ImportBlockchainDelegation(sig []byte, message string, opPub ed25519.PublicKey, aid a2al.Address, issuedAt, expiresAt uint64, scope uint8) (DelegationProof, error) {
	if len(sig) != 65 {
		return DelegationProof{}, fmt.Errorf("%w: signature length", ErrInvalidDelegation)
	}
	if aid[0] != a2al.VersionEthereum {
		return DelegationProof{}, fmt.Errorf("%w: AID must be Ethereum version", ErrInvalidDelegation)
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

// GenerateEthereumIdentity creates a random secp256k1 owner key, a new Ed25519 op key, and a DelegationProof (expiresAt=0).
func GenerateEthereumIdentity() (ethPriv *secp256k1.PrivateKey, opPriv ed25519.PrivateKey, proof DelegationProof, err error) {
	ethPriv, err = crypto.GenerateSecp256k1PrivateKey()
	if err != nil {
		return nil, nil, DelegationProof{}, err
	}
	_, opPriv, err = ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, DelegationProof{}, err
	}
	var aid a2al.Address
	aid[0] = a2al.VersionEthereum
	addr20, err2 := crypto.EthPubKeyToAddress20(ethPriv.PubKey())
	if err2 != nil {
		return nil, nil, DelegationProof{}, err2
	}
	copy(aid[1:], addr20[:])
	now := uint64(time.Now().Unix())
	proof, err = SignEthDelegation(ethPriv, opPriv.Public().(ed25519.PublicKey), aid, now, 0, ScopeNetworkOps)
	if err != nil {
		return nil, nil, DelegationProof{}, err
	}
	return ethPriv, opPriv, proof, nil
}
