// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/a2al/a2al"
	acrypto "github.com/a2al/a2al/crypto"
	"github.com/fxamacker/cbor/v2"
)

const (
	recordSignPrefix = "a2al-rec\x00"
	// RecTypeEndpoint is the Phase 1 endpoint advertisement (spec §7.6).
	RecTypeEndpoint uint8 = 0x01

	// MaxEndpointSignalURLLen caps EndpointPayload.Signal (WebSocket ICE signaling base URL).
	MaxEndpointSignalURLLen = 2048
	// MaxTurnURLs caps EndpointPayload.Turns entry count (credential-free relay hints for DHT).
	MaxTurnURLs = 16
	// MaxTurnURLEntryLen caps each turn:// string length in Turns.
	MaxTurnURLEntryLen = 512
)

// NAT types for EndpointPayload (spec §7.6).
const (
	NATUnknown uint8 = iota
	NATFullCone
	NATRestricted
	NATPortRestricted
	NATSymmetric
)

var (
	recordCanonical cbor.EncMode

	// ErrInvalidRecord is returned when structure, signature, or address binding fails.
	ErrInvalidRecord = errors.New("a2al/protocol: invalid record")
	// ErrRecordExpired means now is past Timestamp+TTL (VerifySignedRecord).
	ErrRecordExpired = errors.New("a2al/protocol: record expired")
)

func init() {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	recordCanonical = em
}

// EndpointPayload is the CBOR inside SignedRecord.payload for rec_type=0x01 (spec §7.6).
type EndpointPayload struct {
	Endpoints []string `cbor:"1,keyasint"`
	NatType   uint8    `cbor:"2,keyasint"`
	// Signal is an optional WebSocket base URL for ICE trickle signaling (no query; room is appended by peers).
	Signal string `cbor:"3,keyasint,omitempty"`
	// Turns lists optional turn:// URLs without credentials (public relay hints).
	Turns []string `cbor:"4,keyasint,omitempty"`
}

// EndpointRecord is the decoded logical view (spec Step 4); no signature material.
type EndpointRecord struct {
	Address   a2al.Address
	Endpoints []string
	NatType   uint8
	Signal    string
	Turns     []string
	Timestamp uint64
	Seq       uint64
	TTL       uint32
}

// recordSignFields is the signed CBOR map (keys 1–6 only, spec §7.6).
type recordSignFields struct {
	Address   []byte `cbor:"1,keyasint"`
	RecType   uint8  `cbor:"2,keyasint"`
	Payload   []byte `cbor:"3,keyasint"`
	Seq       uint64 `cbor:"4,keyasint"`
	Timestamp uint64 `cbor:"5,keyasint"`
	TTL       uint32 `cbor:"6,keyasint"`
}

// SignEndpointRecord builds a SignedRecord for a self-signed endpoint advertisement.
// The signing key must derive the same Address as addr (Phase 1/2 path).
func SignEndpointRecord(priv ed25519.PrivateKey, addr a2al.Address, ep EndpointPayload, seq, timestamp uint64, ttl uint32) (SignedRecord, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignedRecord{}, fmt.Errorf("%w: private key", ErrInvalidRecord)
	}
	if ttl == 0 {
		return SignedRecord{}, fmt.Errorf("%w: ttl", ErrInvalidRecord)
	}
	want, err := acrypto.AddressFromPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedRecord{}, err
	}
	if want != addr {
		return SignedRecord{}, fmt.Errorf("%w: address/key mismatch", ErrInvalidRecord)
	}
	return buildEndpointRecord(priv, addr, ep, seq, timestamp, ttl, nil)
}

// SignEndpointRecordDelegated builds a SignedRecord where an operational key signs on behalf
// of a master-derived AID (Phase 3 delegation path).
// delegationCBOR is embedded verbatim in the record and will be verified by
// receivers via the RecordAuth policy injected into the DHT store.
// Callers must ensure delegationCBOR is a valid DelegationProof for addr authorized to opPriv.
func SignEndpointRecordDelegated(opPriv ed25519.PrivateKey, delegationCBOR []byte, addr a2al.Address, ep EndpointPayload, seq, timestamp uint64, ttl uint32) (SignedRecord, error) {
	if len(opPriv) != ed25519.PrivateKeySize {
		return SignedRecord{}, fmt.Errorf("%w: op private key", ErrInvalidRecord)
	}
	if ttl == 0 {
		return SignedRecord{}, fmt.Errorf("%w: ttl", ErrInvalidRecord)
	}
	if len(delegationCBOR) == 0 {
		return SignedRecord{}, fmt.Errorf("%w: delegation required", ErrInvalidRecord)
	}
	return buildEndpointRecord(opPriv, addr, ep, seq, timestamp, ttl, delegationCBOR)
}

// buildEndpointRecord is the shared signing implementation.
func buildEndpointRecord(priv ed25519.PrivateKey, addr a2al.Address, ep EndpointPayload, seq, timestamp uint64, ttl uint32, delegation []byte) (SignedRecord, error) {
	payloadCBOR, err := recordCanonical.Marshal(ep)
	if err != nil {
		return SignedRecord{}, err
	}
	return signRecordCore(priv, addr, RecTypeEndpoint, payloadCBOR, seq, timestamp, ttl, delegation)
}

func recTypeSignable(recType uint8) bool {
	return (recType >= 0x02 && recType <= 0x0f) ||
		(recType >= 0x10 && recType <= 0x1f) ||
		(recType >= 0x80 && recType <= 0x8f)
}

// SignRecord builds a signed record for RecType sovereign custom (0x02–0x0F), topic (0x10–0x1F), or mailbox (0x80–0x8F).
// payload must be CBOR-encoded bytes.
func SignRecord(priv ed25519.PrivateKey, addr a2al.Address, recType uint8, payload []byte, seq, timestamp uint64, ttl uint32) (SignedRecord, error) {
	if !recTypeSignable(recType) {
		return SignedRecord{}, fmt.Errorf("%w: unsupported RecType for SignRecord", ErrInvalidRecord)
	}
	if ttl == 0 {
		return SignedRecord{}, fmt.Errorf("%w: ttl", ErrInvalidRecord)
	}
	want, err := acrypto.AddressFromPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedRecord{}, err
	}
	if want != addr {
		return SignedRecord{}, fmt.Errorf("%w: address/key mismatch", ErrInvalidRecord)
	}
	return signRecordCore(priv, addr, recType, payload, seq, timestamp, ttl, nil)
}

// SignRecordDelegated is SignRecord with an operational key and DelegationProof.
func SignRecordDelegated(opPriv ed25519.PrivateKey, delegationCBOR []byte, addr a2al.Address, recType uint8, payload []byte, seq, timestamp uint64, ttl uint32) (SignedRecord, error) {
	if !recTypeSignable(recType) {
		return SignedRecord{}, fmt.Errorf("%w: unsupported RecType for SignRecordDelegated", ErrInvalidRecord)
	}
	if ttl == 0 {
		return SignedRecord{}, fmt.Errorf("%w: ttl", ErrInvalidRecord)
	}
	if len(delegationCBOR) == 0 {
		return SignedRecord{}, fmt.Errorf("%w: delegation required", ErrInvalidRecord)
	}
	return signRecordCore(opPriv, addr, recType, payload, seq, timestamp, ttl, delegationCBOR)
}

func signRecordCore(priv ed25519.PrivateKey, addr a2al.Address, recType uint8, payload []byte, seq, timestamp uint64, ttl uint32, delegation []byte) (SignedRecord, error) {
	fields := recordSignFields{
		Address:   addr[:],
		RecType:   recType,
		Payload:   payload,
		Seq:       seq,
		Timestamp: timestamp,
		TTL:       ttl,
	}
	signBytes, err := recordCanonical.Marshal(fields)
	if err != nil {
		return SignedRecord{}, err
	}
	msg := bytes.Join([][]byte{[]byte(recordSignPrefix), signBytes}, nil)
	sig := ed25519.Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	return SignedRecord{
		Address:    addr[:],
		RecType:    recType,
		Payload:    payload,
		Seq:        seq,
		Timestamp:  timestamp,
		TTL:        ttl,
		Pubkey:     pub,
		Signature:  sig,
		Delegation: delegation,
	}, nil
}

// VerifySignedRecord checks cryptographic integrity: signature validity, endpoint payload
// shape, and expiry. It does NOT enforce pubkey↔address authority (whether the signing
// key is allowed to publish for the given Address). Authority is a deployment policy;
// inject it via dht.Config.RecordAuth at the storage layer.
func VerifySignedRecord(sr SignedRecord, now time.Time) error {
	if err := signedRecordCheck(sr); err != nil {
		return err
	}
	fields := recordSignFields{
		Address:   sr.Address,
		RecType:   sr.RecType,
		Payload:   sr.Payload,
		Seq:       sr.Seq,
		Timestamp: sr.Timestamp,
		TTL:       sr.TTL,
	}
	signBytes, err := recordCanonical.Marshal(fields)
	if err != nil {
		return err
	}
	msg := bytes.Join([][]byte{[]byte(recordSignPrefix), signBytes}, nil)
	if !ed25519.Verify(sr.Pubkey, msg, sr.Signature) {
		return ErrInvalidRecord
	}
	if sr.RecType == RecTypeEndpoint {
		var ep EndpointPayload
		if err := cbor.Unmarshal(sr.Payload, &ep); err != nil {
			return fmt.Errorf("%w: payload: %v", ErrInvalidRecord, err)
		}
		if ep.NatType > NATSymmetric {
			return ErrInvalidRecord
		}
		if len(ep.Signal) > MaxEndpointSignalURLLen {
			return fmt.Errorf("%w: signal url length", ErrInvalidRecord)
		}
		if len(ep.Turns) > MaxTurnURLs {
			return fmt.Errorf("%w: turns count", ErrInvalidRecord)
		}
		for _, u := range ep.Turns {
			if len(u) > MaxTurnURLEntryLen {
				return fmt.Errorf("%w: turn url length", ErrInvalidRecord)
			}
		}
	}
	if sr.RecType == RecTypeTopic {
		if len(sr.Payload) > MaxTopicPayloadCBOR {
			return fmt.Errorf("%w: topic payload size", ErrInvalidRecord)
		}
		if _, err := ParseTopicRecord(sr); err != nil {
			return err
		}
	}
	if RecordCategory(sr.RecType) == CategoryMailbox && len(sr.Payload) > MaxMailboxPayloadCBOR {
		return fmt.Errorf("%w: mailbox payload size", ErrInvalidRecord)
	}
	nowUnix := uint64(now.Unix())
	if nowUnix < sr.Timestamp {
		return fmt.Errorf("%w: timestamp in future", ErrInvalidRecord)
	}
	if sr.Timestamp+uint64(sr.TTL) < nowUnix {
		return ErrRecordExpired
	}
	return nil
}

// ParseEndpointRecord decodes an endpoint record after verification.
func ParseEndpointRecord(sr SignedRecord) (EndpointRecord, error) {
	if sr.RecType != RecTypeEndpoint {
		return EndpointRecord{}, fmt.Errorf("%w: not an endpoint record", ErrInvalidRecord)
	}
	var ep EndpointPayload
	if err := cbor.Unmarshal(sr.Payload, &ep); err != nil {
		return EndpointRecord{}, err
	}
	var addr a2al.Address
	copy(addr[:], sr.Address)
	turns := append([]string(nil), ep.Turns...)
	return EndpointRecord{
		Address:   addr,
		Endpoints: ep.Endpoints,
		NatType:   ep.NatType,
		Signal:    ep.Signal,
		Turns:     turns,
		Timestamp: sr.Timestamp,
		Seq:       sr.Seq,
		TTL:       sr.TTL,
	}, nil
}

// RecordIsNewer reports whether a should replace b (spec: larger seq wins; tie-break by timestamp).
func RecordIsNewer(a, b SignedRecord) bool {
	if a.Seq != b.Seq {
		return a.Seq > b.Seq
	}
	return a.Timestamp > b.Timestamp
}
