// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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
}

// EndpointRecord is the decoded logical view (spec Step 4); no signature material.
type EndpointRecord struct {
	Address   a2al.Address
	Endpoints []string
	NatType   uint8
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

// SignEndpointRecord builds a SignedRecord for an endpoint advertisement.
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
	payloadCBOR, err := recordCanonical.Marshal(ep)
	if err != nil {
		return SignedRecord{}, err
	}
	fields := recordSignFields{
		Address:   addr[:],
		RecType:   RecTypeEndpoint,
		Payload:   payloadCBOR,
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
		Address:   addr[:],
		RecType:   RecTypeEndpoint,
		Payload:   payloadCBOR,
		Seq:       seq,
		Timestamp: timestamp,
		TTL:       ttl,
		Pubkey:    pub,
		Signature: sig,
	}, nil
}

// VerifySignedRecord checks signature, pubkey↔address, binding, optional endpoint payload shape, and expiry.
func VerifySignedRecord(sr SignedRecord, now time.Time) error {
	if err := signedRecordCheck(sr); err != nil {
		return err
	}
	addr, err := acrypto.AddressFromPublicKey(sr.Pubkey)
	if err != nil {
		return err
	}
	var recAddr a2al.Address
	copy(recAddr[:], sr.Address)
	if addr != recAddr {
		return ErrInvalidRecord
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
	return EndpointRecord{
		Address:   addr,
		Endpoints: ep.Endpoints,
		NatType:   ep.NatType,
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
