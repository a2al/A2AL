// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/a2al/a2al"
	acrypto "github.com/a2al/a2al/crypto"
	"github.com/fxamacker/cbor/v2"
)

const (
	msgSignPrefix = "a2al-msg\x00"
	txIDLen       = 20
)

var (
	canonical cbor.EncMode

	// ErrInvalidMessage is returned for malformed wire data or failed verification.
	ErrInvalidMessage = errors.New("a2al/protocol: invalid message")
	// ErrUnknownMsgType is returned when msg_type is not defined in Phase 1.
	ErrUnknownMsgType = errors.New("a2al/protocol: unknown msg_type")
)

func init() {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	canonical = em
}

type wireOuter struct {
	Header       Header          `cbor:"1,keyasint"`
	Body         cbor.RawMessage `cbor:"2,keyasint"`
	SenderPubkey []byte          `cbor:"3,keyasint"`
	Signature    []byte          `cbor:"4,keyasint"`
}

// DecodedMessage is a verified, parsed wire message.
type DecodedMessage struct {
	Header       Header
	SenderPubkey ed25519.PublicKey
	SenderAddr   a2al.Address
	Body         any
}

func marshalSignedCore(hdr Header, body any) (bodyCBOR []byte, preimage []byte, err error) {
	if err = headerWireCheck(hdr); err != nil {
		return nil, nil, err
	}
	if err = bodyWireCheck(hdr.MsgType, body); err != nil {
		return nil, nil, err
	}
	bodyCBOR, err = canonical.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	hdrCBOR, err := canonical.Marshal(hdr)
	if err != nil {
		return nil, nil, err
	}
	return bodyCBOR, signPayload(hdrCBOR, bodyCBOR), nil
}

func buildOuter(hdr Header, bodyCBOR []byte, pub ed25519.PublicKey, sig []byte) ([]byte, error) {
	outer := wireOuter{
		Header:       hdr,
		Body:         bodyCBOR,
		SenderPubkey: pub,
		Signature:    sig,
	}
	return canonical.Marshal(outer)
}

// MarshalSignedMessage canonical-encodes header and body, signs, and returns the outer CBOR bytes.
func MarshalSignedMessage(hdr Header, body any, priv ed25519.PrivateKey) ([]byte, error) {
	bodyCBOR, pre, err := marshalSignedCore(hdr, body)
	if err != nil {
		return nil, err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: invalid private key", ErrInvalidMessage)
	}
	sig := acrypto.SignDetached(priv, pre)
	pub := priv.Public().(ed25519.PublicKey)
	return buildOuter(hdr, bodyCBOR, pub, sig)
}

// MarshalSignedMessageKeyStore signs with KeyStore (spec: same preimage as MarshalSignedMessage).
func MarshalSignedMessageKeyStore(hdr Header, body any, ks acrypto.KeyStore, addr a2al.Address) ([]byte, error) {
	bodyCBOR, pre, err := marshalSignedCore(hdr, body)
	if err != nil {
		return nil, err
	}
	sig, err := ks.Sign(addr, pre)
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, ErrInvalidMessage
	}
	pubBytes, err := ks.PublicKey(addr)
	if err != nil {
		return nil, err
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, ErrInvalidMessage
	}
	pub := append(ed25519.PublicKey(nil), pubBytes...)
	return buildOuter(hdr, bodyCBOR, pub, sig)
}

// VerifyAndDecode parses the outer message, re-canonicalizes header/body, verifies Ed25519,
// checks sender_pubkey matches body.address for PING and PONG (spec §Step 3).
func VerifyAndDecode(raw []byte) (*DecodedMessage, error) {
	var outer wireOuter
	if err := cbor.Unmarshal(raw, &outer); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	if err := headerWireCheck(outer.Header); err != nil {
		return nil, err
	}
	if len(outer.SenderPubkey) != ed25519.PublicKeySize || len(outer.Signature) != ed25519.SignatureSize {
		return nil, ErrInvalidMessage
	}
	body, err := decodeBody(outer.Header.MsgType, outer.Body)
	if err != nil {
		return nil, err
	}
	hdrCBOR, err := canonical.Marshal(outer.Header)
	if err != nil {
		return nil, err
	}
	bodyCBOR, err := canonical.Marshal(body)
	if err != nil {
		return nil, err
	}
	if !acrypto.VerifyDetached(outer.SenderPubkey, signPayload(hdrCBOR, bodyCBOR), outer.Signature) {
		return nil, ErrInvalidMessage
	}
	senderAddr, err := acrypto.AddressFromPublicKey(outer.SenderPubkey)
	if err != nil {
		return nil, err
	}
	if err := senderMatchesBody(senderAddr, outer.Header.MsgType, body); err != nil {
		return nil, err
	}
	return &DecodedMessage{
		Header:       outer.Header,
		SenderPubkey: outer.SenderPubkey,
		SenderAddr:   senderAddr,
		Body:         body,
	}, nil
}

func signPayload(hdrCBOR, bodyCBOR []byte) []byte {
	return bytes.Join([][]byte{[]byte(msgSignPrefix), hdrCBOR, bodyCBOR}, nil)
}

func headerWireCheck(h Header) error {
	if len(h.TxID) != txIDLen {
		return fmt.Errorf("%w: tx_id length", ErrInvalidMessage)
	}
	return nil
}

func decodeBody(msgType uint8, raw cbor.RawMessage) (any, error) {
	switch msgType {
	case MsgPing:
		var b BodyPing
		if err := cbor.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		if len(b.Address) != len(a2al.Address{}) {
			return nil, ErrInvalidMessage
		}
		return &b, nil
	case MsgPong:
		var b BodyPong
		if err := cbor.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		if len(b.Address) != len(a2al.Address{}) || !validObserved(b.ObservedAddr) {
			return nil, ErrInvalidMessage
		}
		return &b, nil
	case MsgFindNode:
		var b BodyFindNode
		if err := cbor.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		if len(b.Target) != len(a2al.NodeID{}) {
			return nil, ErrInvalidMessage
		}
		return &b, nil
	case MsgFindNodeResp:
		var b BodyFindNodeResp
		if err := cbor.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		if !validObserved(b.ObservedAddr) {
			return nil, ErrInvalidMessage
		}
		for _, n := range b.Nodes {
			if err := nodeInfoCheck(n); err != nil {
				return nil, err
			}
		}
		return &b, nil
	case MsgFindValue:
		var b BodyFindValue
		if err := cbor.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		if len(b.Target) != len(a2al.NodeID{}) {
			return nil, ErrInvalidMessage
		}
		return &b, nil
	case MsgFindValueResp:
		var b BodyFindValueResp
		if err := cbor.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		if !validObserved(b.ObservedAddr) {
			return nil, ErrInvalidMessage
		}
		for _, n := range b.Nodes {
			if err := nodeInfoCheck(n); err != nil {
				return nil, err
			}
		}
		if b.Record != nil {
			if err := signedRecordCheck(*b.Record); err != nil {
				return nil, err
			}
		}
		for i := range b.Records {
			if err := signedRecordCheck(b.Records[i]); err != nil {
				return nil, err
			}
		}
		return &b, nil
	case MsgStore:
		var b BodyStore
		if err := cbor.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		if err := signedRecordCheck(b.Record); err != nil {
			return nil, err
		}
		if len(b.Key) != 0 && len(b.Key) != len(a2al.NodeID{}) {
			return nil, ErrInvalidMessage
		}
		return &b, nil
	case MsgStoreResp:
		var b BodyStoreResp
		if err := cbor.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		return &b, nil
	default:
		return nil, ErrUnknownMsgType
	}
}

func bodyWireCheck(msgType uint8, body any) error {
	switch msgType {
	case MsgPing:
		b, ok := body.(*BodyPing)
		if !ok {
			return fmt.Errorf("%w: body type for PING", ErrInvalidMessage)
		}
		if len(b.Address) != len(a2al.Address{}) {
			return ErrInvalidMessage
		}
	case MsgPong:
		b, ok := body.(*BodyPong)
		if !ok {
			return fmt.Errorf("%w: body type for PONG", ErrInvalidMessage)
		}
		if len(b.Address) != len(a2al.Address{}) || !validObserved(b.ObservedAddr) {
			return ErrInvalidMessage
		}
	case MsgFindNode:
		b, ok := body.(*BodyFindNode)
		if !ok {
			return fmt.Errorf("%w: body type for FIND_NODE", ErrInvalidMessage)
		}
		if len(b.Target) != len(a2al.NodeID{}) {
			return ErrInvalidMessage
		}
	case MsgFindNodeResp:
		b, ok := body.(*BodyFindNodeResp)
		if !ok {
			return fmt.Errorf("%w: body type for FIND_NODE_RESP", ErrInvalidMessage)
		}
		if !validObserved(b.ObservedAddr) {
			return ErrInvalidMessage
		}
		for _, n := range b.Nodes {
			if err := nodeInfoCheck(n); err != nil {
				return err
			}
		}
	case MsgFindValue:
		b, ok := body.(*BodyFindValue)
		if !ok {
			return fmt.Errorf("%w: body type for FIND_VALUE", ErrInvalidMessage)
		}
		if len(b.Target) != len(a2al.NodeID{}) {
			return ErrInvalidMessage
		}
	case MsgFindValueResp:
		b, ok := body.(*BodyFindValueResp)
		if !ok {
			return fmt.Errorf("%w: body type for FIND_VALUE_RESP", ErrInvalidMessage)
		}
		if !validObserved(b.ObservedAddr) {
			return ErrInvalidMessage
		}
		for _, n := range b.Nodes {
			if err := nodeInfoCheck(n); err != nil {
				return err
			}
		}
		if b.Record != nil {
			if err := signedRecordCheck(*b.Record); err != nil {
				return err
			}
		}
		for i := range b.Records {
			if err := signedRecordCheck(b.Records[i]); err != nil {
				return err
			}
		}
	case MsgStore:
		b, ok := body.(*BodyStore)
		if !ok {
			return fmt.Errorf("%w: body type for STORE", ErrInvalidMessage)
		}
		if err := signedRecordCheck(b.Record); err != nil {
			return err
		}
		if len(b.Key) != 0 && len(b.Key) != len(a2al.NodeID{}) {
			return ErrInvalidMessage
		}
	case MsgStoreResp:
		_, ok := body.(*BodyStoreResp)
		if !ok {
			return fmt.Errorf("%w: body type for STORE_RESP", ErrInvalidMessage)
		}
	default:
		return ErrUnknownMsgType
	}
	return nil
}

func validObserved(b []byte) bool {
	n := len(b)
	return n == 6 || n == 18
}

func nodeInfoCheck(n NodeInfo) error {
	if len(n.Address) != len(a2al.Address{}) || len(n.NodeID) != len(a2al.NodeID{}) {
		return ErrInvalidMessage
	}
	ipLen := len(n.IP)
	if ipLen != 4 && ipLen != 16 {
		return ErrInvalidMessage
	}
	return nil
}

func signedRecordCheck(r SignedRecord) error {
	// SignedRecord.Pubkey and Signature are always the Ed25519 operational key's material,
	// regardless of whether the record's Address belongs to an Ed25519, Ethereum, or other
	// blockchain identity. Delegation proof (field 9) carries the chain-specific signature;
	// this check must stay Ed25519-sized.
	if len(r.Address) != len(a2al.Address{}) || len(r.Pubkey) != ed25519.PublicKeySize || len(r.Signature) != ed25519.SignatureSize {
		return ErrInvalidMessage
	}
	return nil
}

// FindValueResponseWireSize returns the canonical CBOR size of a FIND_VALUE_RESP body (UDP trim, spec §3.7).
func FindValueResponseWireSize(resp *BodyFindValueResp) (int, error) {
	if resp == nil {
		return 0, ErrInvalidMessage
	}
	if err := bodyWireCheck(MsgFindValueResp, resp); err != nil {
		return 0, err
	}
	b, err := canonical.Marshal(resp)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func senderMatchesBody(sender a2al.Address, msgType uint8, body any) error {
	switch msgType {
	case MsgPing:
		var a a2al.Address
		copy(a[:], body.(*BodyPing).Address)
		if a != sender {
			return ErrInvalidMessage
		}
	case MsgPong:
		var a a2al.Address
		copy(a[:], body.(*BodyPong).Address)
		if a != sender {
			return ErrInvalidMessage
		}
	default:
	}
	return nil
}
