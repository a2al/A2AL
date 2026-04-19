// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/a2al/a2al"
	"github.com/fxamacker/cbor/v2"
)

const (
	// MaxMailboxPayloadCBOR is the spec §4.8 cap on SignedRecord.payload (MailboxPayload CBOR).
	MaxMailboxPayloadCBOR = 512
	// DefaultMailboxTTL is the recommended mailbox record TTL in seconds (spec §4.8).
	DefaultMailboxTTL uint32 = 3600
	mailboxSalt                = "a2al-mailbox\x00"
)

// Mailbox message types (spec §4.3).
const (
	MailboxMsgConnectRequest uint8 = 0x01
	MailboxMsgCandidates     uint8 = 0x02
	MailboxMsgText           uint8 = 0x03
)

// MailboxPayload is the CBOR inside SignedRecord.payload for rec_type=0x80 (spec §4.1).
type MailboxPayload struct {
	Recipient   []byte `cbor:"1,keyasint"`
	SenderAddr  []byte `cbor:"2,keyasint"`
	EphemeralPK []byte `cbor:"3,keyasint"`
	Ciphertext  []byte `cbor:"4,keyasint"`
	Nonce       []byte `cbor:"5,keyasint"`
}

// mailboxWire is the plaintext CBOR map encrypted into MailboxPayload (spec §4.3).
type mailboxWire struct {
	MsgType uint8  `cbor:"1,keyasint"`
	Body    []byte `cbor:"2,keyasint"`
}

// MailboxMessage is one decrypted mailbox entry for the application (spec §4.6).
type MailboxMessage struct {
	Sender  a2al.Address
	MsgType uint8
	Body    []byte
	// Seq is copied from the outer SignedRecord.Seq; it is monotonically
	// increasing per sender and serves as a unique record identifier.
	Seq uint64
	// SenderPubkey is the sender's Ed25519 identity public key, taken from
	// SignedRecord.Pubkey after signature verification.  It is guaranteed to
	// correspond to Sender (same key that derived the AID).  Callers may use
	// this to encrypt a reply without an extra DHT lookup.
	SenderPubkey ed25519.PublicKey
}

// EncodeMailboxPayload encrypts (msgType, body) and returns canonical CBOR MailboxPayload.
func EncodeMailboxPayload(senderAddr, recipientAddr a2al.Address, recipientPub ed25519.PublicKey, msgType uint8, body []byte) ([]byte, error) {
	mw := mailboxWire{MsgType: msgType, Body: body}
	plain, err := recordCanonical.Marshal(mw)
	if err != nil {
		return nil, err
	}
	ephPub, nonce, ct, err := mailboxEncryptAEAD(recipientPub, senderAddr, recipientAddr, plain)
	if err != nil {
		return nil, err
	}
	mp := MailboxPayload{
		Recipient:   recipientAddr[:],
		SenderAddr:  senderAddr[:],
		EphemeralPK: ephPub,
		Ciphertext:  ct,
		Nonce:       nonce,
	}
	out, err := recordCanonical.Marshal(mp)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxMailboxPayloadCBOR {
		return nil, fmt.Errorf("%w: mailbox payload exceeds %d bytes", ErrInvalidRecord, MaxMailboxPayloadCBOR)
	}
	return out, nil
}

// OpenMailboxRecord decrypts a verified mailbox SignedRecord for recipientAddr.
func OpenMailboxRecord(recipientPriv ed25519.PrivateKey, recipientAddr a2al.Address, sr SignedRecord) (MailboxMessage, error) {
	var empty MailboxMessage
	if RecordCategory(sr.RecType) != CategoryMailbox {
		return empty, fmt.Errorf("%w: not mailbox record", ErrInvalidRecord)
	}
	var mp MailboxPayload
	if err := cbor.Unmarshal(sr.Payload, &mp); err != nil {
		return empty, err
	}
	if len(mp.Recipient) != len(recipientAddr) || !bytes.Equal(mp.Recipient, recipientAddr[:]) {
		return empty, fmt.Errorf("%w: recipient mismatch", ErrInvalidRecord)
	}
	if len(mp.SenderAddr) != len(recipientAddr) {
		return empty, fmt.Errorf("%w: sender_addr length", ErrInvalidRecord)
	}
	if !bytes.Equal(mp.SenderAddr, sr.Address) {
		return empty, fmt.Errorf("%w: sender_addr/record address mismatch", ErrInvalidRecord)
	}
	if len(mp.EphemeralPK) != 32 || len(mp.Nonce) != 12 {
		return empty, fmt.Errorf("%w: mailbox field lengths", ErrInvalidRecord)
	}
	var senderAddr a2al.Address
	copy(senderAddr[:], mp.SenderAddr)
	plain, err := mailboxDecryptAEAD(recipientPriv, recipientAddr, mp.SenderAddr, mp.EphemeralPK, mp.Nonce, mp.Ciphertext)
	if err != nil {
		return empty, err
	}
	var mw mailboxWire
	if err := cbor.Unmarshal(plain, &mw); err != nil {
		return empty, err
	}
	senderPub := append(ed25519.PublicKey(nil), sr.Pubkey...)
	return MailboxMessage{Sender: senderAddr, MsgType: mw.MsgType, Body: mw.Body, Seq: sr.Seq, SenderPubkey: senderPub}, nil
}
