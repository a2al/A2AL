// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// package group implements the A2AL Group protocol: a signed, append-only DAG
// replicated across a closed set of AIDs. It is the coordination plane for
// agent collaboration and has no dependency on the network layer.
package group

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/a2al/a2al"
	"github.com/fxamacker/cbor/v2"
)

// Protocol-level entry kinds. Application layers may define additional kinds freely.
const (
	KindMeta          = "meta"
	KindInvite        = "invite"
	KindRevoke        = "revoke"
	KindGrantAdmin    = "grant_admin"
	KindRevokeAdmin   = "revoke_admin"
	KindProposeInvite = "propose_invite"
	KindRetract       = "retract"
	KindBudget        = "budget"
	KindSpend         = "spend"
	KindSnapshot      = "snapshot"
)

// Entry errors.
var (
	ErrBadSignature = errors.New("group: invalid entry signature")
	ErrIDMismatch   = errors.New("group: entry ID does not match content hash")
	ErrMalformed    = errors.New("group: malformed entry")
)

// entryCore is the content that is hashed to produce the entry ID and signed
// by the author. Field numbers are permanently stable; never renumber.
type entryCore struct {
	Author  []byte     `cbor:"1,keyasint"`
	Parents [][32]byte `cbor:"2,keyasint"`
	TS      int64      `cbor:"3,keyasint"`
	Kind    string     `cbor:"4,keyasint"`
	ReplyTo []byte     `cbor:"5,keyasint,omitempty"`
	To      [][]byte   `cbor:"6,keyasint,omitempty"`
	Body    []byte     `cbor:"7,keyasint,omitempty"`
	Ref     []byte     `cbor:"8,keyasint,omitempty"`
}

// wireEntry is the full CBOR-serialisable form of an Entry (core fields + id + sig).
// Field numbers are permanently stable; never renumber.
type wireEntry struct {
	ID      []byte     `cbor:"1,keyasint"`
	Author  []byte     `cbor:"2,keyasint"`
	Sig     []byte     `cbor:"3,keyasint"`
	Parents [][32]byte `cbor:"4,keyasint"`
	TS      int64      `cbor:"5,keyasint"`
	Kind    string     `cbor:"6,keyasint"`
	ReplyTo []byte     `cbor:"7,keyasint,omitempty"`
	To      [][]byte   `cbor:"8,keyasint,omitempty"`
	Body    []byte     `cbor:"9,keyasint,omitempty"`
	Ref     []byte     `cbor:"10,keyasint,omitempty"`
}

// detEnc is the deterministic CBOR encoder used for hashing and signing.
// It is initialised once at package load time.
var detEnc cbor.EncMode

func init() {
	var err error
	detEnc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic("group: CBOR init: " + err.Error())
	}
}

// Entry is the coordination plane's minimal immutable unit.
// All fields are set at creation time and never modified.
type Entry struct {
	// ID is SHA256 of the canonical CBOR encoding of the signed core fields.
	ID [32]byte
	// Author is the AID that signed this entry.
	Author a2al.Address
	// Sig is the Ed25519 signature over the canonical CBOR of the core fields.
	Sig [64]byte
	// Parents lists the DAG leaf IDs known to the author at write time.
	// Empty for the first entry in a group (genesis).
	Parents [][32]byte
	// TS is the author's local Unix milliseconds.
	// Used only for display ordering of concurrent entries; not a causal clock.
	TS int64
	// Kind is an open-ended type tag. The protocol defines well-known kinds
	// (see Kind* constants); application layers may extend freely.
	Kind string
	// ReplyTo is a semantic reply reference to another entry's ID.
	// Zero value means no reply reference.
	ReplyTo [32]byte
	// To lists AIDs explicitly mentioned for notification.
	// Empty means no specific recipients.
	To []a2al.Address
	// Body holds inline content, or an object descriptor (name/size/mime)
	// when Ref is also set.
	Body []byte
	// Ref is a content-addressed object reference (SHA256 of object bytes).
	// Zero value means no object. May be set together with Body (descriptor).
	Ref [32]byte
}

// EntryOption is a functional option for NewEntry.
type EntryOption func(*Entry)

// WithBody sets inline body content (text, or object descriptor when used with WithRef).
func WithBody(body []byte) EntryOption { return func(e *Entry) { e.Body = body } }

// WithRef sets a content-addressed object reference. May be combined with WithBody.
func WithRef(ref [32]byte) EntryOption { return func(e *Entry) { e.Ref = ref } }

// WithReplyTo sets the semantic reply-to entry ID.
func WithReplyTo(id [32]byte) EntryOption { return func(e *Entry) { e.ReplyTo = id } }

// WithTo appends explicitly mentioned AIDs.
func WithTo(aids ...a2al.Address) EntryOption {
	return func(e *Entry) { e.To = append(e.To, aids...) }
}

// WithTS overrides the timestamp. Intended for testing only.
func WithTS(ts int64) EntryOption { return func(e *Entry) { e.TS = ts } }

// NewEntry constructs, signs, and returns a new Entry.
// parents should be the current DAG heads of the local replica at write time.
func NewEntry(priv ed25519.PrivateKey, author a2al.Address, parents [][32]byte, kind string, opts ...EntryOption) (Entry, error) {
	e := Entry{
		Author:  author,
		Parents: parents,
		TS:      time.Now().UnixMilli(),
		Kind:    kind,
	}
	for _, o := range opts {
		o(&e)
	}
	core, err := marshalCore(e)
	if err != nil {
		return Entry{}, err
	}
	e.ID = sha256.Sum256(core)
	sig := ed25519.Sign(priv, core)
	copy(e.Sig[:], sig)
	return e, nil
}

// VerifyID checks that e.ID equals SHA256 of the canonical core fields.
// This is a purely local, key-free integrity check: it detects corruption or
// crafted entries whose claimed ID does not match their content.
// Call Verify to additionally validate the Ed25519 signature.
func (e Entry) VerifyID() error {
	core, err := marshalCore(e)
	if err != nil {
		return err
	}
	if sha256.Sum256(core) != e.ID {
		return ErrIDMismatch
	}
	return nil
}

// Verify checks that e.ID matches SHA256 of the core fields, and that e.Sig is
// a valid Ed25519 signature over those same bytes.
// pub must be the Ed25519 public key that corresponds to e.Author.
func (e Entry) Verify(pub ed25519.PublicKey) error {
	core, err := marshalCore(e)
	if err != nil {
		return err
	}
	if sha256.Sum256(core) != e.ID {
		return ErrIDMismatch
	}
	if !ed25519.Verify(pub, core, e.Sig[:]) {
		return ErrBadSignature
	}
	return nil
}

// Marshal encodes e to CBOR for storage or transport.
func (e Entry) Marshal() ([]byte, error) {
	w := wireEntry{
		ID:      e.ID[:],
		Author:  e.Author[:],
		Sig:     e.Sig[:],
		Parents: e.Parents,
		TS:      e.TS,
		Kind:    e.Kind,
		Body:    e.Body,
	}
	if e.ReplyTo != ([32]byte{}) {
		w.ReplyTo = e.ReplyTo[:]
	}
	for _, a := range e.To {
		addr := a
		w.To = append(w.To, addr[:])
	}
	if e.Ref != ([32]byte{}) {
		w.Ref = e.Ref[:]
	}
	return detEnc.Marshal(w)
}

// Unmarshal decodes a CBOR-encoded entry.
// The signature and ID are NOT verified; call e.Verify() separately.
// Unknown fields are silently ignored for forward compatibility.
func Unmarshal(data []byte) (Entry, error) {
	var w wireEntry
	if err := cbor.Unmarshal(data, &w); err != nil {
		return Entry{}, err
	}
	if len(w.ID) != 32 || len(w.Author) != 21 || len(w.Sig) != 64 {
		return Entry{}, ErrMalformed
	}
	var e Entry
	copy(e.ID[:], w.ID)
	copy(e.Author[:], w.Author)
	copy(e.Sig[:], w.Sig)
	e.Parents = w.Parents
	e.TS = w.TS
	e.Kind = w.Kind
	e.Body = w.Body
	if len(w.ReplyTo) == 32 {
		copy(e.ReplyTo[:], w.ReplyTo)
	}
	for _, ab := range w.To {
		if len(ab) == 21 {
			var a a2al.Address
			copy(a[:], ab)
			e.To = append(e.To, a)
		}
	}
	if len(w.Ref) == 32 {
		copy(e.Ref[:], w.Ref)
	}
	return e, nil
}

// marshalCore produces the canonical CBOR bytes over which ID and Sig are computed.
func marshalCore(e Entry) ([]byte, error) {
	c := entryCore{
		Author:  e.Author[:],
		Parents: e.Parents,
		TS:      e.TS,
		Kind:    e.Kind,
		Body:    e.Body,
	}
	if e.ReplyTo != ([32]byte{}) {
		c.ReplyTo = e.ReplyTo[:]
	}
	for _, a := range e.To {
		addr := a
		c.To = append(c.To, addr[:])
	}
	if e.Ref != ([32]byte{}) {
		c.Ref = e.Ref[:]
	}
	return detEnc.Marshal(c)
}
