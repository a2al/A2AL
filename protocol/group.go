// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// MagicGroupSync identifies a QUIC stream carrying Group sync frames.
const MagicGroupSync = "a2gp"

// MagicGroupJoin identifies a QUIC stream carrying a Group join request.
// This is a separate dispatch path that bypasses the CanSync member gate,
// allowing a non-member to self-identify and request admission.
const MagicGroupJoin = "a2gj"

// MaxEntryBodySize is the maximum allowed byte length of an inline entry body.
// Content larger than this limit must be stored as an Object and referenced
// via the Entry.Ref field. This is a protocol constant; all implementations
// must enforce it both at write time and during inbound sync.
const MaxEntryBodySize = 2048

// Mailbox message types for the Group protocol.
//
// Groups put exactly one message type in the mailbox: a plain invite note that
// the daemon never interprets. 0x11 (GroupPoke, "new entries available, come
// sync") was removed: catch-up is the returning AID's own job (see alignAID),
// not something a best-effort envelope can be made to guarantee.
const (
	// MailboxMsgGroupInvite delivers a signed invitation to join a Group.
	// It is delivered to the agent as an ordinary note; the daemon does not
	// decode it, does not create a replica, and does not pre-sync.
	MailboxMsgGroupInvite uint8 = 0x10
)

// Group sync frame types (single byte, sent before each CBOR payload).
const (
	groupFrameHave uint8 = 0x01 // sender's current DAG heads + entry count
	groupFrameWant uint8 = 0x02 // list of entry IDs the sender lacks
	groupFrameGive uint8 = 0x03 // CBOR-encoded entry bytes fulfilling a Want
	groupFrameDone uint8 = 0x04 // sender has no further Wants for this round
)

// groupHave is the CBOR payload of a Have frame.
type groupHave struct {
	Heads      [][32]byte `cbor:"1,keyasint"`
	EntryCount uint64     `cbor:"2,keyasint"`
}

// groupWant is the CBOR payload of a Want frame.
type groupWant struct {
	IDs [][32]byte `cbor:"1,keyasint"`
}

// groupGive is the CBOR payload of a Give frame.
type groupGive struct {
	Entries [][]byte `cbor:"2,keyasint"` // each element is a Marshal()ed Entry
}

// The invite note body is defined by the daemon, not here: it is a plain JSON
// object ({"link":..., "title":...}) addressed to the recipient's agent, and no
// protocol code parses it. See daemon.inviteNote.

// --- low-level frame I/O ---

const maxGroupFramePayload = 4 << 20 // 4 MiB hard cap per frame

// writeGroupFrame writes [frame_type 1B][payload_len 4B big-endian][payload].
func writeGroupFrame(w io.Writer, frameType uint8, payload []byte) error {
	var hdr [5]byte
	hdr[0] = frameType
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readGroupFrame reads one frame and returns its type and CBOR payload.
func readGroupFrame(r io.Reader) (uint8, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("group sync: read frame header: %w", err)
	}
	ft := hdr[0]
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxGroupFramePayload {
		return 0, nil, fmt.Errorf("group sync: frame too large (%d bytes)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, fmt.Errorf("group sync: read frame payload: %w", err)
	}
	return ft, buf, nil
}

// WriteGroupHave encodes and sends a Have frame.
func WriteGroupHave(w io.Writer, heads [][32]byte, count uint64) error {
	b, err := cbor.Marshal(groupHave{Heads: heads, EntryCount: count})
	if err != nil {
		return err
	}
	return writeGroupFrame(w, groupFrameHave, b)
}

// WriteGroupWant encodes and sends a Want frame.
func WriteGroupWant(w io.Writer, ids [][32]byte) error {
	b, err := cbor.Marshal(groupWant{IDs: ids})
	if err != nil {
		return err
	}
	return writeGroupFrame(w, groupFrameWant, b)
}

// WriteGroupGive encodes and sends a Give frame.
func WriteGroupGive(w io.Writer, entries [][]byte) error {
	b, err := cbor.Marshal(groupGive{Entries: entries})
	if err != nil {
		return err
	}
	return writeGroupFrame(w, groupFrameGive, b)
}

// WriteGroupDone sends a Done frame (no payload).
func WriteGroupDone(w io.Writer) error {
	return writeGroupFrame(w, groupFrameDone, nil)
}

// ReadGroupFrame reads one frame and dispatches by type.
// Returns the frame type constant and the decoded payload struct.
func ReadGroupFrame(r io.Reader) (uint8, groupHave, groupWant, groupGive, error) {
	ft, raw, err := readGroupFrame(r)
	if err != nil {
		return 0, groupHave{}, groupWant{}, groupGive{}, err
	}
	var have groupHave
	var want groupWant
	var give groupGive
	switch ft {
	case groupFrameHave:
		err = cbor.Unmarshal(raw, &have)
	case groupFrameWant:
		err = cbor.Unmarshal(raw, &want)
	case groupFrameGive:
		err = cbor.Unmarshal(raw, &give)
	case groupFrameDone:
		// no payload
	default:
		err = fmt.Errorf("group sync: unknown frame type 0x%02x", ft)
	}
	return ft, have, want, give, err
}

// FrameTypeHave etc. re-export the frame type constants for use outside this package.
const (
	FrameTypeGroupHave = groupFrameHave
	FrameTypeGroupWant = groupFrameWant
	FrameTypeGroupGive = groupFrameGive
	FrameTypeGroupDone = groupFrameDone
)
