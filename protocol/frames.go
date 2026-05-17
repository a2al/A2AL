// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// MagicMailboxFrame identifies a QUIC-stream mailbox direct-delivery frame.
const MagicMailboxFrame = "a2mb"

// EncodeSignedRecord CBOR-encodes a SignedRecord.
func EncodeSignedRecord(sr SignedRecord) ([]byte, error) {
	return cbor.Marshal(sr)
}

// DecodeSignedRecord CBOR-decodes a SignedRecord from data.
func DecodeSignedRecord(data []byte) (SignedRecord, error) {
	var sr SignedRecord
	return sr, cbor.Unmarshal(data, &sr)
}

// MailboxFrame is the QUIC direct-delivery frame format.
// Wire layout (stream):
//
//	[magic "a2mb" 4B][msg_id 32B][record_len 4B big-endian][record CBOR]
type MailboxFrame struct {
	MsgID  [32]byte
	Record SignedRecord
}

// WriteMailboxFrame serialises a MailboxFrame to w.
func WriteMailboxFrame(w io.Writer, msgID [32]byte, recordCBOR []byte) error {
	if _, err := io.WriteString(w, MagicMailboxFrame); err != nil {
		return err
	}
	if _, err := w.Write(msgID[:]); err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(recordCBOR)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(recordCBOR)
	return err
}

// ReadMailboxFrameBody reads the body of a MailboxFrame after the 4-byte magic has been consumed.
// Returns (msgID, recordCBOR, error). Enforces a 64 KiB cap on recordCBOR.
func ReadMailboxFrameBody(r io.Reader) ([32]byte, []byte, error) {
	var msgID [32]byte
	if _, err := io.ReadFull(r, msgID[:]); err != nil {
		return msgID, nil, fmt.Errorf("mailbox frame: read msg_id: %w", err)
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return msgID, nil, fmt.Errorf("mailbox frame: read len: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	const maxRecordCBOR = 64 << 10
	if n > maxRecordCBOR {
		return msgID, nil, fmt.Errorf("mailbox frame: record too large (%d bytes)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return msgID, nil, fmt.Errorf("mailbox frame: read record: %w", err)
	}
	return msgID, buf, nil
}
