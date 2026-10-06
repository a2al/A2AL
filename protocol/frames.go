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

// MagicServiceStream identifies a QUIC stream that admits into service_tcp (a2s1).
const MagicServiceStream = "a2s1"

// MagicCAS identifies a QUIC stream that serves content-addressed objects
// as HTTP/1.1 after the same admission keys as a2s1. It is not bridged to
// service_tcp; the daemon answers GET/HEAD /cas/{hash} itself.
const MagicCAS = "a2cs"

// Stream application error codes on Mode A data-plane streams (QUIC STREAM
// STOP_SENDING / RESET_STREAM). The space is a 62-bit integer; these sit
// next to each other so dialers can map them before any business bytes.
// Old peers that do not recognise a code still see a reset stream.
const (
	StreamErrAccessDenied       uint64 = 0x41 // ACL / join-password refused
	StreamErrNoInbound          uint64 = 0x42 // identity is live; no service_tcp bound
	StreamErrInboundUnreachable uint64 = 0x43 // service_tcp bound; TCP dial failed
)

// ErrAccessDenied is returned by Mode A callers when the peer refused the data plane.
var ErrAccessDenied = fmt.Errorf("access denied")

// ErrNoInbound: QUIC and admission succeeded; this AID does not bridge HTTP/TCP.
var ErrNoInbound = fmt.Errorf("no inbound")

// ErrInboundUnreachable: this AID has a bind, but the local TCP backend did not accept.
var ErrInboundUnreachable = fmt.Errorf("inbound unreachable")

// StreamApplicationErr maps a QUIC stream application error code to a sentinel.
// Unknown codes return nil — the caller keeps the original error.
func StreamApplicationErr(code uint64) error {
	switch code {
	case StreamErrAccessDenied:
		return ErrAccessDenied
	case StreamErrNoInbound:
		return ErrNoInbound
	case StreamErrInboundUnreachable:
		return ErrInboundUnreachable
	default:
		return nil
	}
}

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
