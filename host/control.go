// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

// QUIC Stream 0 control plane — a2r2 protocol.
//
// After the 4-byte magic + 21-byte agent-route frame, the a2r2 protocol
// exchanges a small set of length-prefixed control messages on the same stream
// before data streams open. The exchange is sequential: the dialer writes its
// messages and closes its write direction (FIN), then the acceptor replies and
// closes its own write direction (FIN). QUIC stream full-duplex means both
// directions progress concurrently at the transport level within flow-control.
//
// Wire format per message:
//
//	[type: 1B][len: 2B big-endian][payload: len bytes]
//
// Message types:
//
//	0x01  ObservedAddr   acceptor → dialer   wire-encoded UDP source addr (6 or 18 B)
//	0x02  AgentInfoHint  dialer  → acceptor  target AID (21 B) + max held seq (8 B BE)
//	0x03  AgentInfo      acceptor → dialer   CBOR-encoded SignedRecord (topic record)
//
// Unknown message types are skipped by consuming the declared length, ensuring
// forward compatibility without a new magic number.

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

const (
	ctrlMsgObservedAddr  uint8 = 0x01 // acceptor → dialer
	ctrlMsgAgentInfoHint uint8 = 0x02 // dialer → acceptor
	ctrlMsgAgentInfo     uint8 = 0x03 // acceptor → dialer

	// ctrlMaxPayload caps the payload of a single control message.
	// Topic SignedRecord CBOR is ≤512 B payload + ~200 B overhead = well under 4 KiB.
	ctrlMaxPayload = 4096
)

// writeCtrlMsg encodes and writes one control message to w.
func writeCtrlMsg(w io.Writer, msgType uint8, payload []byte) error {
	if len(payload) > ctrlMaxPayload {
		return errors.New("a2al/host: control payload too large")
	}
	hdr := [3]byte{msgType, byte(len(payload) >> 8), byte(len(payload))}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// readCtrlMsg reads one control message from r.
// Returns (0, nil, io.EOF) on clean FIN from the peer.
func readCtrlMsg(r io.Reader) (msgType uint8, payload []byte, err error) {
	var hdr [3]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	msgType = hdr[0]
	length := int(binary.BigEndian.Uint16(hdr[1:3]))
	if length > ctrlMaxPayload {
		return 0, nil, errors.New("a2al/host: oversized control message")
	}
	if length == 0 {
		return msgType, nil, nil
	}
	payload = make([]byte, length)
	_, err = io.ReadFull(r, payload)
	return msgType, payload, err
}

// sendDialerMsgs writes the dialer's control messages then closes the write direction.
// heldSeq is the highest topic record seq the dialer holds for targetAID (0 if unknown).
func sendDialerMsgs(w io.WriteCloser, targetAID a2al.Address, heldSeq uint64) error {
	// AgentInfoHint: target_aid (21 B) || max_held_seq (8 B big-endian)
	var hint [29]byte
	copy(hint[:21], targetAID[:])
	binary.BigEndian.PutUint64(hint[21:], heldSeq)
	if err := writeCtrlMsg(w, ctrlMsgAgentInfoHint, hint[:]); err != nil {
		return err
	}
	return w.Close() // FIN: no more dialer messages
}

// sendAcceptorMsgs writes the acceptor's control messages then closes the write direction.
// remoteAddr is the dialer's observed UDP source address.
// localRecs are the acceptor's current topic records for the target agent.
// dialerHeldSeq is the max seq the dialer claimed; records with seq <= this are skipped.
func sendAcceptorMsgs(w io.WriteCloser, remoteAddr net.Addr, localRecs []protocol.SignedRecord, dialerHeldSeq uint64) error {
	// ObservedAddr: tell the dialer its observed public UDP address.
	if udp, ok := remoteAddr.(*net.UDPAddr); ok && udp != nil && udp.IP != nil {
		if wire, err := protocol.FormatObservedUDP(udp.IP, uint16(udp.Port)); err == nil {
			_ = writeCtrlMsg(w, ctrlMsgObservedAddr, wire) // best-effort
		}
	}

	// AgentInfo: push topic records the dialer may not have yet.
	for _, rec := range localRecs {
		if rec.Seq <= dialerHeldSeq {
			continue // dialer is up-to-date for this record
		}
		b, err := cbor.Marshal(rec)
		if err != nil || len(b) > ctrlMaxPayload {
			continue
		}
		_ = writeCtrlMsg(w, ctrlMsgAgentInfo, b) // best-effort
	}

	return w.Close() // FIN: no more acceptor messages
}

// readDialerMsgs drains the dialer's control messages until FIN.
// Returns the max held_seq from an AgentInfoHint message (0 if none received).
func readDialerMsgs(r io.Reader) (heldSeq uint64, err error) {
	for {
		msgType, payload, rerr := readCtrlMsg(r)
		if rerr == io.EOF {
			return heldSeq, nil
		}
		if rerr != nil {
			return heldSeq, rerr
		}
		if msgType == ctrlMsgAgentInfoHint && len(payload) >= 29 {
			heldSeq = binary.BigEndian.Uint64(payload[21:29])
		}
		// Unknown types: payload already consumed; skip silently.
	}
}

// readAcceptorMsgs drains the acceptor's control messages until FIN.
// Returns the observed-address wire bytes and any SignedRecords received.
// Ignores malformed or expired records rather than failing.
func readAcceptorMsgs(r io.Reader) (observedWire []byte, records []protocol.SignedRecord, err error) {
	now := time.Now()
	for {
		msgType, payload, rerr := readCtrlMsg(r)
		if rerr == io.EOF {
			return observedWire, records, nil
		}
		if rerr != nil {
			return observedWire, records, rerr
		}
		switch msgType {
		case ctrlMsgObservedAddr:
			if len(payload) == 6 || len(payload) == 18 {
				observedWire = append([]byte(nil), payload...)
			}
		case ctrlMsgAgentInfo:
			var rec protocol.SignedRecord
			if cerr := cbor.Unmarshal(payload, &rec); cerr == nil {
				if protocol.VerifySignedRecord(rec, now) == nil {
					records = append(records, rec)
				}
			}
		}
		// Unknown types: consumed, skipped.
	}
}
