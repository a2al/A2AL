// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

// sendMailboxQuic sends a MailboxFrame over an existing QUIC connection.
// Opens a new stream, writes the frame, waits for a 1-byte ACK (5s timeout).
func sendMailboxQuic(ctx context.Context, conn quic.Connection, msgID [32]byte, sr protocol.SignedRecord) error {
	sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	str, err := conn.OpenStreamSync(sendCtx)
	if err != nil {
		return fmt.Errorf("mailbox quic: open stream: %w", err)
	}
	defer str.Close()

	// Encode record.
	recCBOR, err := protocol.EncodeSignedRecord(sr)
	if err != nil {
		return fmt.Errorf("mailbox quic: encode record: %w", err)
	}

	if err := protocol.WriteMailboxFrame(str, msgID, recCBOR); err != nil {
		return fmt.Errorf("mailbox quic: write frame: %w", err)
	}

	// Wait for 1-byte ACK.
	_ = str.SetDeadline(time.Now().Add(5 * time.Second))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(str, ack); err != nil {
		return fmt.Errorf("mailbox quic: ack: %w", err)
	}
	if ack[0] != 0x01 {
		return fmt.Errorf("mailbox quic: unexpected ack byte 0x%02x", ack[0])
	}
	return nil
}

// acceptMailboxFrame handles an inbound MailboxFrame stream.
// The magic 4 bytes have already been consumed by dispatchInboundStream;
// rw provides buffered reading of the remaining data and writing for the ACK.
func (d *Daemon) acceptMailboxFrame(ac *host.AgentConn, rw io.ReadWriter) {
	msgID, recCBOR, err := protocol.ReadMailboxFrameBody(rw)
	if err != nil {
		d.log.Debug("mailbox quic: read frame body", "err", err)
		return
	}

	sr, err := protocol.DecodeSignedRecord(recCBOR)
	if err != nil {
		d.log.Debug("mailbox quic: decode record", "err", err)
		return
	}

	now := time.Now()
	if err := protocol.VerifySignedRecord(sr, now); err != nil {
		d.log.Debug("mailbox quic: invalid record", "err", err)
		return
	}

	// Validate msg_id matches record content.
	expected := sha256.Sum256(sr.Payload)
	if msgID != expected {
		d.log.Debug("mailbox quic: msg_id mismatch")
		return
	}

	// ac.Local is the recipient AID (the QUIC connection is bound to this agent).
	// sr.Address is the sender AID; it is validated indirectly by VerifySignedRecord above.
	d.regMu.RLock()
	reg := d.reg.Get(ac.Local)
	d.regMu.RUnlock()
	if reg == nil {
		return
	}

	ttlExpires := now.Unix() + int64(sr.TTL)
	inserted := d.mboxStore.Put(msgID, MailboxStoreEntry{
		RecipientAID: ac.Local,
		Record:       sr,
		ReceivedAt:   now.Unix(),
		TTLExpires:   ttlExpires,
	})

	// ACK regardless of whether the record was new (duplicate = sender can stop retrying).
	if _, err := rw.Write([]byte{0x01}); err != nil {
		d.log.Debug("mailbox quic: ack write", "err", err)
	}

	if inserted {
		if d.bus != nil {
			d.bus.Publish(Event{
				Type: "mailbox.received",
				AID:  ac.Local,
				Data: map[string]any{"count": 1, "source": "quic_direct"},
			})
		}
		if d.subMgr != nil {
			d.subMgr.NotifyActivity(ac.Local)
		}
	}
}

