// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// registerDHTPushHandler wires the daemon as the consumer of incoming MsgDHTPush
// messages delivered by the DHT node. Called once during Run().
func (d *Daemon) registerDHTPushHandler() {
	d.h.SetDHTPushHandler(func(key a2al.NodeID, rec protocol.SignedRecord) bool {
		switch protocol.RecordCategory(rec.RecType) {
		case protocol.CategoryMailbox:
			return d.handleMailboxPush(key, rec)
		}
		return false
	})
}

// handleMailboxPush processes a SignedRecord delivered via DHT_PUSH.
// Returns true if the record was new (telling the pushing node to renew its subscription).
// key is the DHT key under which the record is stored: NodeIDFromAddress(recipient).
func (d *Daemon) handleMailboxPush(key a2al.NodeID, sr protocol.SignedRecord) bool {
	now := time.Now()
	if err := protocol.VerifySignedRecord(sr, now); err != nil {
		d.log.Debug("mailbox_push: invalid record", "err", err)
		return false
	}

	// sr.Address is the sender AID; find the recipient via DHT key = NodeID(recipient).
	recipientAID, ok := d.findAgentByNodeID(key)
	if !ok {
		return false
	}

	msgID := MsgIDFromRecord(sr)
	if d.mboxStore.Has(msgID) {
		// Duplicate: ACK without renewing subscription so this pusher converges out.
		return false
	}

	ttlExpires := now.Unix() + int64(sr.TTL)
	inserted := d.mboxStore.Put(msgID, MailboxStoreEntry{
		RecipientAID: recipientAID,
		Record:       sr,
		ReceivedAt:   now.Unix(),
		TTLExpires:   ttlExpires,
	})
	if inserted {
		if d.bus != nil {
			d.bus.Publish(Event{
				Type: "mailbox.received",
				AID:  recipientAID,
				Data: map[string]any{"count": 1, "source": "dht_push"},
			})
		}
		if d.subMgr != nil {
			d.subMgr.NotifyActivity(recipientAID)
		}
	}
	return inserted
}

// findAgentByNodeID returns the AID of the registered agent whose DHT NodeID equals key.
func (d *Daemon) findAgentByNodeID(key a2al.NodeID) (a2al.Address, bool) {
	d.regMu.RLock()
	defer d.regMu.RUnlock()
	for _, e := range d.reg.List() {
		if a2al.NodeIDFromAddress(e.AID) == key {
			return e.AID, true
		}
	}
	return a2al.Address{}, false
}
