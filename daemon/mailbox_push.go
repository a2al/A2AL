// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

const hitchRefreshMinGap = 5 * time.Second

// registerDHTPushHandler wires the daemon as the consumer of incoming MsgDHTPush
// messages and STORE_RESP receive-pool hints. Called once during Run().
func (d *Daemon) registerDHTPushHandler() {
	d.h.SetDHTPushHandler(func(key a2al.NodeID, rec protocol.SignedRecord) bool {
		switch protocol.RecordCategory(rec.RecType) {
		case protocol.CategoryMailbox:
			return d.handleMailboxPush(key, rec)
		}
		return false
	})
	d.h.SetReceivePoolHandler(d.handleReceivePool)
	d.syncLocalReceiveKeys()
}

// syncLocalReceiveKeys tells the DHT node which keys are mailbox homes here.
// Registered agents only — the node identity is deliberately excluded, because
// mailbox send/poll both require a registry entry, so mail addressed to the node
// AID has no reader and must not be ingested.
func (d *Daemon) syncLocalReceiveKeys() {
	d.regMu.RLock()
	defer d.regMu.RUnlock()
	d.syncLocalReceiveKeysLocked()
}

// syncLocalReceiveKeysLocked is syncLocalReceiveKeys with regMu already held.
func (d *Daemon) syncLocalReceiveKeysLocked() {
	if d.h == nil || d.h.Node() == nil {
		return
	}
	d.h.Node().SetLocalReceiveKeys(d.localReceiveKeysLocked())
}

// localReceiveKeysLocked lists the DHT keys of AIDs with a mailbox here.
func (d *Daemon) localReceiveKeysLocked() []a2al.NodeID {
	entries := d.reg.List()
	keys := make([]a2al.NodeID, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, a2al.NodeIDFromAddress(e.AID))
	}
	return keys
}

// handleMailboxPush processes a SignedRecord delivered via DHT_PUSH or coincidence
// inbound STORE. Returns true if the record was new (telling a pusher to renew).
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

	newRecord, doorbell := d.fileMailbox(recipientAID, sr)
	if doorbell {
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
	return newRecord
}

// fileMailbox stores sr. doorbell is true only for a newly stored, unclaimed note.
func (d *Daemon) fileMailbox(recipient a2al.Address, sr protocol.SignedRecord) (newRecord, doorbell bool) {
	if d.mboxStore == nil {
		return false, false
	}
	now := time.Now()
	msgID := MsgIDFromRecord(sr)
	if !d.mboxStore.Put(msgID, MailboxStoreEntry{
		RecipientAID: recipient,
		Record:       sr,
		ReceivedAt:   now.Unix(),
		TTLExpires:   now.Unix() + int64(sr.TTL),
	}) {
		return false, false
	}
	if d.tryClaimMailbox(recipient, sr, msgID) {
		return true, false
	}
	return true, true
}

// tryClaimMailbox decrypts a newly stored record when envelope consumers exist.
// Only MailboxMsgEnvelope may be claimed. Non-0x04 is left for poll (one extra decrypt).
func (d *Daemon) tryClaimMailbox(recipient a2al.Address, sr protocol.SignedRecord, msgID [32]byte) bool {
	if !d.hasEnvelopeConsumers() || d.h == nil {
		return false
	}
	msg, err := d.h.DecryptMailboxRecordFor(recipient, sr)
	if err != nil {
		return false
	}
	if msg.MsgType != protocol.MailboxMsgEnvelope {
		return false
	}
	kind, body, err := protocol.SplitEnvelopeInner(msg.Body)
	if err != nil {
		return false
	}
	consumed, _ := d.consumeEnvelope(recipient, msg.Sender, kind, body)
	if !consumed {
		return false
	}
	d.mboxStore.MarkConsumed(msgID)
	return true
}

func (d *Daemon) handleReceivePool(visitor a2al.Address, _ a2al.NodeID, pool []protocol.ReceivePoolHint) {
	if !d.isLocalAID(visitor) {
		return
	}
	if receivePoolNeedsRefresh(d.mboxStore, pool) {
		d.scheduleHitchRefresh(visitor)
	}
}

func receivePoolNeedsRefresh(store *mailboxStore, pool []protocol.ReceivePoolHint) bool {
	if store == nil {
		return false
	}
	for _, slice := range pool {
		if slice.RecType != protocol.RecTypeMailbox || slice.Count == 0 {
			continue
		}
		if sliceHasUnknown(store, slice.IDs) {
			return true
		}
	}
	return false
}

// sliceHasUnknown reports whether ids names a record the local store lacks.
// An empty list with a non-zero count also counts: the peer holds mail it could
// not name, either because there was more than MaxReceivePoolIDs of it or because
// trimming dropped the detail.
//
// A malformed ID makes the whole slice untrustworthy, so the slice is dropped
// rather than treated as a miss: that costs at most a delayed notification (a
// later poll still finds the message) and denies a peer a free refresh trigger.
func sliceHasUnknown(store *mailboxStore, ids [][]byte) bool {
	if len(ids) == 0 {
		return true
	}
	unknown := false
	for _, raw := range ids {
		if len(raw) != 32 {
			return false
		}
		var id [32]byte
		copy(id[:], raw)
		if !store.Has(id) {
			unknown = true
		}
	}
	return unknown
}

func (d *Daemon) scheduleHitchRefresh(aid a2al.Address) {
	d.hitchMu.Lock()
	if _, busy := d.hitchInFlight[aid]; busy {
		d.hitchMu.Unlock()
		return
	}
	if last, ok := d.hitchLast[aid]; ok && time.Since(last) < hitchRefreshMinGap {
		d.hitchMu.Unlock()
		return
	}
	d.hitchInFlight[aid] = struct{}{}
	d.hitchMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := d.refreshMailbox(ctx, aid)
		d.hitchMu.Lock()
		delete(d.hitchInFlight, aid)
		d.hitchLast[aid] = time.Now()
		d.hitchMu.Unlock()
		if err != nil {
			d.log.Debug("hitch refresh", "aid", aid.String(), "err", err)
		}
	}()
}

// isLocalAID reports whether aid is a registered agent on this daemon. Scoped to
// the registry for the same reason as syncLocalReceiveKeys: only registered AIDs
// have a readable mailbox.
func (d *Daemon) isLocalAID(aid a2al.Address) bool {
	d.regMu.RLock()
	e := d.reg.Get(aid)
	d.regMu.RUnlock()
	return e != nil
}

// findAgentByNodeID returns the AID of the registered agent whose DHT NodeID
// equals key.
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
