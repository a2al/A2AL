// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// The daemon's background subscription timer refreshes an AID's mailbox from
// the DHT. It must not consume: it used to call execMailboxPoll, which decrypts
// and marks messages consumed, and then discarded the result. With an SSE
// doorbell attached the timer fires within seconds of delivery, so by the time
// the agent polled, its mail had already been read and thrown away — messages
// arrived, the notification fired, and the poll came back empty.
func TestRefreshMailboxDoesNotConsume(t *testing.T) {
	d := newTestDaemon(t)

	var aid a2al.Address
	aid[0] = 7
	var msgID [32]byte
	msgID[0] = 42

	now := time.Now().Unix()
	if !d.mboxStore.Put(msgID, MailboxStoreEntry{
		RecipientAID: aid,
		Record:       protocol.SignedRecord{TTL: 3600},
		ReceivedAt:   now,
		TTLExpires:   now + 3600,
	}) {
		t.Fatal("seeding the store failed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The fetch itself may fail in a test daemon with no DHT peers; what is
	// under test is that refresh leaves the agent's mail alone either way.
	_, _ = d.refreshMailbox(ctx, aid)

	left, err := d.mboxStore.GetUnconsumed(aid)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 {
		t.Fatalf("refresh consumed the agent's message: %d unconsumed left, want 1", len(left))
	}
}
