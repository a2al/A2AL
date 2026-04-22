// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package routing

import (
	"bytes"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// verifiedMeta returns an EntryMeta representing a directly-verified contact at now.
func verifiedMeta() EntryMeta { return EntryMeta{VerifiedAt: time.Now()} }

// hearsayMeta returns an EntryMeta representing a hearsay (unverified) contact.
func hearsayMeta() EntryMeta { return EntryMeta{} }

func nodeInfoMSBVariant(msb byte, tail byte) protocol.NodeInfo {
	var id a2al.NodeID
	id[0] = msb
	id[31] = tail
	return protocol.NodeInfo{NodeID: id[:], IP: []byte{127, 0, 0, 1}, Port: 1}
}

func TestAdd_bucketPlacement(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, nil)
	p := nodeInfoMSBVariant(0x80, 1)
	if !tb.Add(p, verifiedMeta(), time.Now()) {
		t.Fatal("add")
	}
	if tb.BucketIndexOf(a2al.NodeID{0x80}) != 0 {
		t.Fatal()
	}
	var peerID a2al.NodeID
	copy(peerID[:], p.NodeID)
	if tb.PeerBucketLen(peerID) != 1 {
		t.Fatal()
	}
}

func TestAdd_rejectsSelf(t *testing.T) {
	var self a2al.NodeID
	self[0] = 0x80
	tb := NewTable(self, nil)
	if tb.Add(protocol.NodeInfo{NodeID: self[:]}, verifiedMeta(), time.Now()) {
		t.Fatal("should reject self")
	}
}

func TestNearestN_order(t *testing.T) {
	var self a2al.NodeID
	var target a2al.NodeID
	target[31] = 0x10
	tb := NewTable(self, nil)
	n1 := nodeInfoMSBVariant(0x80, 0x20)
	n1.NodeID[31] = 0x11 // dist 0x01
	n2 := nodeInfoMSBVariant(0x80, 0x30)
	n2.NodeID[31] = 0x13 // dist 0x03
	n3 := nodeInfoMSBVariant(0x80, 0x40)
	n3.NodeID[31] = 0x12 // dist 0x02
	for _, n := range []protocol.NodeInfo{n1, n2, n3} {
		tb.Add(n, verifiedMeta(), time.Now())
	}
	near := tb.NearestN(target, 2)
	if len(near) != 2 {
		t.Fatalf("len %d", len(near))
	}
	if near[0].NodeID[31] != 0x11 || near[1].NodeID[31] != 0x12 {
		t.Fatalf("order %x %x", near[0].NodeID[31], near[1].NodeID[31])
	}
}

func TestFullBucket_pingFailReplaces(t *testing.T) {
	var self a2al.NodeID
	var pinged protocol.NodeInfo
	var failOldest bool
	ping := func(n protocol.NodeInfo) bool {
		pinged = n
		return !failOldest
	}
	tb := NewTable(self, ping)
	var firstID a2al.NodeID
	for i := 0; i < K; i++ {
		n := nodeInfoMSBVariant(0x80, byte(i))
		if !tb.Add(n, verifiedMeta(), time.Now()) {
			t.Fatalf("add %d", i)
		}
		if i == 0 {
			copy(firstID[:], n.NodeID)
		}
	}
	failOldest = true
	newN := nodeInfoMSBVariant(0x80, 99)
	if !tb.Add(newN, verifiedMeta(), time.Now()) {
		t.Fatal("should replace when ping fails")
	}
	if !bytes.Equal(pinged.NodeID, firstID[:]) {
		t.Fatal("PING should target LRU (oldest)")
	}
	var newID a2al.NodeID
	newID[0] = 0x80
	newID[31] = 99
	if !tb.Contains(newID) {
		t.Fatal("new node missing")
	}
	if tb.Contains(firstID) {
		t.Fatal("oldest should be evicted")
	}
}

func TestFullBucket_pingSuccessNoAdd(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, func(protocol.NodeInfo) bool { return true })
	for i := 0; i < K; i++ {
		tb.Add(nodeInfoMSBVariant(0x80, byte(i+1)), verifiedMeta(), time.Now())
	}
	if tb.Add(nodeInfoMSBVariant(0x80, 200), verifiedMeta(), time.Now()) {
		t.Fatal("should not add when LRU alive")
	}
	if tb.Len() != K {
		t.Fatal()
	}
}

func TestTouch_movesToMRU(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, func(protocol.NodeInfo) bool { return true })
	a := nodeInfoMSBVariant(0x80, 1)
	b := nodeInfoMSBVariant(0x80, 2)
	tb.Add(a, verifiedMeta(), time.Now())
	tb.Add(b, verifiedMeta(), time.Now())
	oldest, _ := tb.OldestInBucket(a2al.NodeID{0x80})
	if oldest.NodeID[31] != 1 {
		t.Fatal("a should be LRU")
	}
	tb.Add(a, verifiedMeta(), time.Now()) // touch
	oldest2, _ := tb.OldestInBucket(a2al.NodeID{0x80})
	if oldest2.NodeID[31] != 2 {
		t.Fatal("b should be LRU after a touched")
	}
}

func TestRemove(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, nil)
	n := nodeInfoMSBVariant(0x80, 7)
	var id a2al.NodeID
	copy(id[:], n.NodeID)
	tb.Add(n, verifiedMeta(), time.Now())
	tb.Remove(id)
	if tb.Contains(id) {
		t.Fatal()
	}
}

// ─── New tests for hearsay / pending behaviour ────────────────────────────────

func TestHearsay_emptySlot_inMain(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, nil)
	n := nodeInfoMSBVariant(0x80, 1)
	// Hearsay node should enter main bucket when there is space.
	if !tb.Add(n, hearsayMeta(), time.Now()) {
		t.Fatal("hearsay should be inserted when bucket has space")
	}
	var id a2al.NodeID
	copy(id[:], n.NodeID)
	if !tb.Contains(id) {
		t.Fatal("hearsay node missing from main bucket")
	}
	meta, ok := tb.GetEntryMeta(id)
	if !ok {
		t.Fatal("GetEntryMeta not found")
	}
	if !meta.VerifiedAt.IsZero() {
		t.Fatal("hearsay entry should have zero VerifiedAt")
	}
}

func TestHearsay_fullBucket_intoPending(t *testing.T) {
	var self a2al.NodeID
	// ping always says alive so verified nodes are never evicted.
	tb := NewTable(self, func(protocol.NodeInfo) bool { return true })
	for i := 0; i < K; i++ {
		tb.Add(nodeInfoMSBVariant(0x80, byte(i+1)), verifiedMeta(), time.Now())
	}
	hearsay := nodeInfoMSBVariant(0x80, 200)
	added := tb.Add(hearsay, hearsayMeta(), time.Now())
	if added {
		t.Fatal("hearsay should not displace verified node in full bucket")
	}
	if tb.Len() != K {
		t.Fatalf("main bucket size should remain K, got %d", tb.Len())
	}
	var id a2al.NodeID
	id[0] = 0x80
	id[31] = 200
	if tb.Contains(id) {
		t.Fatal("hearsay node must NOT be in main bucket")
	}
	// Verify it is in the pending list.
	work := tb.CollectMaintenanceWork(time.Now(), time.Now().Add(-30*time.Minute), time.Now().Add(-time.Hour))
	found := false
	for _, ni := range work.PendingToProbe {
		if bytes.Equal(ni.NodeID, hearsay.NodeID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("hearsay node should be in PendingToProbe")
	}
}

func TestPending_FIFOEviction(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, func(protocol.NodeInfo) bool { return true })
	for i := 0; i < K; i++ {
		tb.Add(nodeInfoMSBVariant(0x80, byte(i+1)), verifiedMeta(), time.Now())
	}
	// Fill the pending list beyond capacity.
	var firstPending protocol.NodeInfo
	for i := 0; i < pendingCap+2; i++ {
		ni := nodeInfoMSBVariant(0x80, byte(100+i))
		if i == 0 {
			firstPending = ni
		}
		tb.Add(ni, hearsayMeta(), time.Now())
	}
	work := tb.CollectMaintenanceWork(time.Now(), time.Now().Add(-30*time.Minute), time.Now().Add(-time.Hour))
	if len(work.PendingToProbe) != pendingCap {
		t.Fatalf("pending should be capped at %d, got %d", pendingCap, len(work.PendingToProbe))
	}
	// First inserted should have been evicted (FIFO).
	for _, ni := range work.PendingToProbe {
		if bytes.Equal(ni.NodeID, firstPending.NodeID) {
			t.Fatal("first inserted pending entry should have been evicted by FIFO")
		}
	}
}

func TestPending_TTLExpiry(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, func(protocol.NodeInfo) bool { return true })
	for i := 0; i < K; i++ {
		tb.Add(nodeInfoMSBVariant(0x80, byte(i+1)), verifiedMeta(), time.Now())
	}
	ni := nodeInfoMSBVariant(0x80, 200)
	// Add with arrivedAt in the past beyond TTL.
	old := time.Now().Add(-pendingTTL - time.Minute)
	tb.Add(ni, hearsayMeta(), old)

	// CollectMaintenanceWork expires old pending entries.
	work := tb.CollectMaintenanceWork(time.Now(), time.Now().Add(-30*time.Minute), time.Now().Add(-time.Hour))
	for _, p := range work.PendingToProbe {
		if bytes.Equal(p.NodeID, ni.NodeID) {
			t.Fatal("expired pending entry should have been removed")
		}
	}
}

func TestPendingPromotion(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, func(protocol.NodeInfo) bool { return true })
	for i := 0; i < K; i++ {
		tb.Add(nodeInfoMSBVariant(0x80, byte(i+1)), verifiedMeta(), time.Now())
	}
	hearsay := nodeInfoMSBVariant(0x80, 200)
	tb.Add(hearsay, hearsayMeta(), time.Now())

	// Remove one main-bucket node to make room.
	var removeID a2al.NodeID
	removeID[0] = 0x80
	removeID[31] = 1
	tb.Remove(removeID)

	var hid a2al.NodeID
	hid[0] = 0x80
	hid[31] = 200
	promoted := tb.MarkPendingVerified(hid, EntryMeta{VerifiedAt: time.Now()}, time.Now())
	if !promoted {
		t.Fatal("should be promoted when there is space")
	}
	if !tb.Contains(hid) {
		t.Fatal("promoted node missing from main bucket")
	}
	meta, ok := tb.GetEntryMeta(hid)
	if !ok || meta.VerifiedAt.IsZero() {
		t.Fatal("promoted node should have non-zero VerifiedAt")
	}
}

func TestVerified_protectedFromHearsayIPOverwrite(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, nil)
	orig := protocol.NodeInfo{
		NodeID: func() []byte { var id a2al.NodeID; id[0] = 0x80; id[31] = 5; return id[:] }(),
		IP:     []byte{1, 2, 3, 4},
		Port:   9000,
	}
	tb.Add(orig, verifiedMeta(), time.Now())

	// Now "hear" about the same node from a third party with different IP.
	hearsay := orig
	hearsay.IP = []byte{9, 9, 9, 9}
	hearsay.Port = 1111
	var nid a2al.NodeID
	copy(nid[:], orig.NodeID)
	hearsay.NodeID = append([]byte(nil), orig.NodeID...)
	tb.Add(hearsay, hearsayMeta(), time.Now())

	// The stored IP should remain the original verified IP.
	stored, ok := tb.OldestInBucket(nid)
	if !ok {
		t.Fatal("node missing")
	}
	if !bytes.Equal(stored.IP, []byte{1, 2, 3, 4}) {
		t.Fatalf("hearsay should not overwrite verified IP: got %v", stored.IP)
	}
}

func TestEstimatedNetworkSizeFiltered(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, nil)
	cutoff := time.Now().Add(-30 * time.Minute)

	// Add some verified-fresh nodes and some unverified (hearsay) nodes.
	freshTime := time.Now()
	for i := 0; i < 8; i++ {
		ni := nodeInfoMSBVariant(0x80, byte(i+1))
		meta := EntryMeta{VerifiedAt: freshTime}
		tb.Add(ni, meta, time.Now())
	}
	for i := 0; i < 8; i++ {
		ni := nodeInfoMSBVariant(0x40, byte(i+1))
		tb.Add(ni, hearsayMeta(), time.Now()) // unverified
	}

	est, conf := tb.EstimatedNetworkSizeFiltered(cutoff)
	if est == 0 {
		t.Fatal("expected non-zero estimate")
	}
	if conf <= 0 {
		t.Fatal("expected positive confidence")
	}

	// The raw EstimatedNetworkSize (which falls back to filter) should also be non-zero.
	raw := tb.EstimatedNetworkSize()
	if raw == 0 {
		t.Fatal("EstimatedNetworkSize should be non-zero")
	}
}

func TestUpdateVerifiedAt(t *testing.T) {
	var self a2al.NodeID
	tb := NewTable(self, nil)
	ni := nodeInfoMSBVariant(0x80, 3)
	var id a2al.NodeID
	copy(id[:], ni.NodeID)

	// Initially hearsay.
	tb.Add(ni, hearsayMeta(), time.Now())
	meta, _ := tb.GetEntryMeta(id)
	if !meta.VerifiedAt.IsZero() {
		t.Fatal("should start unverified")
	}

	// Simulate a successful RPC.
	now := time.Now()
	tb.UpdateVerifiedAt(id, now)
	meta, _ = tb.GetEntryMeta(id)
	if meta.VerifiedAt.IsZero() {
		t.Fatal("VerifiedAt should be set after UpdateVerifiedAt")
	}
	if !meta.VerifiedAt.Equal(now) {
		t.Fatal("VerifiedAt should match provided time")
	}
}
