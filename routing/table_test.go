// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package routing

import (
	"bytes"
	"testing"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

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
	if !tb.Add(p, true) {
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
	if tb.Add(protocol.NodeInfo{NodeID: self[:]}, true) {
		t.Fatal("should reject self")
	}
}

func TestNearestN_order(t *testing.T) {
	var self a2al.NodeID
	var target a2al.NodeID
	target[31] = 0x10
	tb := NewTable(self, nil)
	// distances to target: prefer smaller XOR
	n1 := nodeInfoMSBVariant(0x80, 0x20) // xor with target in last byte
	n1.NodeID[31] = 0x11                 // dist 0x01
	n2 := nodeInfoMSBVariant(0x80, 0x30)
	n2.NodeID[31] = 0x13 // dist 0x03
	n3 := nodeInfoMSBVariant(0x80, 0x40)
	n3.NodeID[31] = 0x12 // dist 0x02
	for _, n := range []protocol.NodeInfo{n1, n2, n3} {
		tb.Add(n, true)
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
		if !tb.Add(n, true) {
			t.Fatalf("add %d", i)
		}
		if i == 0 {
			copy(firstID[:], n.NodeID)
		}
	}
	failOldest = true
	newN := nodeInfoMSBVariant(0x80, 99)
	if !tb.Add(newN, true) {
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
		tb.Add(nodeInfoMSBVariant(0x80, byte(i+1)), true)
	}
	if tb.Add(nodeInfoMSBVariant(0x80, 200), true) {
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
	tb.Add(a, true)
	tb.Add(b, true)
	oldest, _ := tb.OldestInBucket(a2al.NodeID{0x80})
	if oldest.NodeID[31] != 1 {
		t.Fatal("a should be LRU")
	}
	tb.Add(a, true) // touch
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
	tb.Add(n, true)
	tb.Remove(id)
	if tb.Contains(id) {
		t.Fatal()
	}
}
