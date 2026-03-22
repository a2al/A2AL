// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"testing"

	"github.com/a2al/a2al"
)

func TestBucketIndex_self(t *testing.T) {
	var self, peer a2al.NodeID
	if BucketIndex(self, peer) != -1 {
		t.Fatal()
	}
}

func TestBucketIndex_firstBit(t *testing.T) {
	var self a2al.NodeID
	var peer a2al.NodeID
	peer[0] = 0x80
	if BucketIndex(self, peer) != 0 {
		t.Fatalf("got %d", BucketIndex(self, peer))
	}
}

func TestLessXORDistance(t *testing.T) {
	var target a2al.NodeID
	target[31] = 0x01
	var a, b a2al.NodeID
	a[31] = 0x02 // dist 03
	b[31] = 0x04 // dist 05
	if !LessXORDistance(a, b, target) {
		t.Fatal("a should be closer")
	}
}
