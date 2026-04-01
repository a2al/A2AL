// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package routing

import (
	"bytes"

	"github.com/a2al/a2al"
)

// BucketIndex is the K-bucket slot for peer relative to self: shared MSB prefix length
// in [0,255]. Returns -1 if peer equals self (spec §4.1, Step 5).
func BucketIndex(self, peer a2al.NodeID) int {
	if self == peer {
		return -1
	}
	return a2al.CommonPrefixLen(self, peer)
}

// LessXORDistance reports whether a is strictly closer to target than b under XOR metric
// (lexicographic compare of Distance(a,target) vs Distance(b,target)).
func LessXORDistance(a, b, target a2al.NodeID) bool {
	da := a2al.Distance(a, target)
	db := a2al.Distance(b, target)
	return bytes.Compare(da[:], db[:]) < 0
}
