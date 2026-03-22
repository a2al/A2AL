// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"bytes"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

const K = 16

type bucket struct {
	nodes []protocol.NodeInfo // oldest at [0], MRU at [len-1]
}

func (b *bucket) indexByID(id a2al.NodeID) int {
	for i, n := range b.nodes {
		if len(n.NodeID) == len(id) && bytes.Equal(n.NodeID, id[:]) {
			return i
		}
	}
	return -1
}

// addOrTouch returns whether the node is present after the operation (new or touched).
// If the bucket is full and LRU answers PING, the new node is dropped.
func (b *bucket) addOrTouch(n protocol.NodeInfo, ping PingFunc) bool {
	var nid a2al.NodeID
	if len(n.NodeID) != len(nid) {
		return false
	}
	copy(nid[:], n.NodeID)

	if i := b.indexByID(nid); i >= 0 {
		b.touch(i)
		return true
	}

	if len(b.nodes) < K {
		b.nodes = append(b.nodes, n)
		return true
	}

	oldest := b.nodes[0]
	if ping == nil || ping(oldest) {
		return false
	}
	copy(b.nodes[0:], b.nodes[1:])
	b.nodes = b.nodes[:len(b.nodes)-1]
	b.nodes = append(b.nodes, n)
	return true
}

func (b *bucket) touch(i int) {
	if i < 0 || i >= len(b.nodes) {
		return
	}
	n := b.nodes[i]
	copy(b.nodes[i:], b.nodes[i+1:])
	b.nodes[len(b.nodes)-1] = n
}

func (b *bucket) remove(id a2al.NodeID) bool {
	i := b.indexByID(id)
	if i < 0 {
		return false
	}
	copy(b.nodes[i:], b.nodes[i+1:])
	b.nodes = b.nodes[:len(b.nodes)-1]
	return true
}
