// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"encoding/hex"
	"net"
	"sort"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// PingFunc probes whether a candidate entry is still alive (spec Step 5).
type PingFunc func(protocol.NodeInfo) bool

// Table is a 256-bucket Kademlia routing table (Phase 1: single LRU zone per bucket).
type Table struct {
	self a2al.NodeID
	ping PingFunc
	b    [256]bucket
}

// NewTable constructs an empty table for the local node. ping may be nil (treated as always true on eviction probe).
func NewTable(self a2al.NodeID, ping PingFunc) *Table {
	return &Table{self: self, ping: ping}
}

// Self returns the local NodeID.
func (t *Table) Self() a2al.NodeID { return t.self }

// Add inserts or refreshes a peer. Returns false if the peer is self, invalid, or rejected when the bucket is full and the LRU peer answers PING.
func (t *Table) Add(n protocol.NodeInfo) bool {
	if len(n.NodeID) != len(t.self) {
		return false
	}
	var peer a2al.NodeID
	copy(peer[:], n.NodeID)
	if peer == t.self {
		return false
	}
	bi := BucketIndex(t.self, peer)
	if bi < 0 {
		return false
	}
	return t.b[bi].addOrTouch(cloneNodeInfo(n), t.ping)
}

func cloneNodeInfo(n protocol.NodeInfo) protocol.NodeInfo {
	return protocol.NodeInfo{
		Address: append([]byte(nil), n.Address...),
		NodeID:  append([]byte(nil), n.NodeID...),
		IP:      append([]byte(nil), n.IP...),
		Port:    n.Port,
	}
}

// Remove deletes a peer by NodeID if present.
func (t *Table) Remove(id a2al.NodeID) {
	for i := range t.b {
		t.b[i].remove(id)
	}
}

// NearestN returns up to n peers with smallest XOR distance to target (excluding self). Results sorted closest-first.
func (t *Table) NearestN(target a2al.NodeID, n int) []protocol.NodeInfo {
	if n <= 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []protocol.NodeInfo
	for i := range t.b {
		for _, node := range t.b[i].nodes {
			if len(node.NodeID) != len(target) {
				continue
			}
			var nid a2al.NodeID
			copy(nid[:], node.NodeID)
			if nid == t.self {
				continue
			}
			key := string(node.NodeID)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, node)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		var ai, aj a2al.NodeID
		copy(ai[:], out[i].NodeID)
		copy(aj[:], out[j].NodeID)
		return LessXORDistance(ai, aj, target)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// BucketIndexOf returns BucketIndex(t.self, peer).
func (t *Table) BucketIndexOf(peer a2al.NodeID) int {
	return BucketIndex(t.self, peer)
}

// AllPeers returns every distinct peer in the table (unordered). Excludes self.
func (t *Table) AllPeers() []protocol.NodeInfo {
	var out []protocol.NodeInfo
	seen := make(map[string]struct{})
	for bi := range t.b {
		for _, node := range t.b[bi].nodes {
			if len(node.NodeID) != len(t.self) {
				continue
			}
			var nid a2al.NodeID
			copy(nid[:], node.NodeID)
			if nid == t.self {
				continue
			}
			key := string(node.NodeID)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, cloneNodeInfo(node))
		}
	}
	return out
}

// Len returns the total number of stored peers.
func (t *Table) Len() int {
	c := 0
	for i := range t.b {
		c += len(t.b[i].nodes)
	}
	return c
}

// Contains reports whether id is present in any bucket.
func (t *Table) Contains(id a2al.NodeID) bool {
	bi := BucketIndex(t.self, id)
	if bi < 0 {
		return false
	}
	return t.b[bi].indexByID(id) >= 0
}

// PeerBucketLen is for tests / debug: number of entries in the bucket for peer's CPL slot.
func (t *Table) PeerBucketLen(peer a2al.NodeID) int {
	bi := BucketIndex(t.self, peer)
	if bi < 0 {
		return 0
	}
	return len(t.b[bi].nodes)
}

// OldestInBucket returns the LRU entry in the bucket that would hold peer (may be nil slice if empty).
func (t *Table) OldestInBucket(peer a2al.NodeID) (protocol.NodeInfo, bool) {
	bi := BucketIndex(t.self, peer)
	if bi < 0 || len(t.b[bi].nodes) == 0 {
		return protocol.NodeInfo{}, false
	}
	return t.b[bi].nodes[0], true
}

// PeerDebugRow is a JSON-friendly routing row (spec §3.6).
type PeerDebugRow struct {
	Bucket        int    `json:"bucket"`
	XORDistToSelf string `json:"xor_distance_to_self_hex"`
	AddressHex    string `json:"address_hex"`
	NodeIDHex     string `json:"node_id_hex"`
	IP            string `json:"ip"`
	Port          uint16 `json:"port"`
}

// DebugPeerRows returns a flat list of peers with bucket index and XOR distance to local self (read-only snapshot; caller must serialize table access if concurrent).
func (t *Table) DebugPeerRows() []PeerDebugRow {
	var out []PeerDebugRow
	for bi := range t.b {
		for _, node := range t.b[bi].nodes {
			var nid a2al.NodeID
			copy(nid[:], node.NodeID)
			if nid == t.self {
				continue
			}
			d := a2al.Distance(nid, t.self)
			out = append(out, PeerDebugRow{
				Bucket:        bi,
				XORDistToSelf: hex.EncodeToString(d[:]),
				AddressHex:    hex.EncodeToString(node.Address),
				NodeIDHex:     hex.EncodeToString(node.NodeID),
				IP:            formatIP(node.IP),
				Port:          node.Port,
			})
		}
	}
	return out
}

func formatIP(ip []byte) string {
	if len(ip) == 4 {
		return net.IPv4(ip[0], ip[1], ip[2], ip[3]).String()
	}
	if len(ip) == 16 {
		return net.IP(append([]byte(nil), ip...)).String()
	}
	return ""
}
