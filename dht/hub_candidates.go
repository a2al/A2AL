// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"net"
	"sort"
	"strings"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)

// PublicHubCandidates returns up to max routing-table peers whose endpoint
// record indicates high inbound TCP reachability: NATFullCone, or any endpoint
// contains a publicly-routable IPv6 GUA address. Results are selected with
// bucket-index diversity (at most one per bucket) to spread candidates across
// the key space.
func (n *Node) PublicHubCandidates(max int) []net.Addr {
	if max <= 0 {
		return nil
	}
	n.tabMu.RLock()
	peers := n.table.AllPeers()
	n.tabMu.RUnlock()

	type candidate struct {
		addr *net.UDPAddr
	}
	byBucket := make(map[int][]candidate)
	seen := make(map[string]struct{})

	for _, ni := range peers {
		if len(ni.NodeID) != len(n.nid) {
			continue
		}
		var id a2al.NodeID
		copy(id[:], ni.NodeID)
		if id == n.nid {
			continue
		}

		// Require a fresh endpoint record with public reachability.
		recs := n.LocalStoreGet(id, protocol.RecTypeEndpoint)
		var capable bool
		for _, sr := range recs {
			er, err := protocol.ParseEndpointRecord(sr)
			if err != nil {
				continue
			}
			if isPublicHubCapable(&er) {
				capable = true
				break
			}
		}
		if !capable {
			continue
		}

		// Resolve dial address (preferred live addr or routing table fallback).
		var udp *net.UDPAddr
		n.peerMu.Lock()
		pa := n.peers[nodeIDKey(id)]
		n.peerMu.Unlock()
		if pa != nil {
			if a := pa.preferred(); a != nil {
				if u, ok := a.(*net.UDPAddr); ok && u.Port != 0 {
					udp = u
				}
			}
		}
		if udp == nil && (len(ni.IP) == 4 || len(ni.IP) == 16) && ni.Port != 0 {
			udp = &net.UDPAddr{IP: append([]byte(nil), ni.IP...), Port: int(ni.Port)}
		}
		if udp == nil {
			continue
		}
		k := udp.String()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}

		bi := routing.BucketIndex(n.nid, id)
		byBucket[bi] = append(byBucket[bi], candidate{addr: udp})
	}

	// One candidate per bucket, sorted descending so we scan highest CPL first.
	// The intent is XOR-space diversity: candidates spread across the key space
	// rather than clustering around the local node.
	buckets := make([]int, 0, len(byBucket))
	for bi := range byBucket {
		buckets = append(buckets, bi)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(buckets)))

	out := make([]net.Addr, 0, max)
	for _, bi := range buckets {
		if len(out) >= max {
			break
		}
		out = append(out, byBucket[bi][0].addr)
	}
	return out
}

// isPublicHubCapable reports whether er indicates high inbound TCP reachability:
//   - NATFullCone: any peer can cold-dial this node's UDP port; TCP is likely open.
//     Note: this includes NAT-behind nodes whose UDP hole-punching succeeded but
//     whose TCP may still be firewalled. The slot cooldown path handles failures.
//   - Any endpoint has a v6 GUA address: node has a direct IPv6 WAN address; its
//     TCP hub on the same host:port is directly reachable from IPv6 peers.
func isPublicHubCapable(er *protocol.EndpointRecord) bool {
	if er.NatType == protocol.NATFullCone {
		return true
	}
	for _, ep := range er.Endpoints {
		// Strip scheme (e.g. "quic://") to get host:port.
		hostport := ep
		if i := strings.Index(ep, "://"); i >= 0 {
			hostport = ep[i+3:]
		}
		host, _, err := net.SplitHostPort(hostport)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		// v6 GUA: not v4, not loopback, not link-local, not private (ULA fc00::/7).
		if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
			!ip.IsPrivate() && !ip.IsUnspecified() && !ip.IsMulticast() {
			return true
		}
	}
	return false
}
