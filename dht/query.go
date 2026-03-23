// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dht

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)

const (
	DefaultAlpha   = 3
	DefaultStagger = 5 * time.Millisecond
)

// Query runs iterative FIND_NODE / FIND_VALUE (spec Step 8).
type Query struct {
	n       *Node
	Alpha   int
	Stagger time.Duration
}

// NewQuery builds a querier with default α=3 and small stagger between parallel RPCs.
func NewQuery(n *Node) *Query {
	if n == nil {
		return nil
	}
	return &Query{n: n, Alpha: DefaultAlpha, Stagger: DefaultStagger}
}

func infoKey(ni protocol.NodeInfo) string {
	if len(ni.NodeID) != len(a2al.NodeID{}) {
		return ""
	}
	return string(ni.NodeID)
}

func cloneNI(ni protocol.NodeInfo) protocol.NodeInfo {
	return protocol.NodeInfo{
		Address: append([]byte(nil), ni.Address...),
		NodeID:  append([]byte(nil), ni.NodeID...),
		IP:      append([]byte(nil), ni.IP...),
		Port:    ni.Port,
	}
}

func sortedByDistance(c map[string]protocol.NodeInfo, target a2al.NodeID) []protocol.NodeInfo {
	out := make([]protocol.NodeInfo, 0, len(c))
	for _, ni := range c {
		out = append(out, ni)
	}
	sort.Slice(out, func(i, j int) bool {
		var ai, aj a2al.NodeID
		copy(ai[:], out[i].NodeID)
		copy(aj[:], out[j].NodeID)
		return routing.LessXORDistance(ai, aj, target)
	})
	return out
}

func (q *Query) alpha() int {
	if q.Alpha <= 0 {
		return DefaultAlpha
	}
	return q.Alpha
}

func (q *Query) stagger() time.Duration {
	if q.Stagger < 0 {
		return 0
	}
	return q.Stagger
}

// FindNode runs iterative FIND_NODE until k-closest known nodes are exhausted or all have been queried.
func (q *Query) FindNode(ctx context.Context, target a2al.NodeID) ([]protocol.NodeInfo, error) {
	if q.n == nil {
		return nil, errors.New("dht: nil node")
	}
	alpha := q.alpha()
	stagger := q.stagger()

	candidates := make(map[string]protocol.NodeInfo)
	queried := make(map[string]struct{})

	for _, ni := range q.n.tabNearest(target, routing.K) {
		if k := infoKey(ni); k != "" {
			candidates[k] = cloneNI(ni)
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		list := sortedByDistance(candidates, target)
		if len(list) == 0 {
			break
		}
		kClosest := list
		if len(kClosest) > routing.K {
			kClosest = kClosest[:routing.K]
		}

		allDone := true
		for _, ni := range kClosest {
			if _, ok := queried[infoKey(ni)]; !ok {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}

		var batch []protocol.NodeInfo
		for _, ni := range kClosest {
			if len(batch) >= alpha {
				break
			}
			key := infoKey(ni)
			if key == "" {
				continue
			}
			if _, ok := queried[key]; ok {
				continue
			}
			var peerID a2al.NodeID
			copy(peerID[:], ni.NodeID)
			if peerID == q.n.nid {
				queried[key] = struct{}{}
				continue
			}
			if _, ok := q.n.lookupPeer(peerID); !ok {
				continue
			}
			batch = append(batch, ni)
		}
		if len(batch) == 0 {
			break
		}

		type res struct {
			nodes []protocol.NodeInfo
		}
		ch := make(chan res, len(batch))
		var wg sync.WaitGroup
		for i := range batch {
			ni := batch[i]
			key := infoKey(ni)
			queried[key] = struct{}{}
			var peerID a2al.NodeID
			copy(peerID[:], ni.NodeID)
			addr, _ := q.n.lookupPeer(peerID)
			d := time.Duration(i) * stagger
			wg.Add(1)
			go func(addr net.Addr, delay time.Duration) {
				defer wg.Done()
				if delay > 0 {
					t := time.NewTimer(delay)
					select {
					case <-t.C:
					case <-ctx.Done():
						if !t.Stop() {
							<-t.C
						}
						return
					}
				}
				nodes, err := q.n.FindNode(ctx, addr, target)
				if err != nil {
					ch <- res{}
					return
				}
				ch <- res{nodes: nodes}
			}(addr, d)
		}
		go func() {
			wg.Wait()
			close(ch)
		}()
		for r := range ch {
			for _, x := range r.nodes {
				k := infoKey(x)
				if k == "" {
					continue
				}
				candidates[k] = cloneNI(x)
				q.n.absorbNodeInfo(x)
			}
		}
	}

	out := sortedByDistance(candidates, target)
	if len(out) > routing.K {
		out = out[:routing.K]
	}
	return out, nil
}

// ErrNoEndpoint is returned when iterative FIND_VALUE does not yield a valid endpoint record.
var ErrNoEndpoint = errors.New("dht: no endpoint record")

// Resolve runs iterative FIND_VALUE for target NodeID (publisher key) and returns a verified endpoint record.
func (q *Query) Resolve(ctx context.Context, target a2al.NodeID) (*protocol.EndpointRecord, error) {
	if q.n == nil {
		return nil, errors.New("dht: nil node")
	}
	if rec := q.n.store.Get(target, time.Now()); rec != nil {
		if err := protocol.VerifySignedRecord(*rec, time.Now()); err == nil {
			if er, err := protocol.ParseEndpointRecord(*rec); err == nil {
				return &er, nil
			}
		}
	}
	alpha := q.alpha()
	stagger := q.stagger()

	candidates := make(map[string]protocol.NodeInfo)
	queried := make(map[string]struct{})

	for _, ni := range q.n.tabNearest(target, routing.K) {
		if k := infoKey(ni); k != "" {
			candidates[k] = cloneNI(ni)
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		list := sortedByDistance(candidates, target)
		if len(list) == 0 {
			return nil, ErrNoEndpoint
		}
		kClosest := list
		if len(kClosest) > routing.K {
			kClosest = kClosest[:routing.K]
		}

		allDone := true
		for _, ni := range kClosest {
			if _, ok := queried[infoKey(ni)]; !ok {
				allDone = false
				break
			}
		}
		if allDone {
			return nil, ErrNoEndpoint
		}

		var batch []protocol.NodeInfo
		for _, ni := range kClosest {
			if len(batch) >= alpha {
				break
			}
			key := infoKey(ni)
			if key == "" {
				continue
			}
			if _, ok := queried[key]; ok {
				continue
			}
			var peerID a2al.NodeID
			copy(peerID[:], ni.NodeID)
			if peerID == q.n.nid {
				queried[key] = struct{}{}
				continue
			}
			if _, ok := q.n.lookupPeer(peerID); !ok {
				continue
			}
			batch = append(batch, ni)
		}
		if len(batch) == 0 {
			return nil, ErrNoEndpoint
		}

		type fvRes struct {
			rec   *protocol.SignedRecord
			nodes []protocol.NodeInfo
		}
		ch := make(chan fvRes, len(batch))
		var wg sync.WaitGroup
		for i := range batch {
			ni := batch[i]
			key := infoKey(ni)
			queried[key] = struct{}{}
			var peerID a2al.NodeID
			copy(peerID[:], ni.NodeID)
			addr, _ := q.n.lookupPeer(peerID)
			d := time.Duration(i) * stagger
			wg.Add(1)
			go func(addr net.Addr, delay time.Duration) {
				defer wg.Done()
				if delay > 0 {
					t := time.NewTimer(delay)
					select {
					case <-t.C:
					case <-ctx.Done():
						if !t.Stop() {
							<-t.C
						}
						return
					}
				}
				rec, nodes, err := q.n.FindValueWithNodes(ctx, addr, target)
				if err != nil {
					ch <- fvRes{}
					return
				}
				ch <- fvRes{rec: rec, nodes: nodes}
			}(addr, d)
		}
		go func() {
			wg.Wait()
			close(ch)
		}()
		for r := range ch {
			if r.rec != nil {
				if err := protocol.VerifySignedRecord(*r.rec, time.Now()); err == nil {
					er, err := protocol.ParseEndpointRecord(*r.rec)
					if err == nil {
						return &er, nil
					}
				}
			}
			for _, x := range r.nodes {
				k := infoKey(x)
				if k == "" {
					continue
				}
				candidates[k] = cloneNI(x)
				q.n.absorbNodeInfo(x)
			}
		}
	}
}
