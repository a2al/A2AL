// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/routing"
)

// QueryHopRec is a compact record sighting from one FIND_VALUE reply.
type QueryHopRec struct {
	RecType uint8  `json:"rec_type"`
	Seq     uint64 `json:"seq"`
}

// QueryHop is one RPC attempt during an iterative lookup.
type QueryHop struct {
	Wave     int           `json:"wave"`
	Track    string        `json:"track"`
	Peer     string        `json:"peer"` // node id hex
	XOR      string        `json:"xor"`  // xor(peer, target) hex
	CPL      int           `json:"cpl"`  // leading zero bits of XOR; larger = nearer
	Addr     string        `json:"addr,omitempty"`
	RTTMs    float64       `json:"rtt_ms"`
	Status   string        `json:"status"` // ok | empty-ok | timeout | error
	Error    string        `json:"error,omitempty"`
	Closer   int           `json:"closer"`
	RecsWire int           `json:"recs_wire"`
	RecsOK   int           `json:"recs_ok"`
	Recs     []QueryHopRec `json:"recs,omitempty"`
}

// QueryTrace is filled when EnableTrace is called before a lookup.
// Nil (the default) keeps the hot path allocation-free besides the existing slotRes.
// Safe to read after FindRecords / FindNode / AggregateRecords / Resolve / IterQuery return.
type QueryTrace struct {
	Target        string     `json:"target"`
	FindValue     bool       `json:"find_value"`
	RecType       uint8      `json:"rec_type"`
	HitThreshold  int        `json:"hit_threshold"`
	SelfXOR       string     `json:"self_xor"`
	SelfCPL       int        `json:"self_cpl"`
	Started       time.Time  `json:"started"`
	DurationMs    float64    `json:"duration_ms"`
	Stop          string     `json:"stop"` // hit | exhausted | deadline
	Seeded        int        `json:"seeded"`
	SkipPunch     int        `json:"skip_punch,omitempty"`
	SkipNoAddr    int        `json:"skip_no_addr,omitempty"`
	Hops          []QueryHop `json:"hops"`
	Attempted     int        `json:"attempted"`
	Replied       int        `json:"replied"`
	EmptyOK       int        `json:"empty_ok"`
	Timeouts      int        `json:"timeouts"`
	Errors        int        `json:"errors"`
	AuthDrop      int        `json:"auth_drop"`
	ClosestN      int        `json:"closest_n"`
	ClosestMinXOR string     `json:"closest_min_xor,omitempty"`
	ClosestMaxXOR string     `json:"closest_max_xor,omitempty"`
	ClosestMinCPL int        `json:"closest_min_cpl,omitempty"` // set with closest_min_xor; 0 is valid (far)
	ClosestMaxCPL int        `json:"closest_max_cpl,omitempty"`
}

// EnableTrace starts collecting a hop log for the next iterative query on q.
func (q *Query) EnableTrace() *QueryTrace {
	if q == nil {
		return nil
	}
	q.trace = &QueryTrace{Hops: make([]QueryHop, 0, 32)}
	return q.trace
}

// TraceLog returns the collector set by EnableTrace, or nil.
func (q *Query) TraceLog() *QueryTrace { return q.trace }

// IterQuery exposes the slot engine. hitThreshold=0 exhausts good+unknown;
// hitThreshold>0 returns once that many distinct records are collected.
func (q *Query) IterQuery(ctx context.Context, target a2al.NodeID, findValue bool, recType uint8, hitThreshold int) ([]protocol.SignedRecord, []protocol.NodeInfo, error) {
	if q == nil || q.n == nil {
		return nil, nil, errors.New("dht: nil node")
	}
	return q.runIterQuery(ctx, target, findValue, recType, hitThreshold)
}

func nodeIDHex(id a2al.NodeID) string { return hex.EncodeToString(id[:]) }

func (t *QueryTrace) begin(n *Node, target a2al.NodeID, findValue bool, recType uint8, hitThreshold int) {
	t.Target = nodeIDHex(target)
	t.FindValue = findValue
	t.RecType = recType
	t.HitThreshold = hitThreshold
	selfDist := xorNodeID(n.nid, target)
	t.SelfXOR = nodeIDHex(selfDist)
	t.SelfCPL = xorCPL(selfDist)
	t.Started = time.Now()
}

func (t *QueryTrace) recordHop(r slotRes, findValue bool, recsOK []protocol.SignedRecord) {
	t.Attempted++
	peer := r.peer
	if peer == (a2al.NodeID{}) {
		peer = r.from
	}
	h := QueryHop{
		Wave:     r.wave,
		Track:    trackName(r.track),
		Peer:     nodeIDHex(peer),
		XOR:      nodeIDHex(r.dist),
		CPL:      xorCPL(r.dist),
		Addr:     r.addr,
		RTTMs:    float64(r.rtt) / float64(time.Millisecond),
		Closer:   len(r.nodes),
		RecsWire: len(r.recs),
		RecsOK:   len(recsOK),
	}
	if drop := h.RecsWire - h.RecsOK; drop > 0 {
		t.AuthDrop += drop
	}
	for _, rec := range recsOK {
		h.Recs = append(h.Recs, QueryHopRec{RecType: rec.RecType, Seq: rec.Seq})
	}
	switch {
	case r.err != nil:
		h.Error = r.err.Error()
		if errors.Is(r.err, context.DeadlineExceeded) || errors.Is(r.err, context.Canceled) {
			h.Status = "timeout"
			t.Timeouts++
		} else {
			h.Status = "error"
			t.Errors++
		}
	case r.from == (a2al.NodeID{}):
		h.Status = "error"
		h.Error = "no reply"
		t.Errors++
	case findValue && len(r.recs) == 0:
		h.Status = "empty-ok"
		t.EmptyOK++
	default:
		h.Status = "ok"
	}
	t.Hops = append(t.Hops, h)
}

func (t *QueryTrace) finish(stop string, replied int, outNodes []protocol.NodeInfo, target a2al.NodeID) {
	t.Stop = stop
	t.DurationMs = float64(time.Since(t.Started)) / float64(time.Millisecond)
	t.Replied = replied
	if n := len(outNodes); n > 0 {
		t.ClosestN = n
		var first, last a2al.NodeID
		copy(first[:], outNodes[0].NodeID)
		copy(last[:], outNodes[n-1].NodeID)
		minDist := xorNodeID(first, target)
		maxDist := xorNodeID(last, target)
		t.ClosestMinXOR = nodeIDHex(minDist)
		t.ClosestMaxXOR = nodeIDHex(maxDist)
		t.ClosestMinCPL = xorCPL(minDist)
		t.ClosestMaxCPL = xorCPL(maxDist)
		if n > routing.K {
			t.ClosestN = routing.K
		}
	}
}

func trackName(track int) string {
	switch track {
	case trackGood:
		return "good"
	case trackUnknown:
		return "unknown"
	case trackBad:
		return "bad"
	default:
		return "?"
	}
}
