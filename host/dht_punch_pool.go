// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

// DHTpunchPool is the host-layer implementation of dht.PunchTransport.
//
// It manages:
//   - The punched-connection pool (nodeID → active QUIC connection)
//   - The punch scheduler goroutine and priority queue
//   - ICE negotiation via the Host's existing connectViaICESignal path
//
// Architecture note (§15, dual-plane):
//   - Connections owned here are Mode B (control-plane QUIC), completely
//     separate from Mode A (data-plane AgentConn). They are never exposed
//     to application code; their sole purpose is carrying DHT messages.
//   - The host layer (this file) calls dht.Node.OnPunchComplete and
//     dht.Node.InjectReceived; the dht layer calls PunchTransport.SendTo
//     and PunchTransport.Punch via the injected interface. Dependency
//     direction remains: host → dht. DHT never imports host.
//
// Phase 2 status — skeleton only:
//   - SendTo: always returns ok=false (no connection pool yet).
//   - Punch: accepts requests but does not perform ICE (logged only).
//   - Wire up ICE dialing and the pool in Phase 4 alongside the
//     routing-table integration (Phase 3).

import (
	"context"
	"log/slog"
	"sync"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/protocol"
)

// DHTpunchPool implements dht.PunchTransport for the host layer.
// Create via NewDHTpunchPool; inject the result into dht.Config.PunchTransport
// before calling dht.NewNode.
type DHTpunchPool struct {
	node *dht.Node
	log  *slog.Logger

	mu   sync.Mutex
	// pool maps nodeID key → active punched QUIC connection.
	// Phase 2: always empty. Phase 4: populated after successful ICE.
	// pool map[string]quic.Connection  // uncommented in Phase 4
}

// NewDHTpunchPool creates a DHTpunchPool bound to node. The pool registers
// itself as the punch result callback target via node.OnPunchComplete.
func NewDHTpunchPool(node *dht.Node, log *slog.Logger) *DHTpunchPool {
	if log == nil {
		log = slog.Default()
	}
	return &DHTpunchPool{
		node: node,
		log:  log,
	}
}

// SendTo implements dht.PunchTransport.
//
// Phase 2: always returns ok=false — the connection pool is empty. DHT will
// fall back to UDP for every send, preserving existing behaviour exactly.
// Phase 4: look up nodeID in the pool; if found, open a QUIC stream and write msg.
func (p *DHTpunchPool) SendTo(_ context.Context, _ a2al.NodeID, _ []byte) (bool, error) {
	// Phase 4: check pool, open stream, write.
	return false, nil
}

// Punch implements dht.PunchTransport.
//
// Phase 2: logs the request and returns immediately without performing ICE.
// The node's isPunching flag (set by the DHT layer before calling Punch) will
// be cleared by a call to node.OnPunchComplete(nodeID, nil, false) from the
// scheduler. For Phase 2 we call it inline so DHT does not get stuck with
// isPunching=true forever.
//
// Phase 4: enqueue into a priority queue; scheduler goroutine dequeues and
// calls h.connectViaICESignal, then calls node.OnPunchComplete with the
// ICE-negotiated peer address and result.
func (p *DHTpunchPool) Punch(nodeID a2al.NodeID, er *protocol.EndpointRecord, priority int) {
	p.log.Debug("dht punch requested (Phase 2: no-op)",
		"node", nodeID,
		"signal", er.Signal,
		"nat_type", er.NatType,
		"priority", priority,
	)
	// Phase 2: immediately report failure so isPunching is cleared and DHT
	// does not permanently exclude this node from query tracks.
	p.node.OnPunchComplete(nodeID, a2al.Address{}, nil, false)
}
