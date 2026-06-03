// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

// DHTpunchPool is the host-layer implementation of dht.PunchTransport.
//
// It manages:
//   - The punched-connection pool (nodeID → active Mode B QUIC connection)
//   - ICE negotiation as caller (Punch) and as callee (HandleIncomingPunch)
//   - Message injection into the DHT node via InjectReceived
//
// Architecture note (§15, dual-plane):
//   - Connections owned here are Mode B (control-plane QUIC), completely
//     separate from Mode A (data-plane AgentConn). They are never exposed
//     to application code; their sole purpose is carrying DHT messages.
//   - The host layer calls dht.Node.OnPunchComplete and dht.Node.InjectReceived;
//     the dht layer calls PunchTransport.SendTo and PunchTransport.Punch via
//     the injected interface. Dependency direction: host → dht only.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/dht"
	"github.com/a2al/a2al/protocol"
	"github.com/a2al/a2al/signaling"
)

const (
	// maxDHTPunchMsg caps a single DHT message read from a Mode B stream.
	maxDHTPunchMsg = 64 << 10 // 64 KiB
	// punchDialTimeout limits end-to-end ICE+QUIC dial time for a single attempt.
	punchDialTimeout = 60 * time.Second
)

// modeBConn is a single Mode B (DHT control-plane) QUIC connection entry.
type modeBConn struct {
	qc     quic.Connection
	cancel context.CancelFunc // cancels the runReadLoop goroutine
}

// DHTpunchPool implements dht.PunchTransport for the host layer.
//
// Lifecycle: create with newDHTpunchPool before dht.NewNode, inject into
// dht.Config.PunchTransport, then call bind(host) after the Host is fully
// initialised. This two-phase setup avoids the dht.Node / Host circular init.
type DHTpunchPool struct {
	log *slog.Logger

	// h is set by bind() after the Host is fully constructed.
	// All methods that need h check for nil and degrade gracefully.
	h *Host

	mu   sync.Mutex
	pool map[a2al.NodeID]*modeBConn // nodeID → active connection
}

// newDHTpunchPool creates an unbound pool. Call bind(host) after host creation.
func newDHTpunchPool(log *slog.Logger) *DHTpunchPool {
	if log == nil {
		log = slog.Default()
	}
	return &DHTpunchPool{
		log:  log,
		pool: make(map[a2al.NodeID]*modeBConn),
	}
}

// bind wires the pool to its owning Host. Called from host.New after the Host
// struct is fully populated.
func (p *DHTpunchPool) bind(h *Host) { p.h = h }

// node returns the DHT node via the host reference, or nil if not yet bound.
func (p *DHTpunchPool) node() interface {
	OnPunchComplete(a2al.NodeID, a2al.Address, net.Addr, bool, bool, dht.PunchFailReason)
	InjectReceived([]byte, net.Addr)
} {
	if p.h == nil {
		return nil
	}
	return p.h.node
}

// SendTo implements dht.PunchTransport.
// Looks up the Mode B connection for nodeID; if found, opens a QUIC stream and
// writes msg. Returns (false, nil) when no connection is available so the DHT
// falls back to UDP transparently.
func (p *DHTpunchPool) SendTo(ctx context.Context, nodeID a2al.NodeID, msg []byte) (bool, error) {
	p.mu.Lock()
	mb, ok := p.pool[nodeID]
	p.mu.Unlock()
	if !ok {
		return false, nil
	}

	st, err := mb.qc.OpenStreamSync(ctx)
	if err != nil {
		p.removeConn(nodeID)
		return false, nil
	}
	defer st.Close()

	if _, err := st.Write(msg); err != nil {
		p.removeConn(nodeID)
		return false, nil
	}
	return true, nil
}

// Punch implements dht.PunchTransport.
// Spawns a goroutine that dials ICE → QUIC (Mode B) and calls OnPunchComplete.
func (p *DHTpunchPool) Punch(nodeID a2al.NodeID, er *protocol.EndpointRecord, priority int) {
	p.log.Debug("dht punch requested", "node", nodeID, "signal", er.Signal, "priority", priority)

	if p.h == nil {
		p.log.Warn("dht punch: pool not bound to host, reporting failure")
		if n := p.node(); n != nil {
			n.OnPunchComplete(nodeID, a2al.Address{}, nil, false, false, dht.PunchFailOther)
		}
		return
	}
	if er.Address == p.h.addr {
		p.log.Debug("dht punch: skipped self endpoint", "node", nodeID)
		if n := p.node(); n != nil {
			n.OnPunchComplete(nodeID, a2al.Address{}, nil, false, false, dht.PunchFailOther)
		}
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), punchDialTimeout)
		defer cancel()

		qc, peerUDP, isDirect, err := p.h.connectViaICEForDHT(ctx, er)
		n := p.node()
		if err != nil {
			reason := dht.PunchFailOther
			if errors.Is(err, ErrNoAgent) {
				reason = dht.PunchFailNoAgent
			}
			p.log.Debug("dht punch ice dial failed", "node", nodeID, "err", err, "reason", reason)
			if n != nil {
				n.OnPunchComplete(nodeID, a2al.Address{}, nil, false, false, reason)
			}
			return
		}

		p.addConn(nodeID, qc)
		if n != nil {
			n.OnPunchComplete(nodeID, er.Address, peerUDP, true, isDirect, dht.PunchFailNone)
		}
	}()
}

// HandleIncomingPunch is called by the daemon ICE listener when a Mode B punch
// incoming is received (fr.Target == nodeAddr). It runs ICE as controlled,
// accepts a QUIC connection, and calls OnPunchComplete on the DHT node.
func (p *DHTpunchPool) HandleIncomingPunch(ctx context.Context, callerNodeID a2al.NodeID, callerLogicalAddr a2al.Address, signalBase, room string) {
	if p.h == nil {
		p.log.Warn("dht punch accept: pool not bound to host")
		return
	}
	if callerLogicalAddr == p.h.addr {
		p.log.Debug("dht punch accept: skipped self caller", "caller", callerLogicalAddr)
		return
	}

	wsURL, err := signaling.AppendRoomToICEURL(signalBase, room)
	if err != nil {
		p.log.Debug("dht punch accept: bad signal url", "base", signalBase, "err", err)
		return
	}

	nodeCert, err := p.h.defaultAgentCert()
	if err != nil {
		p.log.Warn("dht punch accept: no node cert", "err", err)
		return
	}

	qc, peerUDP, isDirect, _, teardown, err := p.h.acceptICEToQUIC(ctx, wsURL, nodeCert, modeBQUICConfig(), callerLogicalAddr, nil, true)
	n := p.node()
	if err != nil {
		p.log.Debug("dht punch accept: ice failed", "caller", callerNodeID, "err", err)
		if n != nil {
			n.OnPunchComplete(callerNodeID, callerLogicalAddr, nil, false, false, dht.PunchFailICETimeout)
		}
		return
	}

	p.addConn(callerNodeID, qc)
	go func() {
		<-qc.Context().Done()
		teardown()
	}()

	if n != nil {
		n.OnPunchComplete(callerNodeID, callerLogicalAddr, peerUDP, true, isDirect, dht.PunchFailNone)
	}
}

// addConn registers a Mode B QUIC connection and starts the read loop.
// If a previous connection for the same nodeID exists it is closed first.
func (p *DHTpunchPool) addConn(nodeID a2al.NodeID, qc quic.Connection) {
	ctx, cancel := context.WithCancel(context.Background())
	mb := &modeBConn{qc: qc, cancel: cancel}

	p.mu.Lock()
	if old, ok := p.pool[nodeID]; ok {
		old.cancel()
	}
	p.pool[nodeID] = mb
	p.mu.Unlock()

	go p.runReadLoop(ctx, nodeID, qc)
}

// removeConn removes a connection from the pool and cancels its read loop.
func (p *DHTpunchPool) removeConn(nodeID a2al.NodeID) {
	p.mu.Lock()
	mb, ok := p.pool[nodeID]
	if ok {
		delete(p.pool, nodeID)
	}
	p.mu.Unlock()
	if ok {
		mb.cancel()
	}
}

// runReadLoop accepts QUIC streams from a Mode B connection and injects each
// message into the DHT node via InjectReceived. Exits when ctx is cancelled or
// the QUIC connection closes.
func (p *DHTpunchPool) runReadLoop(ctx context.Context, nodeID a2al.NodeID, qc quic.Connection) {
	defer p.removeConn(nodeID)
	for {
		st, err := qc.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(s quic.Stream) {
			defer s.Close()
			data, err := io.ReadAll(io.LimitReader(s, maxDHTPunchMsg))
			if err != nil || len(data) == 0 {
				return
			}
			if n := p.node(); n != nil {
				n.InjectReceived(data, qc.RemoteAddr())
			}
		}(st)
	}
}

// ProbeAndPrune tests each cached Mode B connection and evicts dead ones.
// Called at the start of handleNetworkChangeCascade to eliminate stale
// HasConn entries before they can pollute send-plan decisions.
//
// For each entry:
//   - If qc.Context().Err() != nil: already dead, evict immediately (no I/O).
//   - Otherwise: attempt OpenStreamSync; failure → evict.
//     A successful probe opens and immediately closes an empty stream, which
//     is harmless to the remote's runReadLoop (empty data → handler returns).
//
// All probes run concurrently; total elapsed ≤ timeout regardless of pool size.
// Returns the number of evicted connections.
func (p *DHTpunchPool) ProbeAndPrune(timeout time.Duration) int {
	p.mu.Lock()
	type entry struct {
		id a2al.NodeID
		qc quic.Connection
	}
	snapshot := make([]entry, 0, len(p.pool))
	for id, mb := range p.pool {
		snapshot = append(snapshot, entry{id, mb.qc})
	}
	p.mu.Unlock()

	if len(snapshot) == 0 {
		return 0
	}

	// pruneOne evicts the entry only if pool still holds the same qc instance,
	// guarding against a freshly established connection being removed.
	pruneOne := func(id a2al.NodeID, qc quic.Connection) {
		p.mu.Lock()
		mb, ok := p.pool[id]
		if ok && mb.qc == qc {
			delete(p.pool, id)
		} else {
			ok = false
		}
		p.mu.Unlock()
		if ok {
			mb.cancel()
		}
	}

	var pruned atomic.Int32
	var wg sync.WaitGroup
	for _, e := range snapshot {
		if e.qc.Context().Err() != nil {
			// Fast path: QUIC context already cancelled — dead with no I/O needed.
			pruneOne(e.id, e.qc)
			pruned.Add(1)
			continue
		}
		// Slow path: verify with a stream open under timeout.
		wg.Add(1)
		go func(id a2al.NodeID, qc quic.Connection) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			st, err := qc.OpenStreamSync(ctx)
			if err != nil {
				pruneOne(id, qc)
				pruned.Add(1)
				return
			}
			_ = st.Close()
		}(e.id, e.qc)
	}
	wg.Wait()

	n := int(pruned.Load())
	p.log.Info("wake/netchange: punch pool probed",
		"total", len(snapshot), "evicted", n, "kept", len(snapshot)-n)
	return n
}

// HasConn implements dht.PunchTransport.
// Returns true if an active Mode B QUIC connection exists for nodeID.
func (p *DHTpunchPool) HasConn(nodeID a2al.NodeID) bool {
	p.mu.Lock()
	_, ok := p.pool[nodeID]
	p.mu.Unlock()
	return ok
}

// InvalidateConn implements dht.PunchTransport.
// Closes and evicts the Mode B QUIC connection for nodeID.
// Called by the DHT layer when a QUIC-routed RPC times out.
func (p *DHTpunchPool) InvalidateConn(nodeID a2al.NodeID) {
	p.log.Debug("dht punch: invalidating stale conn", "node", nodeID)
	p.removeConn(nodeID)
}

// EvictAll closes and evicts all Mode B QUIC connections.
// Called when the network topology changes: ICE-negotiated paths are bound
// to the old interface/NAT mapping and must be treated as invalid wholesale.
// Re-punch happens naturally on the next DHT RPC via deferICE / replication-probe.
func (p *DHTpunchPool) EvictAll() {
	p.mu.Lock()
	ids := make([]a2al.NodeID, 0, len(p.pool))
	for id := range p.pool {
		ids = append(ids, id)
	}
	p.mu.Unlock()

	for _, id := range ids {
		p.removeConn(id)
	}
	if len(ids) > 0 {
		p.log.Info("dht punch: evicted all conns after network change", "count", len(ids))
	}
}

// ConnCount returns the number of active Mode B connections (for diagnostics).
func (p *DHTpunchPool) ConnCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pool)
}

// Ensure DHTpunchPool satisfies the interface at compile time.
var _ interface {
	SendTo(context.Context, a2al.NodeID, []byte) (bool, error)
	Punch(a2al.NodeID, *protocol.EndpointRecord, int)
	HasConn(a2al.NodeID) bool
} = (*DHTpunchPool)(nil)

