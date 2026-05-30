// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// iceTransportWin holds the transport resources from a successful non-relay ICE
// dial on the caller side. Returned by tryICEViaHub when the ICE path wins.
// The caller is responsible for either registering it in the pool (to enable
// reuse for subsequent agents on the same remote node) or closing it.
type iceTransportWin struct {
	tr         *quic.Transport
	sess       *iceSession
	remoteAddr *net.UDPAddr
}

func (w *iceTransportWin) close() {
	_ = w.tr.Close()
	w.sess.Close()
}

// nodeTransportPool caches ICE-established quic.Transport instances on the
// caller side, keyed by the remote host's endpoint fingerprint.
//
// When a second or subsequent agent on the same remote a2ald instance is
// dialled, the pool lets QUIC reuse the existing hole-punched transport rather
// than running a new ICE negotiation.
//
// Lifecycle: each entry's transport is kept alive as long as at least one QUIC
// connection on it is open (tracked via refs). When the last connection closes,
// refs reaches zero and the transport + ICE session are closed automatically.
// When a probe dial fails (peer rebooted, path changed), the entry is removed
// from the pool but the transport is still closed only once the last active
// connection drains — this prevents evict from killing a connection on the
// same transport that is still in use.
type nodeTransportPool struct {
	mu   sync.Mutex
	pool map[string]*nodeTransportEntry
	log  *slog.Logger
}

type nodeTransportEntry struct {
	tr         *quic.Transport
	sess       *iceSession
	remoteAddr *net.UDPAddr
	key        string
	refs       atomic.Int32
}

func newNodeTransportPool(log *slog.Logger) *nodeTransportPool {
	return &nodeTransportPool{
		pool: make(map[string]*nodeTransportEntry),
		log:  log,
	}
}

// tryDial attempts a new QUIC connection on a cached transport (500 ms timeout).
// Returns nil if no entry exists or the dial fails. On failure the entry is
// removed from the pool (stopping future reuse), but its resources are only
// released once all currently active connections on it have closed.
func (p *nodeTransportPool) tryDial(ctx context.Context, key string,
	cert tls.Certificate, expectRemote a2al.Address) quic.Connection {

	p.mu.Lock()
	e := p.pool[key]
	p.mu.Unlock()
	if e == nil {
		return nil
	}

	probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	cliTLS, err := quicClientTLSWithCert(cert, expectRemote)
	if err != nil {
		return nil
	}
	qc, err := e.tr.Dial(probeCtx, e.remoteAddr, cliTLS, defaultQUICConfig())
	if err != nil {
		p.log.Debug("node transport: probe failed, removing", "remote", e.remoteAddr, "err", err)
		// Remove from pool so no new connections are attempted on this transport.
		// The transport itself is closed by releaseRef once all active
		// connections (including the original firstQC) have drained.
		p.evict(key)
		return nil
	}
	e.refs.Add(1)
	go func() { <-qc.Context().Done(); p.releaseRef(e) }()
	return qc
}

// register stores a transport entry after a successful ICE dial.
// firstQC is the initial QUIC connection that triggered the ICE dial; the pool
// holds one ref on its behalf and releases it when firstQC closes.
// Ownership of win.tr and win.sess transfers to the pool.
func (p *nodeTransportPool) register(key string, win *iceTransportWin, firstQC quic.Connection) {
	e := &nodeTransportEntry{
		tr:         win.tr,
		sess:       win.sess,
		remoteAddr: win.remoteAddr,
		key:        key,
	}
	e.refs.Store(1) // one ref held on behalf of firstQC

	p.mu.Lock()
	// Any previous entry for this key is simply overwritten in the map.
	// Its own refs goroutines remain active and will call releaseRef when
	// all connections on it close — we do not force-close it here.
	p.pool[key] = e
	p.mu.Unlock()

	p.log.Debug("node transport: registered", "remote", win.remoteAddr)
	go func() { <-firstQC.Context().Done(); p.releaseRef(e) }()
}

// evict removes an entry from the pool map without closing its resources.
// Actual cleanup happens in releaseRef once refs reaches zero.
func (p *nodeTransportPool) evict(key string) {
	p.mu.Lock()
	delete(p.pool, key)
	p.mu.Unlock()
}

// releaseRef decrements e's reference count. When it reaches zero the
// transport and session are closed, and the entry is removed from the pool
// if it hasn't already been replaced by a newer entry.
func (p *nodeTransportPool) releaseRef(e *nodeTransportEntry) {
	if e.refs.Add(-1) == 0 {
		p.mu.Lock()
		if p.pool[e.key] == e { // guard: don't evict a replacement entry
			delete(p.pool, e.key)
		}
		p.mu.Unlock()
		_ = e.tr.Close()
		e.sess.Close()
		p.log.Debug("node transport: closed (last ref released)", "remote", e.remoteAddr)
	}
}

// nodeTransportKey derives a stable host fingerprint from an EndpointRecord.
// All agents on the same a2ald instance publish identical Endpoints and
// Signals, so this key is the same for every AID hosted on that node.
func nodeTransportKey(er *protocol.EndpointRecord) string {
	if er == nil {
		return ""
	}
	eps := make([]string, len(er.Endpoints))
	copy(eps, er.Endpoints)
	slices.Sort(eps)

	sigs := make([]string, len(er.Signals), len(er.Signals)+1)
	copy(sigs, er.Signals)
	if er.Signal != "" {
		sigs = append(sigs, er.Signal)
	}
	slices.Sort(sigs)
	sigs = slices.Compact(sigs)
	if len(sigs) > 0 && sigs[0] == "" {
		sigs = sigs[1:]
	}
	return strings.Join(eps, "\x00") + "\x01" + strings.Join(sigs, "\x00")
}
