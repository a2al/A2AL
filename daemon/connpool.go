// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

const (
	// connPoolMaxSize caps the number of cached outbound Mode A connections.
	// Small by design: fetch is on-demand; we are not an "octopus" node.
	connPoolMaxSize = 8

	// connPoolDialTimeout is the independent timeout for a single dial attempt.
	// Deliberately decoupled from the caller's context so that a user hang-up
	// does not set a backoff record or abort in-flight singleflight waiters.
	connPoolDialTimeout = 60 * time.Second

	// connPoolBackoffBase / Max bound the exponential backoff after a network failure.
	connPoolBackoffBase = 15 * time.Second
	connPoolBackoffMax  = 5 * time.Minute
)

// connPoolKey identifies a cached outbound connection.
type connPoolKey struct {
	local  a2al.Address
	remote a2al.Address
}

func (k connPoolKey) String() string {
	return k.local.String() + "→" + k.remote.String()
}

// connPoolEntry holds one cached connection or a failure-backoff record.
type connPoolEntry struct {
	conn       quic.Connection // nil when in backoff
	lastUsed   time.Time
	failCount  int
	lastFailAt time.Time
}

// dialFunc is the dialing strategy injected at construction.
// The pool does not import host directly, keeping the dependency direction clean.
type dialFunc func(ctx context.Context, local, remote a2al.Address, er *protocol.EndpointRecord) (quic.Connection, error)

// modeAConnPool caches outbound data-plane QUIC connections for reuse across
// execConnect and execFetch calls. Connections are established lazily, evicted
// passively (dead-on-use detection) or via LRU when the pool is at capacity.
//
// Lifecycle: no keepalive pings are sent — connections live as long as QUIC
// considers them alive (MaxIdleTimeout from defaultQUICConfig, currently 90 s).
// If a connection dies between calls, acquire detects it and reconnects.
type modeAConnPool struct {
	mu     sync.Mutex
	pool   map[connPoolKey]*connPoolEntry
	flight singleflight.Group
	dial   dialFunc
	log    *slog.Logger
}

func newModeAConnPool(dial dialFunc, log *slog.Logger) *modeAConnPool {
	return &modeAConnPool{
		pool: make(map[connPoolKey]*connPoolEntry),
		dial: dial,
		log:  log,
	}
}

// acquire returns a live QUIC connection for (local → remote).
// er must be a freshly resolved EndpointRecord for remote; the caller resolves
// it so that any reconnect after a dead-connection eviction uses current data.
//
// On a network failure the entry is kept as a backoff record; subsequent calls
// within the backoff window return immediately without dialing.
// Context cancellation (caller hang-up) does NOT set a backoff record.
func (p *modeAConnPool) acquire(ctx context.Context, local, remote a2al.Address, er *protocol.EndpointRecord) (quic.Connection, error) {
	key := connPoolKey{local, remote}

	// ── Fast path: return a cached live connection ────────────────────────
	p.mu.Lock()
	if ent, ok := p.pool[key]; ok {
		switch {
		case ent.conn != nil && ent.conn.Context().Err() == nil:
			// Alive: update lastUsed and return.
			ent.lastUsed = time.Now()
			conn := ent.conn
			p.mu.Unlock()
			return conn, nil

		case ent.conn != nil:
			// Dead connection: evict and fall through to re-dial.
			p.log.Debug("connpool: evicting dead connection", "key", key.String())
			delete(p.pool, key)

		case !ent.lastFailAt.IsZero():
			// Backoff entry: check whether the window has elapsed.
			if time.Since(ent.lastFailAt) < connPoolBackoff(ent.failCount) {
				p.mu.Unlock()
				return nil, errors.New("a2al/daemon: connect in backoff, try again later")
			}
			// Backoff elapsed: remove and try again.
			delete(p.pool, key)
		}
	}
	p.mu.Unlock()

	// ── Slow path: dial, deduplicated via singleflight ────────────────────
	//
	// The dial context is intentionally decoupled from the caller's ctx:
	//   1. A caller hang-up must not abort the dial for other singleflight
	//      waiters that share the same in-flight attempt.
	//   2. A caller-cancelled context must not be mistaken for a network
	//      failure and written as a backoff record.
	// We use context.WithoutCancel so that the dial inherits values (e.g.
	// trace spans) but not the cancellation signal, and cap it independently.
	dialCtx, dialCancel := context.WithTimeout(context.WithoutCancel(ctx), connPoolDialTimeout)

	v, err, _ := p.flight.Do(key.String(), func() (any, error) {
		defer dialCancel()
		p.log.Debug("connpool: dialing", "local", local.String(), "remote", remote.String())
		conn, dialErr := p.dial(dialCtx, local, remote, er)

		p.mu.Lock()
		defer p.mu.Unlock()

		if dialErr != nil {
			// Only record backoff for genuine network failures. Context
			// cancellation from the dial timeout itself is also a network
			// event, so we treat DeadlineExceeded as a failure but skip
			// Canceled (which can only come from our own dialCancel after a
			// successful dial path, or from an upstream cancellation that
			// somehow propagated — neither should penalise the pool).
			if !errors.Is(dialErr, context.Canceled) {
				ent := p.pool[key]
				if ent == nil {
					ent = &connPoolEntry{}
				}
				ent.conn = nil
				ent.failCount++
				ent.lastFailAt = time.Now()
				p.pool[key] = ent
				p.log.Debug("connpool: dial failed", "key", key.String(),
					"fail_count", ent.failCount, "backoff", connPoolBackoff(ent.failCount), "err", dialErr)
			}
			return nil, dialErr
		}

		p.evictIfFull()
		p.pool[key] = &connPoolEntry{conn: conn, lastUsed: time.Now()}
		p.log.Debug("connpool: connection cached", "key", key.String())
		return conn, nil
	})
	if err != nil {
		// dialCancel may already have been called inside the flight func;
		// calling it again is a no-op.
		dialCancel()
		return nil, err
	}
	dialCancel()
	return v.(quic.Connection), nil
}

// evictIfFull removes the least-recently-used entry when at capacity.
// Must be called with p.mu held. The evicted connection is closed after
// the lock is released to avoid holding the mutex during I/O.
func (p *modeAConnPool) evictIfFull() {
	if len(p.pool) < connPoolMaxSize {
		return
	}
	var oldest connPoolKey
	var oldestTime time.Time
	found := false
	for k, ent := range p.pool {
		if ent.conn == nil {
			// Prefer evicting dead/backoff entries first (no I/O needed).
			oldest = k
			found = true
			break
		}
		if !found || ent.lastUsed.Before(oldestTime) {
			oldest = k
			oldestTime = ent.lastUsed
			found = true
		}
	}
	if !found {
		return
	}
	toClose := p.pool[oldest].conn // may be nil for backoff entries
	delete(p.pool, oldest)
	p.log.Debug("connpool: evicted LRU entry", "key", oldest.String())

	// Close outside the lock to avoid holding the mutex during network I/O.
	if toClose != nil {
		go func() { _ = toClose.CloseWithError(0, "pool eviction") }()
	}
}

// Close shuts down all cached connections and clears the pool.
// It is safe to call concurrently and is idempotent.
func (p *modeAConnPool) Close() {
	p.mu.Lock()
	conns := make([]quic.Connection, 0, len(p.pool))
	for _, ent := range p.pool {
		if ent.conn != nil {
			conns = append(conns, ent.conn)
		}
	}
	p.pool = make(map[connPoolKey]*connPoolEntry)
	p.mu.Unlock()

	for _, c := range conns {
		_ = c.CloseWithError(0, "pool closed")
	}
}

// connPoolBackoff returns the backoff duration for n consecutive failures.
func connPoolBackoff(n int) time.Duration {
	if n <= 0 {
		return connPoolBackoffBase
	}
	d := connPoolBackoffBase
	for i := 1; i < n; i++ {
		d *= 2
		if d >= connPoolBackoffMax {
			return connPoolBackoffMax
		}
	}
	return d
}
