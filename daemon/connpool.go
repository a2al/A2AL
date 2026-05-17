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
	// connPoolMaxSize caps the number of cached outbound Mode A connections
	// as a safety net against connection leaks. Normal pool size is bounded
	// naturally by idle eviction (connPoolIdleTimeout); this hard cap only
	// fires if something creates connections much faster than they are used.
	connPoolMaxSize = 256

	// connPoolIdleTimeout is the maximum time a cached connection may sit
	// unused before the background evictor closes it. Connections in active
	// use (tunnel, streaming fetch) are never idle, so only genuinely dormant
	// connections are affected.
	connPoolIdleTimeout = 5 * time.Minute

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
	local   a2al.Address
	remote  a2al.Address
	noRelay bool // when true, only direct (no TURN relay) connections are cached here
}

func (k connPoolKey) String() string {
	if k.noRelay {
		return k.local.String() + "→" + k.remote.String() + "(direct)"
	}
	return k.local.String() + "→" + k.remote.String()
}

// connPoolEntry holds one cached connection or a failure-backoff record.
type connPoolEntry struct {
	conn       quic.Connection // nil when in backoff
	refs       int32           // active long-lived users (tunnels); evictor skips when > 0
	isRelayed  bool            // true when the connection uses a TURN relay path
	lastUsed   time.Time
	failCount  int
	lastFailAt time.Time
}

// dialFunc is the dialing strategy injected at construction.
// noRelay requests a direct-only connection (no TURN relay candidates).
// The pool does not import host directly, keeping the dependency direction clean.
type dialFunc func(ctx context.Context, local, remote a2al.Address, er *protocol.EndpointRecord, noRelay bool) (quic.Connection, bool, error)

// modeAConnPool caches outbound data-plane QUIC connections for reuse across
// execConnect, execFetch, and execTunnelOpen calls. Connections are established
// lazily and evicted in three ways:
//   - passively on next acquire when the QUIC context is already dead
//   - proactively by the background idle evictor after connPoolIdleTimeout,
//     but only when refs == 0 (no active tunnels hold the connection)
//   - via LRU when the pool exceeds connPoolMaxSize (safety-net only)
//
// Lifecycle: defaultQUICConfig sends QUIC PING keepalives every 25 s, so
// connections remain live as long as the network path holds. Long-lived users
// (tunnels) call retain/release to increment/decrement refs; the evictor skips
// any connection with refs > 0, preventing premature closure of active tunnels.
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
// noRelay=true requests a direct-only connection (relay candidates excluded).
// Returns the connection and whether it uses a relay path.
// er must be a freshly resolved EndpointRecord for remote; the caller resolves
// it so that any reconnect after a dead-connection eviction uses current data.
//
// On a network failure the entry is kept as a backoff record; subsequent calls
// within the backoff window return immediately without dialing.
// Context cancellation (caller hang-up) does NOT set a backoff record.
func (p *modeAConnPool) acquire(ctx context.Context, local, remote a2al.Address, er *protocol.EndpointRecord, noRelay bool) (quic.Connection, bool, error) {
	key := connPoolKey{local, remote, noRelay}

	// ── Fast path: return a cached live connection ────────────────────────
	p.mu.Lock()
	if ent, ok := p.pool[key]; ok {
		switch {
		case ent.conn != nil && ent.conn.Context().Err() == nil:
			// Alive: update lastUsed and return.
			ent.lastUsed = time.Now()
			conn := ent.conn
			relayed := ent.isRelayed
			p.mu.Unlock()
			return conn, relayed, nil

		case ent.conn != nil:
			// Dead connection: evict and fall through to re-dial.
			p.log.Debug("connpool: evicting dead connection", "key", key.String())
			delete(p.pool, key)

		case !ent.lastFailAt.IsZero():
			// Backoff entry: check whether the window has elapsed.
			if time.Since(ent.lastFailAt) < connPoolBackoff(ent.failCount) {
				p.mu.Unlock()
				return nil, false, errors.New("a2al/daemon: connect in backoff, try again later")
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

	type dialResult struct {
		conn      quic.Connection
		isRelayed bool
	}
	v, err, _ := p.flight.Do(key.String(), func() (any, error) {
		defer dialCancel()
		p.log.Debug("connpool: dialing", "local", local.String(), "remote", remote.String(), "no_relay", noRelay)
		conn, isRelayed, dialErr := p.dial(dialCtx, local, remote, er, noRelay)

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
		p.pool[key] = &connPoolEntry{conn: conn, isRelayed: isRelayed, lastUsed: time.Now()}
		p.log.Debug("connpool: connection cached", "key", key.String(), "is_relayed", isRelayed)
		return dialResult{conn, isRelayed}, nil
	})
	if err != nil {
		// dialCancel may already have been called inside the flight func;
		// calling it again is a no-op.
		dialCancel()
		return nil, false, err
	}
	dialCancel()
	dr := v.(dialResult)
	return dr.conn, dr.isRelayed, nil
}

// evictIfFull removes the least-recently-used evictable entry when at capacity.
// Entries with active refs (live tunnels) are skipped, so the pool may briefly
// exceed connPoolMaxSize if all entries are in use — protecting active tunnels
// takes precedence over the hard cap. Must be called with p.mu held. The evicted
// connection is closed after the lock is released to avoid holding the mutex
// during I/O.
func (p *modeAConnPool) evictIfFull() {
	if len(p.pool) < connPoolMaxSize {
		return
	}
	var oldest connPoolKey
	var oldestTime time.Time
	found := false
	for k, ent := range p.pool {
		if ent.refs > 0 {
			// Never evict connections with active long-lived users.
			continue
		}
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

// startIdleEvictor runs a background goroutine that closes connections that
// have not been used for connPoolIdleTimeout. It returns when ctx is cancelled.
// Call once from the daemon's Run loop.
func (p *modeAConnPool) startIdleEvictor(ctx context.Context) {
	ticker := time.NewTicker(connPoolIdleTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.evictIdle()
		}
	}
}

func (p *modeAConnPool) evictIdle() {
	p.mu.Lock()
	var toClose []quic.Connection
	for k, ent := range p.pool {
		if ent.conn != nil && ent.refs == 0 && time.Since(ent.lastUsed) > connPoolIdleTimeout {
			toClose = append(toClose, ent.conn)
			delete(p.pool, k)
			p.log.Debug("connpool: evicting idle connection", "key", k.String())
		}
	}
	p.mu.Unlock()
	for _, c := range toClose {
		_ = c.CloseWithError(0, "idle timeout")
	}
}

// getLive returns a cached live QUIC connection without dialing.
// Returns nil if no live connection is cached for (local, remote).
// Used by M6 QUIC direct delivery to check before falling back to DHT.
func (p *modeAConnPool) getLive(local, remote a2al.Address) quic.Connection {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Try noRelay=false first (most common), then noRelay=true.
	for _, noRelay := range []bool{false, true} {
		key := connPoolKey{local, remote, noRelay}
		if ent, ok := p.pool[key]; ok && ent.conn != nil && ent.conn.Context().Err() == nil {
			ent.lastUsed = time.Now()
			return ent.conn
		}
	}
	return nil
}

// retain increments the active-user count for the connection identified by
// (local, remote, noRelay). While refs > 0 the background evictor will not close the
// connection. Call once after a successful acquire for any long-lived use.
func (p *modeAConnPool) retain(local, remote a2al.Address, noRelay bool) {
	key := connPoolKey{local, remote, noRelay}
	p.mu.Lock()
	if ent, ok := p.pool[key]; ok {
		ent.refs++
	}
	p.mu.Unlock()
}

// release decrements the active-user count. When refs reaches zero the
// connection becomes eligible for normal idle eviction.
func (p *modeAConnPool) release(local, remote a2al.Address, noRelay bool) {
	key := connPoolKey{local, remote, noRelay}
	p.mu.Lock()
	if ent, ok := p.pool[key]; ok && ent.refs > 0 {
		ent.refs--
	}
	p.mu.Unlock()
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
