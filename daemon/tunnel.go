// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/host"
)

// tunnelEntry represents a persistent multiplexed TCP→QUIC tunnel.
// Multiple TCP clients may connect to the local listener concurrently;
// each gets its own QUIC stream on the shared pooled connection.
// The QUIC connection itself is owned by modeAConnPool — tunnel only borrows it.
type tunnelEntry struct {
	id        string
	localAID  a2al.Address
	remoteAID a2al.Address
	listen    string // "127.0.0.1:PORT"
	httpsURL  string // "https://127.0.0.1:PORT" when TLS is available, else ""
	isRelayed bool   // whether the underlying QUIC connection uses a relay path
	noRelay   bool   // whether relay was disabled for this tunnel
	openedAt  time.Time

	// liveness tracking
	lastActivity atomic.Int64 // unix nano; updated on each new TCP accept
	activeConns  atomic.Int32

	// shutdown
	cancel context.CancelFunc
	done   <-chan struct{} // closed when the accept loop exits
}

// tunnelStatus is the JSON-serialisable view of a tunnelEntry.
type tunnelStatus struct {
	ID           string    `json:"id"`
	LocalAID     string    `json:"local_aid"`
	RemoteAID    string    `json:"remote_aid"`
	Listen       string    `json:"listen"`
	HTTPSURL     string    `json:"https_url,omitempty"`
	IsRelayed    bool      `json:"is_relayed"`
	OpenedAt     time.Time `json:"opened_at"`
	LastActivity time.Time `json:"last_activity,omitempty"`
	ActiveConns  int32     `json:"active_conns"`
}

func (e *tunnelEntry) status() tunnelStatus {
	s := tunnelStatus{
		ID:          e.id,
		LocalAID:    e.localAID.String(),
		RemoteAID:   e.remoteAID.String(),
		Listen:      e.listen,
		HTTPSURL:    e.httpsURL,
		IsRelayed:   e.isRelayed,
		OpenedAt:    e.openedAt,
		ActiveConns: e.activeConns.Load(),
	}
	if ns := e.lastActivity.Load(); ns != 0 {
		s.LastActivity = time.Unix(0, ns)
	}
	return s
}

// tunnelRegistry tracks all open tunnels for this daemon session.
type tunnelRegistry struct {
	mu      sync.RWMutex
	entries map[string]*tunnelEntry
}

func newTunnelRegistry() *tunnelRegistry {
	return &tunnelRegistry{entries: make(map[string]*tunnelEntry)}
}

func (r *tunnelRegistry) add(e *tunnelEntry) {
	r.mu.Lock()
	r.entries[e.id] = e
	r.mu.Unlock()
}

func (r *tunnelRegistry) get(id string) (*tunnelEntry, bool) {
	r.mu.RLock()
	e, ok := r.entries[id]
	r.mu.RUnlock()
	return e, ok
}

func (r *tunnelRegistry) delete(id string) {
	r.mu.Lock()
	delete(r.entries, id)
	r.mu.Unlock()
}

func (r *tunnelRegistry) list() []tunnelStatus {
	r.mu.RLock()
	out := make([]tunnelStatus, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.status())
	}
	r.mu.RUnlock()
	return out
}

// closeAll shuts down every active tunnel, used on daemon shutdown.
func (r *tunnelRegistry) closeAll() {
	r.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(r.entries))
	dones := make([]<-chan struct{}, 0, len(r.entries))
	for _, e := range r.entries {
		cancels = append(cancels, e.cancel)
		dones = append(dones, e.done)
	}
	r.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	// Each accept loop's defer calls d.tunnels.delete(entry.id) before
	// closing its done channel, so by the time all <-done unblock the
	// registry is already empty. No second lock needed.
	for _, done := range dones {
		<-done
	}
}

// ── tunnel open/close ────────────────────────────────────────────────────────

const tunnelDefaultIdleTimeout = 6 * time.Minute

// tunnelOpenReq is the body for POST /tunnel/{aid}.
type tunnelOpenReq struct {
	LocalAID       string `json:"local_aid,omitempty"`
	IdleTimeoutSec int    `json:"idle_timeout_sec,omitempty"` // 0 = default (6 min), -1 = no timeout
	DisableRelay   *bool  `json:"disable_relay,omitempty"`    // nil = use node default
}

func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// execTunnelOpen resolves the remote agent, acquires a pooled QUIC connection,
// starts a local TCP listener, and runs an accept loop in the background.
// Each accepted TCP connection gets its own QUIC stream (up to the gateway's
// maxStreamsPerConn=100 limit). The tunnel holds a retain on the QUIC connection
// for its lifetime; the connection is released (not closed) when the tunnel exits.
func (d *Daemon) execTunnelOpen(ctx context.Context, remoteAidStr string, req tunnelOpenReq) (*tunnelEntry, error) {
	remote, err := a2al.ParseAddress(remoteAidStr)
	if err != nil {
		return nil, errBadAID
	}
	local, err := d.pickLocalAgent(req.LocalAID)
	if err != nil {
		return nil, err
	}

	// Resolve with 20 s cap, same as execFetch / execConnect.
	rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
	er, err := d.h.Resolve(rctx, remote)
	rcancel()
	if err != nil {
		if d.beacon != nil {
			er, err = d.resolveFromBeacon(ctx, remote)
		}
		if err != nil {
			return nil, errResolve
		}
	}

	nr := resolveNoRelay(req.DisableRelay, d.cfg.DisableRelay)
	qc, isRelayed, err := d.connPool.acquire(ctx, local, remote, er, nr)
	if err != nil {
		if errors.Is(err, host.ErrRelayRequired) {
			return nil, err
		}
		return nil, errConnectQUIC
	}
	// Hold a reference so the idle evictor does not close this connection
	// while the tunnel is active. Released in the accept loop's defer.
	d.connPool.retain(local, remote, nr)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		d.connPool.release(local, remote, nr)
		return nil, errListen
	}

	tctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var idleTimeout time.Duration
	switch {
	case req.IdleTimeoutSec > 0:
		idleTimeout = time.Duration(req.IdleTimeoutSec) * time.Second
	case req.IdleTimeoutSec == 0:
		idleTimeout = tunnelDefaultIdleTimeout
	// req.IdleTimeoutSec < 0: no idle timeout (idleTimeout stays 0)
	}

	listenAddr := ln.Addr().String()
	httpsURL := ""
	if d.tunnelTLS != nil {
		httpsURL = "https://" + listenAddr
	}
	entry := &tunnelEntry{
		id:        randomID(),
		localAID:  local,
		remoteAID: remote,
		listen:    listenAddr,
		httpsURL:  httpsURL,
		isRelayed: isRelayed,
		noRelay:   nr,
		openedAt:  time.Now(),
		cancel:    cancel,
		done:      done,
	}
	entry.lastActivity.Store(time.Now().UnixNano())

	d.tunnels.add(entry)

	go func() {
		defer func() {
			_ = ln.Close()
			d.tunnels.delete(entry.id)
			d.connPool.release(local, remote, entry.noRelay)
			close(done)
		}()

		// Shut down the listener when the QUIC connection dies or the tunnel
		// is explicitly cancelled. ln.Close() unblocks the Accept() call in
		// the main loop below; calling it multiple times is safe (net.Listener
		// returns an error on subsequent closes, which we ignore with _ =).
		go func() {
			select {
			case <-qc.Context().Done():
				d.log.Debug("tunnel: quic died, closing listener", "id", entry.id)
				cancel()
			case <-tctx.Done():
			}
			_ = ln.Close() // unblock Accept()
		}()

		// Idle watcher: close when no new connections for idleTimeout.
		// Only started when idleTimeout > 0; a negative IdleTimeoutSec disables it.
		if idleTimeout > 0 {
			go func() {
				tick := time.NewTicker(10 * time.Second)
				defer tick.Stop()
				for {
					select {
					case <-tctx.Done():
						return
					case <-tick.C:
						idle := time.Since(time.Unix(0, entry.lastActivity.Load()))
						if entry.activeConns.Load() == 0 && idle >= idleTimeout {
					d.log.Debug("tunnel: idle timeout", "id", entry.id, "idle", idle)
						cancel()
						_ = ln.Close() // unblock Accept()
						return
						}
					}
				}
			}()
		}

		d.log.Debug("tunnel: listening", "id", entry.id, "listen", entry.listen,
			"local", local.String(), "remote", remote.String())

		for {
			tcpConn, err := ln.Accept()
			if err != nil {
				// Listener closed (cancel, QUIC death, or idle timeout).
				return
			}
			entry.lastActivity.Store(time.Now().UnixNano())
			entry.activeConns.Add(1)

			go func() {
				defer entry.activeConns.Add(-1)
				openCtx, openCancel := context.WithTimeout(tctx, 30*time.Second)
				defer openCancel()
				qs, err := qc.OpenStreamSync(openCtx)
				if err != nil {
					d.log.Warn("tunnel: open stream failed", "id", entry.id, "err", err)
					_ = tcpConn.Close()
					return
				}
				// Sniff and optionally upgrade to TLS so the browser
				// can use https://127.0.0.1:PORT with the persisted
				// self-signed certificate.
				conn := sniffAndUpgrade(tcpConn, d.tunnelTLS)
				bridgeTCPQUICStream(qs, conn)
			}()
		}
	}()

	return entry, nil
}

// closeTunnel cancels and waits for the tunnel accept loop to exit.
// Returns false if the id was not found.
func (d *Daemon) closeTunnel(id string) bool {
	e, ok := d.tunnels.get(id)
	if !ok {
		return false
	}
	e.cancel()
	<-e.done
	return true
}
