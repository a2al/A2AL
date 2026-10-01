// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
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
	token     string
	openedAt  time.Time

	// liveness tracking
	lastActivity atomic.Int64 // unix nano; updated on each new TCP accept and when the last active conn closes
	activeConns  atomic.Int32

	// data-plane byte counters: cumulative totals across all bridge goroutines.
	// bytesUp = bytes forwarded from local TCP (browser) → remote QUIC stream.
	// bytesDown = bytes forwarded from remote QUIC stream → local TCP (browser).
	bytesUp      atomic.Int64
	bytesDown    atomic.Int64
	lastProgress atomic.Int64 // unix nano; updated whenever either direction advances

	qcMu     sync.Mutex
	qc       quic.Connection
	repairMu sync.Mutex

	// shutdown
	cancel context.CancelFunc
	done   <-chan struct{} // closed when the accept loop exits
}

func (e *tunnelEntry) conn() quic.Connection {
	e.qcMu.Lock()
	defer e.qcMu.Unlock()
	return e.qc
}

func (e *tunnelEntry) setConn(c quic.Connection, relayed bool) {
	e.qcMu.Lock()
	e.qc = c
	e.isRelayed = relayed
	e.qcMu.Unlock()
}

// connLive is true when there is no tracked connection (tests, race) or it
// has not yet closed. A dead QUIC must not be handed back as a reusable tunnel.
func (e *tunnelEntry) connLive() bool {
	c := e.conn()
	return c == nil || c.Context().Err() == nil
}

// tunnelStatus is the JSON-serialisable view of a tunnelEntry.
type tunnelStatus struct {
	ID             string    `json:"id"`
	LocalAID       string    `json:"local_aid"`
	RemoteAID      string    `json:"remote_aid"`
	Listen         string    `json:"listen"`
	HTTPSURL       string    `json:"https_url,omitempty"`
	IsRelayed      bool      `json:"is_relayed"`
	Connected      bool      `json:"connected"`
	Allowed        bool      `json:"allowed"`
	OpenedAt       time.Time `json:"opened_at"`
	LastActivity   time.Time `json:"last_activity,omitempty"`
	ActiveConns    int32     `json:"active_conns"`
	BytesUp        int64     `json:"bytes_up"`
	BytesDown      int64     `json:"bytes_down"`
	LastProgressAt time.Time `json:"last_progress_at,omitempty"`
}

func (e *tunnelEntry) status() tunnelStatus {
	s := tunnelStatus{
		ID:          e.id,
		LocalAID:    e.localAID.String(),
		RemoteAID:   e.remoteAID.String(),
		Listen:      e.listen,
		HTTPSURL:    e.httpsURL,
		IsRelayed:   e.isRelayed,
		Connected:   true,
		Allowed:     e.listen != "",
		OpenedAt:    e.openedAt,
		ActiveConns: e.activeConns.Load(),
		BytesUp:     e.bytesUp.Load(),
		BytesDown:   e.bytesDown.Load(),
	}
	if ns := e.lastActivity.Load(); ns != 0 {
		s.LastActivity = time.Unix(0, ns)
	}
	if ns := e.lastProgress.Load(); ns != 0 {
		s.LastProgressAt = time.Unix(0, ns)
	}
	return s
}

// connDone decrements activeConns and, when the last connection closes,
// resets lastActivity so idle timeout counts from disconnect time.
func (e *tunnelEntry) connDone() {
	if e.activeConns.Add(-1) == 0 {
		e.lastActivity.Store(time.Now().UnixNano())
	}
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

// findListen reports a tunnel already bound to port.
// exact is set when that tunnel belongs to local→remote.
// occupied is set when some other tunnel holds the port.
func (r *tunnelRegistry) findListen(local, remote a2al.Address, port int) (exact *tunnelEntry, occupied bool) {
	if port <= 0 {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		if listenPort(e.listen) != port {
			continue
		}
		if e.localAID == local && e.remoteAID == remote {
			return e, false
		}
		occupied = true
	}
	return nil, occupied
}

func listenPort(listen string) int {
	_, ps, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}

func listenTunnel(port int) (net.Listener, error) {
	addr := "127.0.0.1:0"
	if port > 0 {
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	return net.Listen("tcp", addr)
}

func isAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	// Windows Listen returns WSAEADDRINUSE (10048). Current Go's
	// syscall.EADDRINUSE is a different constant, so errors.Is misses it.
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == 10048
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
	AccessToken    string `json:"access_token,omitempty"`
	IdleTimeoutSec int    `json:"idle_timeout_sec,omitempty"` // 0 = default (6 min), -1 = no timeout
	DisableRelay   *bool  `json:"disable_relay,omitempty"`    // nil = use node default
	LocalPort      int    `json:"local_port,omitempty"`       // 0 = ephemeral 127.0.0.1 port
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
func (d *Daemon) execTunnelOpen(ctx context.Context, remoteAidStr string, req tunnelOpenReq) (*tunnelEntry, bool, error) {
	remote, err := a2al.ParseAddress(remoteAidStr)
	if err != nil {
		return nil, false, errBadAID
	}
	local, err := d.pickLocalAgent(req.LocalAID)
	if err != nil {
		return nil, false, err
	}
	d.noteActingAgent(local)

	if req.LocalPort < 0 || req.LocalPort > 65535 {
		return nil, false, errBadLocalPort
	}
	// A requested port already held by this same pair is that caller's tunnel.
	// Checked before resolve/dial so a repeat open does not acquire or retain again.
	if req.LocalPort > 0 {
		if e, occupied := d.tunnels.findListen(local, remote, req.LocalPort); e != nil {
			keep, err := d.reuseTunnel(ctx, e, local, remote)
			if err != nil {
				return nil, false, err
			}
			if keep != nil {
				return keep, true, nil
			}
		} else if occupied {
			return nil, false, errPortInUse
		}
	}

	// Resolve with 20 s cap, same as execFetch / execConnect.
	rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
	er, contacted, err := d.resolveTracked(rctx, remote)
	rcancel()
	if err != nil {
		if d.beacon != nil && d.beaconShouldFallbackForResolve(err, contacted) {
			er, err = d.resolveFromBeacon(ctx, remote)
		}
		if err != nil {
			return nil, false, errResolve
		}
	}

	nr := resolveNoRelay(req.DisableRelay, d.cfg.DisableRelay)
	qc, isRelayed, err := d.connPool.acquire(ctx, local, remote, er, nr, true)
	if err != nil {
		if errors.Is(err, host.ErrRelayRequired) {
			return nil, false, err
		}
		return nil, false, errConnectQUIC
	}
	orig := qc
	qc, newRelayed, allowed, err := d.probeServiceAdmission(ctx, local, remote, er, nr, qc, req.AccessToken)
	if err != nil {
		return nil, false, errConnectQUIC
	}
	if qc != orig {
		isRelayed = newRelayed
	}
	if !allowed {
		return &tunnelEntry{
			id:        randomID(),
			localAID:  local,
			remoteAID: remote,
			isRelayed: isRelayed,
			noRelay:   nr,
			openedAt:  time.Now(),
		}, false, nil
	}
	d.connPool.retain(local, remote, nr)

	ln, err := listenTunnel(req.LocalPort)
	if err != nil {
		e, lerr := d.dropTunnelListen(local, remote, nr, req.LocalPort, err)
		if lerr != nil {
			return nil, false, lerr
		}
		return e, true, nil
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
		token:     req.AccessToken,
		openedAt:  time.Now(),
		qc:        qc,
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

		go d.watchTunnelConn(entry, ln, cancel, tctx)

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
				defer entry.connDone()
				cur := entry.conn()
				qs, err := d.openTunnelStream(tctx, cur, entry.token)
				if err != nil {
					if isAccessDeniedErr(err) || tctx.Err() != nil {
						d.log.Warn("tunnel: open stream failed", "id", entry.id, "err", err)
						_ = tcpConn.Close()
						return
					}
					next, rerr := d.repairTunnelConn(tctx, entry, local, remote, nr, er, cur)
					if rerr != nil {
						d.log.Warn("tunnel: repair failed", "id", entry.id, "err", rerr)
						cancel()
						_ = ln.Close()
						_ = tcpConn.Close()
						return
					}
					qs, err = d.openTunnelStream(tctx, next, entry.token)
					if err != nil {
						d.log.Warn("tunnel: open stream failed", "id", entry.id, "err", err)
						if !isAccessDeniedErr(err) && tctx.Err() == nil {
							cancel()
							_ = ln.Close()
						}
						_ = tcpConn.Close()
						return
					}
				}
				// Sniff and optionally upgrade to TLS so the browser
				// can use https://127.0.0.1:PORT with the persisted
				// self-signed certificate.
				conn := sniffAndUpgrade(tcpConn, d.tunnelTLS)
				onProgress := func() { entry.lastProgress.Store(time.Now().UnixNano()) }
				bridgeTCPQUICStream(qs, conn, &entry.bytesUp, &entry.bytesDown, onProgress)
			}()
		}
	}()

	return entry, true, nil
}

// reuseTunnel returns e when the existing listen is still usable.
// A dead or unrepairable connection is closed and the caller opens a new tunnel.
func (d *Daemon) reuseTunnel(ctx context.Context, e *tunnelEntry, local, remote a2al.Address) (*tunnelEntry, error) {
	if !e.connLive() {
		d.closeTunnel(e.id)
		return nil, nil
	}
	if err := d.probeTunnelStream(ctx, e.conn(), e.token); err == nil || isAccessDeniedErr(err) {
		return e, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	next, rerr := d.repairTunnelConn(ctx, e, local, remote, e.noRelay, nil, e.conn())
	if rerr == nil {
		if err := d.probeTunnelStream(ctx, next, e.token); err == nil || isAccessDeniedErr(err) {
			return e, nil
		}
	}
	d.closeTunnel(e.id)
	return nil, nil
}

// openTunnelStream opens one admitted stream, bounded by connPoolOpenProbeTimeout.
func (d *Daemon) openTunnelStream(ctx context.Context, conn quic.Connection, token string) (quic.Stream, error) {
	return openLimited(ctx, conn, func(ctx context.Context, c quic.Connection) (quic.Stream, error) {
		return d.openAdmittedStream(ctx, c, token)
	})
}

// probeTunnelStream confirms the cached QUIC can still open a service stream.
// A nil conn skips the probe (tests).
func (d *Daemon) probeTunnelStream(ctx context.Context, conn quic.Connection, token string) error {
	if conn == nil {
		return nil
	}
	str, err := d.openTunnelStream(ctx, conn, token)
	if str != nil {
		_ = str.Close()
	}
	return err
}

// watchTunnelConn closes the listener when the current QUIC dies or the
// tunnel is cancelled. ln.Close unblocks Accept. A repair that swaps the
// connection first is ignored: Done on the old connection must not tear
// down a tunnel that already holds a new one.
func (d *Daemon) watchTunnelConn(entry *tunnelEntry, ln net.Listener, cancel context.CancelFunc, tctx context.Context) {
	for {
		cur := entry.conn()
		if cur == nil {
			return
		}
		select {
		case <-cur.Context().Done():
			if entry.conn() != cur {
				continue
			}
			d.log.Debug("tunnel: quic died, closing listener", "id", entry.id)
			cancel()
			_ = ln.Close()
			return
		case <-tctx.Done():
			_ = ln.Close()
			return
		}
	}
}

// repairTunnelConn replaces a tunnel's pooled QUIC after stream open failed.
// The listen address is unchanged. Concurrent repairs share one dial.
func (d *Daemon) repairTunnelConn(ctx context.Context, entry *tunnelEntry, local, remote a2al.Address, noRelay bool, er *protocol.EndpointRecord, dead quic.Connection) (quic.Connection, error) {
	entry.repairMu.Lock()
	defer entry.repairMu.Unlock()
	if cur := entry.conn(); cur != nil && cur != dead && cur.Context().Err() == nil {
		return cur, nil
	}
	old := entry.conn()
	d.connPool.forget(local, remote, noRelay)
	qc2, relayed, err := d.connPool.acquireRepair(ctx, local, remote, er, noRelay, true)
	if err != nil {
		if old != nil {
			_ = old.CloseWithError(0, "reconnect requested")
		}
		return nil, err
	}
	d.connPool.retain(local, remote, noRelay)
	entry.setConn(qc2, relayed)
	if old != nil && old != qc2 {
		_ = old.CloseWithError(0, "reconnect requested")
	}
	return qc2, nil
}

// dropTunnelListen releases the retain taken for a listener that did not start.
// A concurrent open of the same local→remote port wins: return that tunnel.
func (d *Daemon) dropTunnelListen(local, remote a2al.Address, noRelay bool, port int, listenErr error) (*tunnelEntry, error) {
	d.connPool.release(local, remote, noRelay)
	if port > 0 {
		if e, _ := d.tunnels.findListen(local, remote, port); e != nil {
			return e, nil
		}
		if isAddrInUse(listenErr) {
			return nil, errPortInUse
		}
	}
	return nil, errListen
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
