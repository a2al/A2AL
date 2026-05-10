// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2al/a2al/host"
	"github.com/quic-go/quic-go"
)

// parseServiceTCP splits a service_tcp value into (scheme, addr).
// Recognised prefixes: "https://", "http://".
// Anything else is returned as ("tcp", raw) for plain TCP forwarding.
func parseServiceTCP(raw string) (scheme, addr string) {
	if strings.HasPrefix(raw, "https://") {
		return "https", strings.TrimPrefix(raw, "https://")
	}
	if strings.HasPrefix(raw, "http://") {
		return "http", strings.TrimPrefix(raw, "http://")
	}
	return "tcp", raw
}

// dialServiceTCP opens a connection to the service described by serviceTCP.
// For "https://…" it wraps the connection in TLS with InsecureSkipVerify —
// the daemon and the backend share the same trust domain (local/LAN).
func dialServiceTCP(ctx context.Context, serviceTCP string, timeout time.Duration) (net.Conn, error) {
	scheme, addr := parseServiceTCP(serviceTCP)
	d := &net.Dialer{Timeout: timeout}
	if scheme == "https" {
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return tc, nil
	}
	return d.DialContext(ctx, "tcp", addr)
}

// sessionInfo is the per-connection metadata stored while a gateway TCP bridge
// is active. It is exposed via GET /sessions/{port}.
type sessionInfo struct {
	CallerAID    string    `json:"caller_aid"`
	CallerPubkey string    `json:"caller_pubkey"` // base64url-encoded Ed25519 public key
	LocalAID     string    `json:"local_aid"`
	ConnectedAt  time.Time `json:"connected_at"`
}

const (
	maxGatewayConns    = 1024
	maxStreamsPerConn   = 100
	tcpBridgeDeadline  = 30 * time.Second
)

func (d *Daemon) gatewayAcceptLoop(ctx context.Context) {
	for {
		ac, err := d.h.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.log.Debug("accept", "reason", err)
			continue
		}
		if !d.tryAcquireGatewayConn() {
			d.log.Warn("gateway: max connections reached", "limit", maxGatewayConns)
			_ = ac.CloseWithError(1, "too many connections")
			continue
		}
		go func() {
			defer d.releaseGatewayConn()
			d.serveGatewayConn(ctx, ac)
		}()
	}
}

func (d *Daemon) tryAcquireGatewayConn() bool {
	for {
		cur := d.gatewayConns.Load()
		if cur >= maxGatewayConns {
			return false
		}
		if d.gatewayConns.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (d *Daemon) releaseGatewayConn() {
	d.gatewayConns.Add(-1)
}

func (d *Daemon) serveGatewayConn(ctx context.Context, ac *host.AgentConn) {
	d.log.Debug("gateway: quic accepted", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String())
	d.regMu.RLock()
	reg := d.reg.Get(ac.Local)
	d.regMu.RUnlock()
	if reg == nil {
		d.log.Warn("gateway: unknown local agent", "aid", ac.Local.String())
		_ = ac.CloseWithError(1, "unknown agent")
		return
	}
	defer ac.CloseWithError(0, "gateway closed")
	var streamCount atomic.Int64
	for {
		str, err := ac.AcceptStream(ctx)
		if err != nil {
			d.log.Debug("gateway: accept stream done", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String(), "reason", err)
			return
		}
		if streamCount.Load() >= maxStreamsPerConn {
			_ = str.Close()
			continue
		}
		streamCount.Add(1)
		go func() {
			defer streamCount.Add(-1)
			d.bridgeInboundStream(ac, str, reg.ServiceTCP)
		}()
	}
}

func (d *Daemon) bridgeInboundStream(ac *host.AgentConn, str quic.Stream, serviceTCP string) {
	if serviceTCP == "" {
		d.log.Warn("gateway: empty service_tcp", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String())
		_ = str.Close()
		return
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	tcp, err := dialServiceTCP(dialCtx, serviceTCP, 5*time.Second)
	if err != nil {
		d.log.Warn("gateway: tcp dial", "local_aid", ac.Local.String(), "remote_aid", ac.Remote.String(), "target", serviceTCP, "err", err)
		_ = str.Close()
		return
	}

	// Register session so backends can query caller identity via GET /sessions/{port}.
	// The source port of the daemon's outbound TCP connection is the unique key —
	// the backend sees it as conn.RemoteAddr().Port after Accept().
	srcPort := tcp.LocalAddr().(*net.TCPAddr).Port
	si := &sessionInfo{
		CallerAID:   ac.Remote.String(),
		LocalAID:    ac.Local.String(),
		ConnectedAt: time.Now(),
	}
	if certs := ac.ConnectionState().TLS.PeerCertificates; len(certs) > 0 {
		if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
			si.CallerPubkey = base64.RawURLEncoding.EncodeToString(pub)
		}
	}
	d.sessions.Store(srcPort, si)
	defer d.sessions.Delete(srcPort)

	bridgeTCPQUICStream(str, tcp)
}

func bridgeTCPQUICStream(str quic.Stream, tcp net.Conn) {
	if tc, ok := tcp.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(tcpBridgeDeadline)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(tcp, str)
		if tw, ok := tcp.(*net.TCPConn); ok {
			_ = tw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(str, tcp)
		// Signal EOF on the QUIC send side with a clean FIN, not RESET_STREAM.
		// CancelWrite would discard unacknowledged data in flight and send
		// RESET_STREAM, causing the remote reader to get a StreamError instead
		// of io.EOF — breaking HTTP responses that are still in transit.
		_ = str.Close()
	}()
	wg.Wait()
	_ = str.Close()
	_ = tcp.Close()
}
