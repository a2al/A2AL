// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/daemon/aidproxy"
	"github.com/a2al/a2al/group"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

// daemonDialer implements [aidproxy.Dialer] using the daemon's connPool and
// registry.
//
// For locally registered agents with a known service_tcp address, it connects
// via TCP directly (local short-circuit, no QUIC). For all other AIDs it
// resolves the endpoint via DHT, acquires a pooled QUIC connection from
// connPool, and opens a new stream — the same Mode A data-plane path used by
// execFetch and execTunnelOpen.
type daemonDialer struct {
	d *Daemon
}

// Dial opens a bidirectional [io.ReadWriteCloser] stream to remote.
//
// The returned stream carries raw HTTP/1.1 bytes. The caller writes the
// request and reads back the response; no additional framing is needed.
func (dd *daemonDialer) Dial(ctx context.Context, remote a2al.Address) (io.ReadWriteCloser, error) {
	// Local short-circuit: skip QUIC for locally hosted agents.
	// d.reg only contains agents explicitly registered with this daemon, so
	// there are no false positives.
	dd.d.regMu.RLock()
	localEntry := dd.d.reg.Get(remote)
	dd.d.regMu.RUnlock()
	if localEntry != nil && localEntry.ServiceTCP != "" {
		// Use DialContext so caller context cancellation (client disconnect,
		// dial timeout) is respected rather than running the full 5-second
		// hardcoded timeout independently.
		return dialServiceTCP(ctx, localEntry.ServiceTCP, 5*time.Second)
	}

	// Resolve remote endpoint (20 s budget; shares the caller's context).
	rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
	er, contacted, err := dd.d.resolveTracked(rctx, remote)
	rcancel()
	if err != nil {
		if dd.d.beacon != nil && dd.d.beaconShouldFallbackForResolve(err, contacted) {
			er, err = dd.d.resolveFromBeacon(ctx, remote)
		}
		if err != nil {
			return nil, errResolve
		}
	}

	// Acquire a pooled QUIC connection and open a new stream.
	// Uses the node identity as the local AID (consistent with execFetch).
	conn, _, err := dd.d.connPool.acquire(ctx, dd.d.nodeAddr, remote, er, false, true)
	if err != nil {
		return nil, errConnectQUIC
	}
	_, stream, _, err := dd.d.openPooled(ctx, dd.d.nodeAddr, remote, er, false, true, conn, func(ctx context.Context, c quic.Connection) (quic.Stream, error) {
		return dd.d.openAdmittedStream(ctx, c, "")
	})
	if err != nil {
		return nil, fetchStreamErr(err)
	}
	return stream, nil
}

// newAIDProxy constructs the aidproxy.Handler wired to this daemon.
// Called once from routes() during startup.
func (d *Daemon) newAIDProxy() *aidproxy.Handler {
	h := aidproxy.New(
		aidproxy.NewChain(aidproxy.RawAIDResolver{}),
		&daemonDialer{d},
		d.log,
	)
	h.LocalCAS = d.serveAIDProxyCAS
	return h
}

func (d *Daemon) serveAIDProxyCAS(w http.ResponseWriter, r *http.Request, aid a2al.Address, resourcePath string) bool {
	path := resourcePath
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	id, ok := group.ParseCASPath(path)
	if !ok {
		return false
	}
	if d.casLocalHolder(aid) {
		d.serveCASFile(w, aid, id, r.Method)
		return true
	}
	d.proxyRemoteCAS(w, r, aid, id)
	return true
}

func (d *Daemon) proxyRemoteCAS(w http.ResponseWriter, r *http.Request, remote a2al.Address, id [32]byte) {
	dialCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	stream, err := d.dialCAS(dialCtx, d.nodeAddr, remote, "")
	cancel()
	if err != nil {
		writeAIDHTTPErr(w, err, "connect failed", http.StatusBadGateway)
		return
	}
	defer stream.Close()

	outReq, err := http.NewRequest(r.Method, "http://cas"+group.CASPath(id), nil)
	if err != nil {
		http.Error(w, "bad request", http.StatusInternalServerError)
		return
	}
	outReq.Header.Set("Connection", "close")
	if err := outReq.Write(stream); err != nil {
		http.Error(w, "upstream write failed", http.StatusBadGateway)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReaderSize(stream, 32*1024), outReq)
	if err != nil {
		writeAIDHTTPErr(w, err, "upstream read failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (d *Daemon) dialCAS(ctx context.Context, local, remote a2al.Address, token string) (io.ReadWriteCloser, error) {
	rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
	er, contacted, err := d.resolveTracked(rctx, remote)
	rcancel()
	if err != nil {
		if d.beacon != nil && d.beaconShouldFallbackForResolve(err, contacted) {
			er, err = d.resolveFromBeacon(ctx, remote)
		}
		if err != nil {
			return nil, errResolve
		}
	}
	if local == (a2al.Address{}) {
		local = d.nodeAddr
	}
	conn, _, err := d.connPool.acquire(ctx, local, remote, er, false, true)
	if err != nil {
		return nil, errConnectQUIC
	}
	_, stream, _, err := d.openPooled(ctx, local, remote, er, false, true, conn, func(ctx context.Context, c quic.Connection) (quic.Stream, error) {
		return host.AdmitCASStream(ctx, c, token)
	})
	if err != nil {
		return nil, fetchStreamErr(err)
	}
	return stream, nil
}

func writeAIDHTTPErr(w http.ResponseWriter, err error, fallback string, fallbackStatus int) {
	switch {
	case isAccessDeniedErr(err):
		http.Error(w, "access denied", http.StatusForbidden)
	case errors.Is(err, protocol.ErrNoInbound):
		http.Error(w, "no inbound", http.StatusServiceUnavailable)
	case errors.Is(err, protocol.ErrInboundUnreachable):
		http.Error(w, "inbound unreachable", http.StatusBadGateway)
	default:
		http.Error(w, fallback, fallbackStatus)
	}
}
