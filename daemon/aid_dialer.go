// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"io"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/daemon/aidproxy"
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
	er, err := dd.d.h.Resolve(rctx, remote)
	rcancel()
	if err != nil {
		if dd.d.beacon != nil {
			er, err = dd.d.resolveFromBeacon(ctx, remote)
		}
		if err != nil {
			return nil, errResolve
		}
	}

	// Acquire a pooled QUIC connection and open a new stream.
	// Uses the node identity as the local AID (consistent with execFetch).
	conn, err := dd.d.connPool.acquire(ctx, dd.d.nodeAddr, remote, er)
	if err != nil {
		return nil, errConnectQUIC
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, errConnectQUIC
	}
	return stream, nil
}

// newAIDProxy constructs the aidproxy.Handler wired to this daemon.
// Called once from routes() during startup.
func (d *Daemon) newAIDProxy() *aidproxy.Handler {
	return aidproxy.New(
		aidproxy.NewChain(aidproxy.RawAIDResolver{}),
		&daemonDialer{d},
		d.log,
	)
}
