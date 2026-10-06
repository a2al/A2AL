// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

// errOpenStream marks a failure to open a stream on an existing pooled conn
// (as opposed to a write/read failure after the stream exists).
type errOpenStream struct{ err error }

func (e *errOpenStream) Error() string { return e.err.Error() }
func (e *errOpenStream) Unwrap() error { return e.err }

func (d *Daemon) openAdmittedStream(ctx context.Context, conn quic.Connection, token string) (quic.Stream, error) {
	if d.h.PeerServiceStream(conn) {
		return host.AdmitServiceStream(ctx, conn, token)
	}
	return conn.OpenStreamSync(ctx)
}

// openPooled opens a stream on conn. If that fails because the cached
// connection cannot carry data, the slot is dropped and one repair dial
// runs. This caller waits at most connPoolRepairWait; the dial itself may
// finish later and fill the pool. Access-denied, and a caller who is already
// done while the connection is still up, do not drop the slot.
func (d *Daemon) openPooled(
	ctx context.Context,
	local, remote a2al.Address,
	er *protocol.EndpointRecord,
	noRelay, user bool,
	conn quic.Connection,
	open func(context.Context, quic.Connection) (quic.Stream, error),
) (quic.Connection, quic.Stream, bool, error) {
	if err := ctx.Err(); err != nil {
		return conn, nil, false, err
	}
	str, err := openLimited(ctx, conn, open)
	if err == nil {
		return conn, str, false, nil
	}
	if isServiceDoorErr(err) || (ctx.Err() != nil && conn.Context().Err() == nil) {
		return conn, nil, false, err
	}
	if d.connPool == nil || !d.connPool.evictUnheld(conn) {
		return conn, nil, false, err
	}
	if d.log != nil {
		d.log.Debug("connpool: open failed, redialing",
			"local", local.String(), "remote", remote.String(), "err", err)
	}
	conn2, relayed, err2 := d.connPool.acquireRepair(ctx, local, remote, er, noRelay, user)
	if err2 != nil {
		return nil, nil, relayed, err2
	}
	str2, err3 := openLimited(ctx, conn2, open)
	if err3 != nil && !isServiceDoorErr(err3) && (ctx.Err() == nil || conn2.Context().Err() != nil) {
		d.connPool.evictUnheld(conn2)
	}
	return conn2, str2, relayed, err3
}

// openLimited bounds OpenStream on a pooled connection. The caller's deadline
// still applies when it is sooner.
func openLimited(ctx context.Context, conn quic.Connection, open func(context.Context, quic.Connection) (quic.Stream, error)) (quic.Stream, error) {
	probeCtx, cancel := context.WithTimeout(ctx, connPoolOpenProbeTimeout)
	defer cancel()
	return open(probeCtx, conn)
}

// probeServiceAdmission returns whether the peer allows a service stream now.
// Peers that did not advertise a2s1 are allowed here without opening a stream.
// A stale a2s1 connection is replaced once via openPooled.
func (d *Daemon) probeServiceAdmission(
	ctx context.Context,
	local, remote a2al.Address,
	er *protocol.EndpointRecord,
	noRelay bool,
	conn quic.Connection,
	token string,
) (quic.Connection, bool, bool, error) {
	if d.h == nil || !d.h.PeerServiceStream(conn) {
		return conn, false, true, nil
	}
	open := func(ctx context.Context, c quic.Connection) (quic.Stream, error) {
		if d.h != nil && d.h.PeerServiceStream(c) {
			return host.AdmitServiceStream(ctx, c, token)
		}
		return nil, nil
	}
	conn2, str, relayed, err := d.openPooled(ctx, local, remote, er, noRelay, true, conn, open)
	if str != nil {
		_ = str.Close()
	}
	if err != nil {
		if isAccessDeniedErr(err) {
			return conn2, relayed, false, nil
		}
		return conn2, relayed, false, err
	}
	return conn2, relayed, true, nil
}
