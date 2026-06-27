// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"net"
	"time"

	ice "github.com/pion/ice/v3"
)

// icePacketConn adapts ice.Conn (stream-oriented, single remote peer) to
// net.PacketConn so it can back a quic.Transport.
//
// Because an ICE connection has exactly one remote endpoint, WriteTo ignores
// the supplied addr and always writes to the ICE-selected path. This matches
// how quic-go's sendConn uses the PacketConn: it passes the addr returned by
// ReadFrom, which is always the same remote.
//
// # Pitfall: LocalAddr() must never be forwarded directly to ice.Conn
//
// pion/ice.Conn.LocalAddr() (and RemoteAddr()) return nil once the ICE agent
// clears its selected pair on disconnect. This violates the net.PacketConn
// contract, which requires LocalAddr() to remain valid for the object's
// lifetime.
//
// quic-go's connMultiplexer calls LocalAddr() in the defer of
// Transport.listen() — i.e. after the connection is already dead — to index
// the connection for removal (multiplexer.go: RemoveConn → index). Returning
// nil there causes a nil-pointer dereference (ACCESS_VIOLATION on Windows).
//
// Fix: snapshot LocalAddr at construction time, while ICE is Connected.
// quic-go itself applies the same pattern internally (send_conn.go:
// newSendConn captures LocalAddr once at dial time), so a static snapshot is
// both correct and consistent with quic-go's expectations.
//
// RemoteAddr() in ReadFrom is safe: when ICE disconnects, Read() returns an
// error first, so the nil RemoteAddr is never reached or used.
type icePacketConn struct {
	c         *ice.Conn
	localAddr net.Addr
}

// newIcePacketConn constructs an icePacketConn. Must be called immediately
// after completeICESession succeeds, while the ICE agent is still Connected
// and LocalAddr() is guaranteed non-nil.
func newIcePacketConn(c *ice.Conn) *icePacketConn {
	return &icePacketConn{c: c, localAddr: c.LocalAddr()}
}

func (p *icePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.c.Read(b)
	if err != nil {
		return 0, nil, err
	}
	return n, p.c.RemoteAddr(), nil
}

func (p *icePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.c.Write(b)
}

func (p *icePacketConn) Close() error                       { return p.c.Close() }
func (p *icePacketConn) LocalAddr() net.Addr                { return p.localAddr }
func (p *icePacketConn) SetDeadline(t time.Time) error      { return p.c.SetDeadline(t) }
func (p *icePacketConn) SetReadDeadline(t time.Time) error  { return p.c.SetReadDeadline(t) }
func (p *icePacketConn) SetWriteDeadline(t time.Time) error { return p.c.SetWriteDeadline(t) }
