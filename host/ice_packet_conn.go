// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"errors"
	"net"
	"time"

	ice "github.com/pion/ice/v3"
	"github.com/quic-go/quic-go"
)

// closeICETransport tears down a quic.Transport on ice.Conn.
//
// Agent close must go through sess.closeAgent (per-session Once). pion's
// SetReadDeadline is a stub, so Transport.Close cannot unblock listen until
// the agent is closed (buf.Close wakes ice.Conn.Read). Reverse order deadlocks.
// See doc-local/ICE与QUIC关闭原则.md.
func closeICETransport(tr *quic.Transport, sess *iceSession) {
	if sess != nil {
		sess.closeAgent()
	}
	if tr != nil {
		_ = tr.Close()
	}
}

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
// If LocalAddr is already nil (agent closed or selected pair gone),
// newIcePacketConn returns an error: ICE data-path setup failed. That is
// expected when punch already won and closed the agent.
//
// RemoteAddr() in ReadFrom is safe: when ICE disconnects, Read() returns an
// error first, so the nil RemoteAddr is never reached or used.
//
// Close does not close the ICE agent. Agent lifetime is owned by
// iceSession.closeAgent. quic-go Transport.Close does not call PacketConn.Close
// when it did not create the conn (createdConn == false).
type icePacketConn struct {
	c         *ice.Conn
	localAddr net.Addr
}

// newIcePacketConn constructs an icePacketConn. LocalAddr must still be
// non-nil; a nil addr means the agent is already down.
func newIcePacketConn(c *ice.Conn) (*icePacketConn, error) {
	if c == nil {
		return nil, errors.New("a2al/host: ice conn is nil")
	}
	la := c.LocalAddr()
	if la == nil {
		return nil, errors.New("a2al/host: ice LocalAddr is nil")
	}
	return &icePacketConn{c: c, localAddr: la}, nil
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

func (p *icePacketConn) Close() error                       { return nil }
func (p *icePacketConn) LocalAddr() net.Addr                { return p.localAddr }
func (p *icePacketConn) SetDeadline(t time.Time) error      { return p.c.SetDeadline(t) }
func (p *icePacketConn) SetReadDeadline(t time.Time) error  { return p.c.SetReadDeadline(t) }
func (p *icePacketConn) SetWriteDeadline(t time.Time) error { return p.c.SetWriteDeadline(t) }
