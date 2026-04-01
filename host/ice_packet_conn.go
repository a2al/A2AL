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
type icePacketConn struct {
	c *ice.Conn
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
func (p *icePacketConn) LocalAddr() net.Addr                { return p.c.LocalAddr() }
func (p *icePacketConn) SetDeadline(t time.Time) error      { return p.c.SetDeadline(t) }
func (p *icePacketConn) SetReadDeadline(t time.Time) error  { return p.c.SetReadDeadline(t) }
func (p *icePacketConn) SetWriteDeadline(t time.Time) error { return p.c.SetWriteDeadline(t) }
