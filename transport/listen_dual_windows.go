// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package transport

import (
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// ListenDualUDP opens a UDP socket that handles both IPv4 and IPv6 traffic.
//
// On Windows, IPV6_V6ONLY defaults to 1 (RFC 3493 §5.3; confirmed by Microsoft
// documentation for Vista+). Go's net.ListenUDP("udp", "[::]:port") therefore
// binds only an IPv6 socket, leaving IPv4 traffic unreachable. To ensure both
// families are served on the same logical port, ListenDualUDP opens two separate
// file descriptors — udp4 on 0.0.0.0:port and udp6 on [::]:port — and wraps
// them in a dualPacketConn that multiplexes reads and routes writes by family.
//
// For explicit single-family binds (e.g. "1.2.3.4:port" or "[::1]:port"),
// a plain *net.UDPConn is returned, preserving existing behaviour.
//
// The dualPacketConn satisfies net.PacketConn and is transparent to UDPMux.
func ListenDualUDP(addr string) (net.PacketConn, error) {
	network, resolved := resolveListenAddr(addr)
	if network != "udp" {
		// Specific single-family address: one socket, no wrapping needed.
		a, err := net.ResolveUDPAddr(network, resolved)
		if err != nil {
			return nil, err
		}
		return net.ListenUDP(network, a)
	}

	// Wildcard dual-stack: extract port and open two sockets on the same port.
	// Port 0 → kernel-assigned: bind c4 first, then mirror its port for c6.
	_, portStr, err := net.SplitHostPort(resolved)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	c4, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	assignedPort := c4.LocalAddr().(*net.UDPAddr).Port
	c6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: assignedPort})
	if err != nil {
		c4.Close()
		return nil, err
	}
	return newDualPacketConn(c4, c6), nil
}

// dualPkt is a received UDP datagram together with its normalised source address.
type dualPkt struct {
	data []byte
	from *net.UDPAddr
}

// dualPacketConn multiplexes two UDP sockets (udp4 + udp6) behind a single
// net.PacketConn interface. It is used on Windows where a single dual-stack
// socket cannot be relied upon (IPV6_V6ONLY=1 by default).
//
// Read path:  two background goroutines read from c4 and c6 respectively and
//
//	fan packets into a shared buffered channel; ReadFrom selects from that
//	channel.
//
// Write path: WriteTo inspects the destination IP and routes to c4 (if v4 or
//
//	v4-mapped) or c6 (if v6).
type dualPacketConn struct {
	c4   *net.UDPConn
	c6   *net.UDPConn
	pkt  chan dualPkt
	done chan struct{}
	once sync.Once

	dlMu sync.Mutex
	rdl  time.Time // read deadline (applied in ReadFrom timer)
}

const dualChanDepth = 2048

func newDualPacketConn(c4, c6 *net.UDPConn) *dualPacketConn {
	d := &dualPacketConn{
		c4:   c4,
		c6:   c6,
		pkt:  make(chan dualPkt, dualChanDepth),
		done: make(chan struct{}),
	}
	go d.readLoop(c4)
	go d.readLoop(c6)
	return d
}

func (d *dualPacketConn) readLoop(c *net.UDPConn) {
	buf := make([]byte, readBufSize)
	for {
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			return // socket closed or network error; goroutine exits
		}
		// Normalise v4-mapped source addresses from the IPv6 socket.
		if addr != nil {
			if v4 := addr.IP.To4(); v4 != nil && len(addr.IP) == net.IPv6len {
				addr = &net.UDPAddr{IP: v4, Port: addr.Port}
			}
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case d.pkt <- dualPkt{data, addr}:
		case <-d.done:
			return
		}
	}
}

// ReadFrom blocks until a packet is available on either socket, the read
// deadline expires, or the connection is closed.
func (d *dualPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	d.dlMu.Lock()
	dl := d.rdl
	d.dlMu.Unlock()

	if !dl.IsZero() {
		remain := time.Until(dl)
		if remain <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(remain)
		defer t.Stop()
		select {
		case pk := <-d.pkt:
			return copy(p, pk.data), pk.from, nil
		case <-t.C:
			return 0, nil, os.ErrDeadlineExceeded
		case <-d.done:
			return 0, nil, net.ErrClosed
		}
	}

	select {
	case pk := <-d.pkt:
		return copy(p, pk.data), pk.from, nil
	case <-d.done:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo routes the packet to the correct socket based on the destination
// address family. v4-mapped destinations are normalised to pure IPv4.
func (d *dualPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("dualPacketConn: WriteTo requires *net.UDPAddr")
	}
	if v4 := ua.IP.To4(); v4 != nil {
		// IPv4 or v4-mapped: route to the udp4 socket with a 4-byte IP.
		return d.c4.WriteTo(b, &net.UDPAddr{IP: v4, Port: ua.Port})
	}
	return d.c6.WriteTo(b, ua)
}

// Close shuts down both sockets and signals the reader goroutines to exit.
// Idempotent.
func (d *dualPacketConn) Close() error {
	d.once.Do(func() {
		close(d.done)
		d.c4.Close()
		d.c6.Close()
	})
	return nil
}

// LocalAddr returns a *net.UDPAddr of the form [::]:port, representing the
// dual-stack listener. The port is shared between c4 and c6.
func (d *dualPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv6zero, Port: d.c4.LocalAddr().(*net.UDPAddr).Port}
}

func (d *dualPacketConn) SetDeadline(t time.Time) error {
	_ = d.SetReadDeadline(t)
	return d.SetWriteDeadline(t)
}

func (d *dualPacketConn) SetReadDeadline(t time.Time) error {
	d.dlMu.Lock()
	d.rdl = t
	d.dlMu.Unlock()
	return nil
}

func (d *dualPacketConn) SetWriteDeadline(t time.Time) error {
	_ = d.c4.SetWriteDeadline(t)
	_ = d.c6.SetWriteDeadline(t)
	return nil
}

// SetReadBuffer sets the OS read buffer size on both sockets.
func (d *dualPacketConn) SetReadBuffer(n int) error {
	if err := d.c4.SetReadBuffer(n); err != nil {
		return err
	}
	return d.c6.SetReadBuffer(n)
}

// SetWriteBuffer sets the OS write buffer size on both sockets.
func (d *dualPacketConn) SetWriteBuffer(n int) error {
	if err := d.c4.SetWriteBuffer(n); err != nil {
		return err
	}
	return d.c6.SetWriteBuffer(n)
}
