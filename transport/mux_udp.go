// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	muxChanDepth = 2048
	readBufSize  = 65536
)

// UDPMux demultiplexes one UDP socket between DHT (CBOR) and QUIC (RFC 9000 long header
// 0xc0–0xff, plus short headers from registered peers). Same-port sharing per spec Phase 2a.
type UDPMux struct {
	conn *net.UDPConn

	quicPeers sync.Map // string (UDPAddr.String()) -> struct{}

	dhtIn chan pkt
	qIn   chan pkt

	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error

	readDone chan struct{}
	wg       sync.WaitGroup

	// quic virtual conn deadlines (do not forward to *UDPConn — shared fd would break mux readLoop)
	qMu      sync.Mutex
	qReadDL  time.Time
	qWriteDL time.Time
}

type pkt struct {
	data []byte
	addr net.Addr
}

// NewUDPMux wraps an existing UDP listener. StartReadLoop must be called before use.
func NewUDPMux(conn *net.UDPConn) *UDPMux {
	return &UDPMux{
		conn:     conn,
		dhtIn:    make(chan pkt, muxChanDepth),
		qIn:      make(chan pkt, muxChanDepth),
		readDone: make(chan struct{}),
	}
}

// MarkQUICPeer registers a remote UDP address as carrying QUIC (short-header) packets.
func (m *UDPMux) MarkQUICPeer(addr net.Addr) {
	m.quicPeers.Store(addr.String(), struct{}{})
}

// UnmarkQUICPeer removes the registration (e.g. when a QUIC connection closes).
func (m *UDPMux) UnmarkQUICPeer(addr net.Addr) {
	m.quicPeers.Delete(addr.String())
}

// StartReadLoop begins demuxing UDP datagrams; it returns when the connection is closed.
func (m *UDPMux) StartReadLoop() {
	m.wg.Add(1)
	go m.readLoop()
}

func (m *UDPMux) readLoop() {
	defer m.wg.Done()
	defer close(m.readDone)
	buf := make([]byte, readBufSize)
	for {
		n, addr, err := m.conn.ReadFrom(buf)
		if err != nil {
			if m.closed.Load() {
				return
			}
			m.closeErr = err
			return
		}
		if n == 0 {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		p := pkt{data: data, addr: addr}
		if m.isQUICPacket(data, addr) {
			// Register peer for subsequent QUIC short headers before Accept/Dial returns.
			m.MarkQUICPeer(addr)
			// Never drop QUIC: handshake needs every datagram. Backpressure UDP reads if quic-go is slow.
			m.qIn <- p
		} else {
			select {
			case m.dhtIn <- p:
			default:
			}
		}
	}
}

func (m *UDPMux) isQUICPacket(data []byte, from net.Addr) bool {
	if len(data) == 0 {
		return false
	}
	// Long header: two high bits set (RFC 9000).
	if (data[0] & 0xc0) == 0xc0 {
		return true
	}
	_, ok := m.quicPeers.Load(from.String())
	return ok
}

// DHTTransport returns the DHT packet plane for this mux.
func (m *UDPMux) DHTTransport() *MuxDHTTransport {
	return &MuxDHTTransport{m: m}
}

// QUICPacketConn returns a net.PacketConn that only sees QUIC-labelled datagrams.
func (m *UDPMux) QUICPacketConn() net.PacketConn {
	return &muxQUICConn{m: m}
}

// Close closes the UDP socket and stops demuxing.
func (m *UDPMux) Close() error {
	var err error
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		err = m.conn.Close()
	})
	m.wg.Wait()
	if err != nil {
		return err
	}
	if m.closeErr != nil {
		return m.closeErr
	}
	return nil
}

// WaitReadLoop waits until the read loop exits (after Close).
func (m *UDPMux) WaitReadLoop() {
	<-m.readDone
}

// MuxDHTTransport implements Transport for DHT over UDPMux.
type MuxDHTTransport struct {
	m *UDPMux
}

func (t *MuxDHTTransport) Send(addr net.Addr, data []byte) error {
	if len(data) > MaxPacketSize {
		return ErrPacketTooLarge
	}
	_, err := t.m.conn.WriteTo(data, addr)
	return err
}

func (t *MuxDHTTransport) Receive() ([]byte, net.Addr, error) {
	select {
	case p, ok := <-t.m.dhtIn:
		if !ok {
			return nil, nil, ErrClosed
		}
		return p.data, p.addr, nil
	case <-t.m.readDone:
		return nil, nil, ErrClosed
	}
}

func (t *MuxDHTTransport) LocalAddr() net.Addr {
	return t.m.conn.LocalAddr()
}

func (t *MuxDHTTransport) Close() error {
	// UDP lifecycle is owned by UDPMux; Host closes the mux after stopping QUIC.
	return nil
}

type muxQUICConn struct {
	m *UDPMux
}

func (c *muxQUICConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		c.m.qMu.Lock()
		dl := c.m.qReadDL
		c.m.qMu.Unlock()

		if !dl.IsZero() {
			remain := time.Until(dl)
			if remain <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(remain)
			select {
			case <-c.m.readDone:
				timer.Stop()
				return 0, nil, net.ErrClosed
			case pkt := <-c.m.qIn:
				timer.Stop()
				n := copy(p, pkt.data)
				return n, pkt.addr, nil
			case <-timer.C:
				return 0, nil, os.ErrDeadlineExceeded
			}
		}

		select {
		case <-c.m.readDone:
			return 0, nil, net.ErrClosed
		case pkt := <-c.m.qIn:
			n := copy(p, pkt.data)
			return n, pkt.addr, nil
		}
	}
}

func (c *muxQUICConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.m.conn.WriteTo(b, addr)
}

func (c *muxQUICConn) Close() error {
	return nil // quic.Transport closes the logical conn; UDP owned by UDPMux
}

func (c *muxQUICConn) LocalAddr() net.Addr {
	return c.m.conn.LocalAddr()
}

func (c *muxQUICConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *muxQUICConn) SetReadDeadline(t time.Time) error {
	c.m.qMu.Lock()
	c.m.qReadDL = t
	c.m.qMu.Unlock()
	return nil
}

func (c *muxQUICConn) SetWriteDeadline(t time.Time) error {
	c.m.qMu.Lock()
	c.m.qWriteDL = t
	c.m.qMu.Unlock()
	return nil
}
