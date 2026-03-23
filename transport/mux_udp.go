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

// UDPMux demultiplexes one UDP socket between DHT (CBOR) and QUIC (RFC 9000).
//
// Discrimination: all QUIC packets (long and short header) have the "Fixed Bit"
// (0x40) set per RFC 9000 §17. A2AL DHT messages are CBOR maps whose first byte
// falls in 0xa0-0xbf, where bit 6 is always clear. Checking `data[0]&0x40 != 0`
// is therefore a reliable, stateless discriminator — no peer tracking needed.
type UDPMux struct {
	conn *net.UDPConn

	dhtIn chan pkt
	qIn   chan pkt

	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error

	readDone chan struct{}
	wg       sync.WaitGroup

	// QUIC virtual conn deadlines (never forwarded to *UDPConn — shared fd).
	qMu      sync.Mutex
	qReadDL  time.Time
	qWriteDL time.Time
}

type pkt struct {
	data []byte
	addr net.Addr
}

// NewUDPMux wraps an existing UDP listener. Call StartReadLoop before use.
func NewUDPMux(conn *net.UDPConn) *UDPMux {
	return &UDPMux{
		conn:     conn,
		dhtIn:    make(chan pkt, muxChanDepth),
		qIn:      make(chan pkt, muxChanDepth),
		readDone: make(chan struct{}),
	}
}

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
		if isQUICPacket(data[0]) {
			m.qIn <- p
		} else {
			select {
			case m.dhtIn <- p:
			default:
			}
		}
	}
}

// isQUICPacket returns true if the first byte has the QUIC Fixed Bit (0x40) set.
// All QUIC long and 1-RTT short header packets set this bit (RFC 9000 §17).
// CBOR maps (our DHT wire format) start with 0xa0-0xbf where bit 6 is clear.
func isQUICPacket(firstByte byte) bool {
	return firstByte&0x40 != 0
}

// DHTTransport returns the DHT packet plane.
func (m *UDPMux) DHTTransport() *MuxDHTTransport {
	return &MuxDHTTransport{m: m}
}

// QUICPacketConn returns a net.PacketConn that only sees QUIC datagrams.
func (m *UDPMux) QUICPacketConn() net.PacketConn {
	return &muxQUICConn{m: m}
}

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

// WaitReadLoop blocks until the read loop exits (after Close).
func (m *UDPMux) WaitReadLoop() {
	<-m.readDone
}

// ---------------------------------------------------------------------------
// DHT Transport (implements transport.Transport)
// ---------------------------------------------------------------------------

type MuxDHTTransport struct{ m *UDPMux }

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

func (t *MuxDHTTransport) LocalAddr() net.Addr { return t.m.conn.LocalAddr() }

func (t *MuxDHTTransport) Close() error {
	return nil // lifecycle owned by UDPMux
}

// ---------------------------------------------------------------------------
// QUIC PacketConn
// ---------------------------------------------------------------------------

type muxQUICConn struct{ m *UDPMux }

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
			case pk := <-c.m.qIn:
				timer.Stop()
				n := copy(p, pk.data)
				return n, pk.addr, nil
			case <-timer.C:
				return 0, nil, os.ErrDeadlineExceeded
			}
		}

		select {
		case <-c.m.readDone:
			return 0, nil, net.ErrClosed
		case pk := <-c.m.qIn:
			n := copy(p, pk.data)
			return n, pk.addr, nil
		}
	}
}

func (c *muxQUICConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.m.conn.WriteTo(b, addr)
}

func (c *muxQUICConn) Close() error   { return nil }
func (c *muxQUICConn) LocalAddr() net.Addr { return c.m.conn.LocalAddr() }

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
