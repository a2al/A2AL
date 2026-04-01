// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2al/a2al/host"
	"github.com/quic-go/quic-go"
)

const (
	maxGatewayConns    = 1024
	maxStreamsPerConn   = 100
	tcpBridgeDeadline  = 30 * time.Second
)

func (d *Daemon) gatewayAcceptLoop(ctx context.Context) {
	var active atomic.Int64
	for {
		ac, err := d.h.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.log.Debug("accept", "err", err)
			continue
		}
		if active.Load() >= maxGatewayConns {
			d.log.Warn("gateway: max connections reached", "limit", maxGatewayConns)
			_ = ac.CloseWithError(1, "too many connections")
			continue
		}
		active.Add(1)
		go func() {
			defer active.Add(-1)
			d.serveGatewayConn(ctx, ac)
		}()
	}
}

func (d *Daemon) serveGatewayConn(ctx context.Context, ac *host.AgentConn) {
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
	tcp, err := net.DialTimeout("tcp", serviceTCP, 5*time.Second)
	if err != nil {
		d.log.Warn("gateway: tcp dial", "target", serviceTCP, "err", err)
		_ = str.Close()
		return
	}
	var hdr [21]byte
	copy(hdr[:], ac.Remote[:])
	if _, err := tcp.Write(hdr[:]); err != nil {
		_ = str.Close()
		_ = tcp.Close()
		return
	}
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
		str.CancelWrite(0)
	}()
	wg.Wait()
	_ = str.Close()
	_ = tcp.Close()
}
