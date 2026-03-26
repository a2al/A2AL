// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/a2al/a2al/host"
	"github.com/quic-go/quic-go"
)

func (d *Daemon) gatewayAcceptLoop(ctx context.Context) {
	for {
		ac, err := d.h.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.log.Debug("accept", "err", err)
			continue
		}
		go d.serveGatewayConn(ctx, ac)
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
	for {
		str, err := ac.AcceptStream(ctx)
		if err != nil {
			return
		}
		go d.bridgeInboundStream(ac, str, reg.ServiceTCP)
	}
}

func (d *Daemon) bridgeInboundStream(ac *host.AgentConn, str quic.Stream, serviceTCP string) {
	tcp, err := net.Dial("tcp", serviceTCP)
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
