// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/nodeks"
	"github.com/a2al/a2al/protocol"
)

func TestGateway_a2s1_noInbound(t *testing.T) {
	a := newTestDaemon(t)
	aid := newTestAgent(t, a)
	e := a.reg.Get(aid)
	if err := a.h.RegisterDelegatedAgent(aid, e.OpPriv, e.DelegationCBOR); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	ksB, err := nodeks.LoadOrGenerate(filepath.Join(dir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	hb, err := host.New(host.Config{
		KeyStore:         ksB,
		ListenAddr:       "127.0.0.1:0",
		QUICListenAddr:   "127.0.0.1:0",
		MinObservedPeers: 1,
		FallbackHost:     "127.0.0.1",
		DisableUPnP:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	go func() {
		ac, err := a.h.Accept(ctx)
		if err != nil {
			return
		}
		a.serveGatewayConn(ctx, ac)
	}()

	conn, err := hb.Connect(ctx, aid, a.h.QUICLocalAddr())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	if !hb.PeerServiceStream(conn) {
		t.Fatal("dialer should see 0x06 ServiceStream")
	}
	_, err = host.AdmitServiceStream(ctx, conn, "")
	if !errors.Is(err, protocol.ErrNoInbound) {
		t.Fatalf("AdmitServiceStream: %v, want no inbound", err)
	}
	select {
	case <-conn.Context().Done():
		t.Fatal("QUIC should stay up after no inbound")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestGateway_a2s1_inboundUnreachable(t *testing.T) {
	a := newTestDaemon(t)
	aid := newTestAgent(t, a)
	e := a.reg.Get(aid)
	if err := a.h.RegisterDelegatedAgent(aid, e.OpPriv, e.DelegationCBOR); err != nil {
		t.Fatal(err)
	}
	e.ServiceTCP = "127.0.0.1:1"
	if err := a.reg.Put(e); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	ksB, err := nodeks.LoadOrGenerate(filepath.Join(dir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	hb, err := host.New(host.Config{
		KeyStore:         ksB,
		ListenAddr:       "127.0.0.1:0",
		QUICListenAddr:   "127.0.0.1:0",
		MinObservedPeers: 1,
		FallbackHost:     "127.0.0.1",
		DisableUPnP:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	go func() {
		ac, err := a.h.Accept(ctx)
		if err != nil {
			return
		}
		a.serveGatewayConn(ctx, ac)
	}()

	conn, err := hb.Connect(ctx, aid, a.h.QUICLocalAddr())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	str, err := host.AdmitServiceStream(ctx, conn, "")
	if err != nil {
		t.Fatalf("AdmitServiceStream: %v", err)
	}
	_, err = str.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 8)
	_, err = str.Read(buf)
	if !errors.Is(streamAppErr(err), protocol.ErrInboundUnreachable) {
		t.Fatalf("read: %v, want inbound unreachable", err)
	}
	select {
	case <-conn.Context().Done():
		t.Fatal("QUIC should stay up after inbound unreachable")
	case <-time.After(200 * time.Millisecond):
	}
}
