// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/nodeks"
	"github.com/a2al/a2al/internal/registry"
	"github.com/a2al/a2al/protocol"
)

func TestGateway_aclDeniesServiceTCP_keepsQUIC(t *testing.T) {
	a := newTestDaemon(t)
	aid := newTestAgent(t, a)
	e := a.reg.Get(aid)
	if err := a.h.RegisterDelegatedAgent(aid, e.OpPriv, e.DelegationCBOR); err != nil {
		t.Fatal(err)
	}

	var dials atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			_ = c.Close()
		}
	}()

	e.ServiceTCP = ln.Addr().String()
	e.ACL = &registry.ACLPolicy{Default: registry.ACLDefaultDeny}
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

	if !hb.PeerServiceStream(conn) {
		t.Fatal("dialer should see 0x06 ServiceStream")
	}
	_, err = host.AdmitServiceStream(ctx, conn, "")
	if !errors.Is(err, protocol.ErrAccessDenied) {
		t.Fatalf("AdmitServiceStream: %v", err)
	}
	select {
	case <-conn.Context().Done():
		t.Fatal("QUIC should stay up after stream deny")
	case <-time.After(200 * time.Millisecond):
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("service_tcp dialed %d times, want 0", n)
	}
}
