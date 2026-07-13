// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/a2al/a2al/host"
	"github.com/a2al/a2al/internal/nodeks"
	"github.com/a2al/a2al/protocol"
)

// TestGateway_dhtFallback reproduces the scenario behind the "gateway: empty
// service_tcp" warning storm: a DHT control-plane (Mode B) stream ends up on
// a connection that the accept path classified as an ordinary Mode A
// connection (e.g. a punch-pool connection that missed the punchExpect
// window, or here, more simply, a direct Connect to the node's own AID,
// which never has a service_tcp). It asserts tryHandleAsDHTFallback
// recovers a valid signed DHT message via InjectReceived instead of
// silently dropping it, while still rejecting non-DHT garbage the same way
// as before.
func TestGateway_dhtFallback(t *testing.T) {
	a := newTestDaemon(t)

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
		// Mirrors gatewayAcceptLoop's per-connection handling.
		a.serveGatewayConn(ctx, ac)
	}()

	// B dials A's own node identity directly. A node AID never has a
	// service_tcp registered, which is exactly the precondition that used
	// to trigger "empty service_tcp" for any non-mailbox stream.
	conn, err := hb.Connect(ctx, a.nodeAddr, a.h.QUICLocalAddr())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	t.Run("recovers misrouted DHT message", func(t *testing.T) {
		before := a.h.Node().DebugStatsData().RxPackets

		str, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatalf("OpenStreamSync: %v", err)
		}
		bAddr := ksB.Address()
		hdr := protocol.Header{
			Version: protocol.ProtocolVersion,
			MsgType: protocol.MsgPing,
			TxID:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		}
		body := &protocol.BodyPing{Address: bAddr[:]}
		raw, err := protocol.MarshalSignedMessageKeyStore(hdr, body, ksB, bAddr)
		if err != nil {
			t.Fatalf("MarshalSignedMessageKeyStore: %v", err)
		}
		if _, err := str.Write(raw); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := str.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if a.h.Node().DebugStatsData().RxPackets > before {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("expected DHT ping to be recovered via fallback; RxPackets did not advance past %d", before)
	})

	t.Run("still rejects non-DHT garbage", func(t *testing.T) {
		before := a.h.Node().DebugStatsData().RxPackets

		str, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatalf("OpenStreamSync: %v", err)
		}
		if _, err := str.Write([]byte("not a dht message, not a mailbox frame either")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := str.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		// Give the gateway goroutine time to process and (correctly) drop it.
		time.Sleep(300 * time.Millisecond)
		if after := a.h.Node().DebugStatsData().RxPackets; after != before {
			t.Fatalf("garbage stream should not be counted as a DHT rx: before=%d after=%d", before, after)
		}
	})
}
