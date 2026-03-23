// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"net"
	"testing"
	"time"
)

func TestIsQUICPacket(t *testing.T) {
	cases := []struct {
		name   string
		first  byte
		isQUIC bool
	}{
		{"QUIC long header Initial", 0xc0, true},
		{"QUIC long header Handshake", 0xe0, true},
		{"QUIC long header 0-RTT", 0xd0, true},
		{"QUIC short header (1-RTT) min", 0x40, true},
		{"QUIC short header (1-RTT) max", 0x7f, true},
		{"CBOR map empty", 0xa0, false},
		{"CBOR map 5 entries", 0xa5, false},
		{"CBOR map 23 entries", 0xb7, false},
		{"CBOR map max definite-short", 0xbf, false},
		{"zero byte", 0x00, false},
	}
	for _, tc := range cases {
		if got := isQUICPacket(tc.first); got != tc.isQUIC {
			t.Errorf("%s (0x%02x): got %v, want %v", tc.name, tc.first, got, tc.isQUIC)
		}
	}
}

func TestUDPMux_routing(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	mux := NewUDPMux(conn)
	mux.StartReadLoop()
	defer mux.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	sender, err := net.DialUDP("udp4", nil, localAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	// Start DHT receiver goroutine before sending.
	dhtTr := mux.DHTTransport()
	dhtDone := make(chan []byte, 1)
	go func() {
		data, _, err := dhtTr.Receive()
		if err == nil {
			dhtDone <- data
		}
	}()
	time.Sleep(200 * time.Millisecond) // let goroutine block on Receive

	// CBOR map first byte (0xa5) → DHT
	dhtPayload := []byte{0xa5, 1, 2, 3}
	if _, err := sender.Write(dhtPayload); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-dhtDone:
		if len(got) != len(dhtPayload) || got[0] != 0xa5 {
			t.Fatalf("DHT got %x, want %x", got, dhtPayload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DHT receive timeout")
	}

	// QUIC long header first byte (0xc0) → QUIC
	quicPayload := []byte{0xc0, 10, 20, 30, 40}
	if _, err := sender.Write(quicPayload); err != nil {
		t.Fatal(err)
	}
	qConn := mux.QUICPacketConn()
	_ = qConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := qConn.ReadFrom(buf)
	if err != nil {
		t.Fatal("QUIC ReadFrom:", err)
	}
	if n != len(quicPayload) || buf[0] != 0xc0 {
		t.Fatalf("QUIC got %x, want %x", buf[:n], quicPayload)
	}

	// QUIC short header first byte (0x40) → QUIC (no MarkQUICPeer needed)
	shortPayload := []byte{0x40, 0xaa, 0xbb}
	if _, err := sender.Write(shortPayload); err != nil {
		t.Fatal(err)
	}
	_ = qConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = qConn.ReadFrom(buf)
	if err != nil {
		t.Fatal("QUIC short ReadFrom:", err)
	}
	if n != len(shortPayload) || buf[0] != 0x40 {
		t.Fatalf("QUIC short got %x, want %x", buf[:n], shortPayload)
	}
}
