// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"net"
	"testing"
	"time"

	ice "github.com/pion/ice/v3"

	"github.com/a2al/a2al/signaling"
)

func TestSelectedBasePort(t *testing.T) {
	host, err := ice.NewCandidateHost(&ice.CandidateHostConfig{Network: "udp", Address: "192.0.2.1", Port: 5001, Component: 1})
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := selectedBasePort(host); !ok || p != 5001 {
		t.Fatalf("host: got %d,%v", p, ok)
	}
	srflx, err := ice.NewCandidateServerReflexive(&ice.CandidateServerReflexiveConfig{
		Network: "udp", Address: "203.0.113.9", Port: 40000, Component: 1, RelAddr: "0.0.0.0", RelPort: 5002,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := selectedBasePort(srflx); !ok || p != 5002 {
		t.Fatalf("srflx: got %d,%v want base port", p, ok)
	}
	relay, err := ice.NewCandidateRelay(&ice.CandidateRelayConfig{
		Network: "udp", Address: "198.51.100.1", Port: 3478, Component: 1, RelAddr: "203.0.113.9", RelPort: 40000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := selectedBasePort(relay); ok {
		t.Fatal("relay must not be pruned")
	}
}

func TestCandidateNetCloseExceptPortNoMatchKeepsAll(t *testing.T) {
	n, err := newCandidateNet()
	if err != nil {
		t.Fatal(err)
	}
	c1, err := n.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := n.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if got := n.closeExceptPort(1); got != 0 {
		t.Fatalf("unmatched port closed %d sockets", got)
	}
	keep := c1.LocalAddr().(*net.UDPAddr).Port
	if got := n.closeExceptPort(keep); got != 1 {
		t.Fatalf("closed %d, want 1", got)
	}
	if _, err := c1.WriteTo([]byte("x"), c1.LocalAddr()); err != nil {
		t.Fatal("kept socket closed:", err)
	}
	if _, err := c2.WriteTo([]byte("x"), c1.LocalAddr()); err == nil {
		t.Fatal("dropped socket still open")
	}
}

func TestICEPruneKeepsSelectedPath(t *testing.T) {
	relay, err := signaling.StartRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	room := signaling.RoomID("aidaaaaaaaaaaaaaaaaaaaa", "aidbbbbbbbbbbbbbbbbbbbb")
	wsURL, err := signaling.AppendRoomToICEURL(relay.BaseURL(), room)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type res struct {
		s *iceSession
		e error
	}
	aCh, bCh := make(chan res, 1), make(chan res, 1)
	v4Only := []ice.NetworkType{ice.NetworkTypeUDP4}
	go func() { s, e := runICESession(ctx, wsURL, nil, true, true, false, v4Only, nil); aCh <- res{s, e} }()
	go func() { s, e := runICESession(ctx, wsURL, nil, false, true, false, v4Only, nil); bCh <- res{s, e} }()
	a, b := <-aCh, <-bCh
	if a.e != nil || b.e != nil {
		t.Fatal(a.e, b.e)
	}
	defer a.s.Close()
	defer b.s.Close()

	for _, s := range []*iceSession{a.s, b.s} {
		deadline := time.Now().Add(3 * time.Second)
		for !s.iceConnected.Load() && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		s.pruneUnselected()
	}

	ping := func(from, to *iceSession, msg string) {
		t.Helper()
		if _, err := from.iceConn.Write([]byte(msg)); err != nil {
			t.Fatal("write after prune:", err)
		}
		buf := make([]byte, 64)
		_ = to.iceConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := to.iceConn.Read(buf)
		if err != nil || string(buf[:n]) != msg {
			t.Fatalf("read after prune: %q %v", buf[:n], err)
		}
	}
	ping(a.s, b.s, "a-to-b")
	ping(b.s, a.s, "b-to-a")

	pair, err := a.s.agent.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		t.Fatal("selected pair lost after prune", err)
	}
	a.s.cnet.mu.Lock()
	for _, c := range a.s.cnet.conns {
		if c.LocalAddr().(*net.UDPAddr).Port != pair.Local.Port() {
			t.Errorf("unselected socket %s still recorded", c.LocalAddr())
		}
	}
	a.s.cnet.mu.Unlock()
}
