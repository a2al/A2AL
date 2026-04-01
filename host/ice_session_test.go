// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"testing"
	"time"

	"github.com/a2al/a2al/signaling"
)

func TestICESessionHostOnlyLoopback(t *testing.T) {
	relay, err := signaling.StartRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	room := signaling.RoomID("aidaaaaaaaaaaaaaaaaaaaa", "aidbbbbbbbbbbbbbbbbbbbb")
	wsURL, err := signaling.AppendRoomQuery(relay.BaseURL()+"/ice", room)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type res struct {
		s *iceSession
		e error
	}
	ctrlCh := make(chan res, 1)
	othCh := make(chan res, 1)

	go func() {
		s, e := runICESession(ctx, wsURL, nil, true, true)
		ctrlCh <- res{s, e}
	}()
	go func() {
		s, e := runICESession(ctx, wsURL, nil, false, true)
		othCh <- res{s, e}
	}()

	a := <-ctrlCh
	b := <-othCh
	if a.e != nil {
		t.Fatal("controlling:", a.e)
	}
	if b.e != nil {
		t.Fatal("controlled:", b.e)
	}
	defer a.s.Close()
	defer b.s.Close()

	payload := []byte("a2al-ice-ping")
	if _, err := a.s.iceConn.Write(payload); err != nil {
		t.Fatal("write:", err)
	}
	buf := make([]byte, 256)
	n, err := b.s.iceConn.Read(buf)
	if err != nil {
		t.Fatal("read:", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("got %q want %q", buf[:n], payload)
	}
}
