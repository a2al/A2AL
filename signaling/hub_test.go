// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package signaling

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestHubTargetedICEPair(t *testing.T) {
	hub, err := ListenHub("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()

	base := "ws://" + hub.Addr().String()
	subURL, err := SubscribeURL(base)
	if err != nil {
		t.Fatal(err)
	}
	room := RoomID("aidaaaaaaaaaaaaaaaaaaaa", "aidbbbbbbbbbbbbbbbbbbbb")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Callee: persistent /signal + reg
	subWS, _, err := websocket.Dial(ctx, subURL, &websocket.DialOptions{Subprotocols: []string{SubprotocolICE}})
	if err != nil {
		t.Fatal(err)
	}
	defer subWS.CloseNow()
	regFr, err := EncodeFrame(Frame{T: "reg", AID: "aidbbbbbbbbbbbbbbbbbbbb"})
	if err != nil {
		t.Fatal(err)
	}
	if err := subWS.Write(ctx, websocket.MessageBinary, regFr); err != nil {
		t.Fatal(err)
	}

	callerURL, err := AppendRoomToICEURL(base, room)
	if err != nil {
		t.Fatal(err)
	}
	callerURL, _ = AppendQuery(callerURL, "target", "aidbbbbbbbbbbbbbbbbbbbb")
	callerURL, _ = AppendQuery(callerURL, "caller", "aidaaaaaaaaaaaaaaaaaaaa")

	errCh := make(chan error, 2)
	go func() {
		c1, _, e := websocket.Dial(ctx, callerURL, &websocket.DialOptions{Subprotocols: []string{SubprotocolICE}})
		if e != nil {
			errCh <- e
			return
		}
		defer c1.CloseNow()
		calleeICE, err := AppendRoomToICEURL(base, room)
		if err != nil {
			errCh <- err
			return
		}
		c2, _, e := websocket.Dial(ctx, calleeICE, &websocket.DialOptions{Subprotocols: []string{SubprotocolICE}})
		if e != nil {
			errCh <- e
			return
		}
		defer c2.CloseNow()
		errCh <- nil
	}()

	// Read incoming notification on subscriber
	_, incData, err := subWS.Read(ctx)
	if err != nil {
		t.Fatal("read incoming:", err)
	}
	inc, err := DecodeFrame(incData)
	if err != nil {
		t.Fatal(err)
	}
	if inc.T != "incoming" || inc.Caller != "aidaaaaaaaaaaaaaaaaaaaa" || inc.Target != "aidbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("incoming frame: %+v", inc)
	}

	select {
	case e := <-errCh:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("timeout")
	}
}
