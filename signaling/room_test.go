// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package signaling

import "testing"

func TestRoomID_symmetric(t *testing.T) {
	a, b := "a2al1aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "a2al1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if RoomID(a, b) != RoomID(b, a) {
		t.Fatal("RoomID must be symmetric")
	}
}

func TestRoomID_deterministic(t *testing.T) {
	r := RoomID("alice", "bob")
	if len(r) != 32 {
		t.Fatalf("RoomID length=%d, want 32 hex chars", len(r))
	}
	if r != RoomID("alice", "bob") {
		t.Fatal("RoomID not deterministic")
	}
}

func TestAppendRoomQuery(t *testing.T) {
	got, err := AppendRoomQuery("wss://signal.example.com/ice", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	want := "wss://signal.example.com/ice?room=abc123"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAppendRoomQuery_replacesExisting(t *testing.T) {
	got, err := AppendRoomQuery("ws://host/ice?room=old&x=1", "new")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ws://host/ice?room=new&x=1" {
		t.Fatalf("got %q", got)
	}
}
