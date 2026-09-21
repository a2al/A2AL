// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package chat

import (
	"testing"
	"time"

	"github.com/a2al/a2al"
)

func addr(n byte) a2al.Address {
	var a a2al.Address
	a[0] = 0xA0
	a[1] = n
	return a
}

func TestStore_requestAcceptRefuseBlock(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, b := addr(1), addr(2)
	if err := s.PutOutPending(b); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOutPending(b); err != nil {
		t.Fatal("retry out_pending must be ok")
	}
	if err := s.SetMutual(b); err != nil {
		t.Fatal(err)
	}
	e, ok := s.Get(b)
	if !ok || e.State != StateMutual {
		t.Fatalf("%+v", e)
	}
	if _, err := s.AppendOut(b, Rec{Kind: KindText, Body: "hi"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(b); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(b); ok {
		t.Fatal("refuse must drop roster")
	}

	if err := s.PutInPending(a, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := s.Block(a); err != nil {
		t.Fatal(err)
	}
	e, ok = s.Get(a)
	if !ok || e.State != StateBlocked {
		t.Fatal("block must keep row")
	}
	got, _, _ := s.Read(a, 0, 50)
	if len(got) != 0 {
		t.Fatal("block must drop log")
	}
}

func TestStore_pendingExpiry(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_700_000_000, 0)
	s.SetNow(func() time.Time { return start })
	p := addr(3)
	if err := s.PutInPending(p, "x"); err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return start.Add(IgnoreTTL + time.Second) })
	if _, ok := s.Get(p); ok {
		t.Fatal("expired in_pending must vanish")
	}
}

func TestStore_seqDedupAndUnsent(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := addr(4)
	if err := s.PutOutPending(p); err != nil {
		t.Fatal(err)
	}
	seq, err := s.AppendOut(p, Rec{Kind: KindText, Body: "a"})
	if err != nil || seq != 1 {
		t.Fatalf("seq=%d err=%v", seq, err)
	}
	if err := s.SetMutual(p); err != nil {
		t.Fatal(err)
	}
	dup, edge, err := s.AppendIn(p, Rec{Seq: 7, Kind: KindText, Body: "in"})
	if err != nil || dup {
		t.Fatal(err)
	}
	if !edge || s.UnreadCount(p) != 1 {
		t.Fatalf("unread edge=%v n=%d", edge, s.UnreadCount(p))
	}
	dup, edge, err = s.AppendIn(p, Rec{Seq: 7, Kind: KindText, Body: "in"})
	if err != nil || !dup {
		t.Fatalf("dup=%v err=%v", dup, err)
	}
	if n := len(s.Unsent(p)); n != 1 {
		t.Fatalf("unsent %d", n)
	}
	if err := s.MarkSent(p, 1); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Unsent(p)); n != 0 {
		t.Fatalf("unsent after mark %d", n)
	}
	if err := s.MarkRead(p, 0); err != nil {
		t.Fatal(err)
	}
	if n := s.UnreadCount(p); n != 0 {
		t.Fatalf("unread after mark %d", n)
	}
	entries, scanned, more := s.Read(p, 0, 10)
	if more || scanned != 2 || len(entries) != 2 || entries[0].Idx != 1 {
		t.Fatalf("read %+v scanned=%d more=%v", entries, scanned, more)
	}
}

func TestStore_notFriends(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendOut(addr(9), Rec{Kind: KindText, Body: "x"}); err != ErrNotFriends {
		t.Fatalf("err=%v", err)
	}
}

func TestStore_pendingCap(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < PendingCap; i++ {
		if err := s.PutInPending(addr(byte(i+1)), ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutInPending(addr(0xFE), ""); err != ErrPendingFull {
		t.Fatalf("err=%v", err)
	}
}

func TestStore_contactsStableOrder(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return time.Unix(100, 0) })
	if err := s.SetMutual(addr(3)); err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return time.Unix(200, 0) })
	if err := s.SetMutual(addr(1)); err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return time.Unix(150, 0) })
	if err := s.SetMutual(addr(2)); err != nil {
		t.Fatal(err)
	}
	got := s.Contacts()
	if len(got) != 3 || got[0].Peer != addr(1) || got[1].Peer != addr(2) || got[2].Peer != addr(3) {
		t.Fatalf("%+v", got)
	}
	again := s.Contacts()
	for i := range got {
		if got[i].Peer != again[i].Peer {
			t.Fatalf("unstable %v vs %v", got, again)
		}
	}
}
