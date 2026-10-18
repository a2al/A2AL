// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/a2al/a2al"
)

func wakeTestAID(n byte) a2al.Address {
	var a a2al.Address
	a[0] = a2al.VersionEd25519
	a[1] = n
	return a
}

func testWakeScheduler(t *testing.T) (*wakeScheduler, chan []byte) {
	t.Helper()
	ch := make(chan []byte, 8)
	s := &wakeScheduler{
		bindings:  make(map[a2al.Address]wakeBinding),
		windows:   make(map[a2al.Address]*wakeWindow),
		last:      make(map[a2al.Address]wakeLastResult),
		handles:   make(map[a2al.Address]string),
		delivered: make(map[a2al.Address]wakeDelivered),
		outgoing:  make(map[a2al.Address]wakeDelivered),
		busy:      make(map[a2al.Address]struct{}),
		held:      make(map[a2al.Address]*wakeWindow),
		quiet:     40 * time.Millisecond,
		maxWait:   250 * time.Millisecond,
		eventsCap: wakeEventsCap,
	}
	s.spawn = func(b wakeBinding, stdin []byte) {
		s.commitDelivered(b.AID)
		ch <- append([]byte(nil), stdin...)
	}
	t.Cleanup(s.stop)
	return s, ch
}

func parseWakePayload(t *testing.T, raw []byte) wakePayload {
	t.Helper()
	var p wakePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("payload: %v %s", err, raw)
	}
	return p
}

func waitWakeSpawn(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for wake spawn")
		return nil
	}
}

func assertNoWakeSpawn(t *testing.T, ch <-chan []byte) {
	t.Helper()
	select {
	case b := <-ch:
		t.Fatalf("unexpected spawn %s", b)
	case <-time.After(80 * time.Millisecond):
	}
}

func TestWake_nilSchedulerNoPanic(t *testing.T) {
	var s *wakeScheduler
	s.onEvent(Event{Type: "chat.received", AID: wakeTestAID(1)})
	s.fire(wakeTestAID(1))
	s.stop()
	s.removeBinding(wakeTestAID(1))
}

func TestWake_unboundDoesNotSpawn(t *testing.T) {
	s, ch := testWakeScheduler(t)
	aid := wakeTestAID(1)
	s.onEvent(Event{
		Type: "chat.received",
		AID:  aid,
		Data: map[string]any{"peer": "p", "seq": uint64(1)},
	})
	assertNoWakeSpawn(t, ch)
}

func TestWake_samePeerBurstOneSpawn(t *testing.T) {
	s, ch := testWakeScheduler(t)
	aid := wakeTestAID(2)
	s.bindings[aid] = wakeBinding{AID: aid, Via: "exec", Cmd: "helper"}
	peer := wakeTestAID(9).String()
	for i := 1; i <= 3; i++ {
		s.onEvent(Event{
			Type: "chat.received",
			AID:  aid,
			Data: map[string]any{"peer": peer, "seq": uint64(i)},
		})
	}
	p := parseWakePayload(t, waitWakeSpawn(t, ch))
	if p.AID != aid.String() {
		t.Fatalf("aid %s", p.AID)
	}
	if len(p.Events) != 1 || p.Events[0].Type != "chat.received" || p.Events[0].Peer != peer || p.Events[0].Seq != 3 {
		t.Fatalf("events %#v", p.Events)
	}
	assertNoWakeSpawn(t, ch)
}

func TestWake_chatAndGroupOneSpawn(t *testing.T) {
	s, ch := testWakeScheduler(t)
	aid := wakeTestAID(3)
	s.bindings[aid] = wakeBinding{AID: aid, Via: "exec", Cmd: "helper"}
	peer := wakeTestAID(8).String()
	s.onEvent(Event{
		Type: "chat.received",
		AID:  aid,
		Data: map[string]any{"peer": peer, "seq": uint64(4)},
	})
	s.onEvent(Event{
		Type: "group.mentioned",
		AID:  aid,
		Data: map[string]any{"group_id": "g1", "entry_id": "e1", "from": peer},
	})
	p := parseWakePayload(t, waitWakeSpawn(t, ch))
	if len(p.Events) != 2 {
		t.Fatalf("want 2 events, got %#v", p.Events)
	}
	assertNoWakeSpawn(t, ch)
}

func TestWake_secondBatchAfterFire(t *testing.T) {
	s, ch := testWakeScheduler(t)
	aid := wakeTestAID(4)
	s.bindings[aid] = wakeBinding{AID: aid, Via: "exec", Cmd: "helper"}
	peer := wakeTestAID(7).String()
	s.onEvent(Event{
		Type: "chat.received",
		AID:  aid,
		Data: map[string]any{"peer": peer, "seq": uint64(1)},
	})
	_ = waitWakeSpawn(t, ch)
	s.onEvent(Event{
		Type: "chat.received",
		AID:  aid,
		Data: map[string]any{"peer": peer, "seq": uint64(2)},
	})
	p := parseWakePayload(t, waitWakeSpawn(t, ch))
	if len(p.Events) != 1 || p.Events[0].Seq != 2 {
		t.Fatalf("%#v", p.Events)
	}
}

func TestWake_maxWaitFiresDuringStream(t *testing.T) {
	s, ch := testWakeScheduler(t)
	s.quiet = time.Second
	s.maxWait = 60 * time.Millisecond
	aid := wakeTestAID(5)
	s.bindings[aid] = wakeBinding{AID: aid, Via: "exec", Cmd: "helper"}
	peer := wakeTestAID(6).String()
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		s.onEvent(Event{
			Type: "chat.received",
			AID:  aid,
			Data: map[string]any{"peer": peer, "seq": uint64(1)},
		})
		time.Sleep(15 * time.Millisecond)
	}
	_ = waitWakeSpawn(t, ch)
}

func TestWake_eventsCap(t *testing.T) {
	s, ch := testWakeScheduler(t)
	s.eventsCap = 2
	aid := wakeTestAID(6)
	s.bindings[aid] = wakeBinding{AID: aid, Via: "exec", Cmd: "helper"}
	for i := byte(1); i <= 3; i++ {
		s.onEvent(Event{
			Type: "chat.received",
			AID:  aid,
			Data: map[string]any{"peer": wakeTestAID(i).String(), "seq": uint64(1)},
		})
	}
	p := parseWakePayload(t, waitWakeSpawn(t, ch))
	if len(p.Events) != 2 {
		t.Fatalf("cap: %#v", p.Events)
	}
}

func TestWake_ignoresUnread(t *testing.T) {
	s, ch := testWakeScheduler(t)
	aid := wakeTestAID(7)
	s.bindings[aid] = wakeBinding{AID: aid, Via: "exec", Cmd: "helper"}
	s.onEvent(Event{Type: "chat.unread", AID: aid, Data: map[string]any{"peer": "x"}})
	s.onEvent(Event{Type: "group.unread", AID: aid, Data: map[string]any{"group_id": "g"}})
	assertNoWakeSpawn(t, ch)
}

func TestWake_inviteSnapshotDoesNotRespawn(t *testing.T) {
	s, ch := testWakeScheduler(t)
	aid := wakeTestAID(8)
	s.bindings[aid] = wakeBinding{AID: aid, Via: "exec", Cmd: "helper"}
	peers := []string{wakeTestAID(1).String(), wakeTestAID(2).String()}
	s.onEvent(Event{
		Type: "chat.invites",
		AID:  aid,
		Data: map[string]any{"count": 2, "peers": peers},
	})
	_ = waitWakeSpawn(t, ch)
	s.onEvent(Event{
		Type: "chat.invites",
		AID:  aid,
		Data: map[string]any{"count": 2, "peers": []string{peers[1], peers[0]}},
	})
	assertNoWakeSpawn(t, ch)
	s.onEvent(Event{
		Type: "chat.invites",
		AID:  aid,
		Data: map[string]any{"count": 3, "peers": []string{peers[0], peers[1], wakeTestAID(3).String()}},
	})
	_ = waitWakeSpawn(t, ch)
}

func TestWake_newSeqStillSpawns(t *testing.T) {
	s, ch := testWakeScheduler(t)
	aid := wakeTestAID(9)
	s.bindings[aid] = wakeBinding{AID: aid, Via: "exec", Cmd: "helper"}
	peer := wakeTestAID(4).String()
	s.onEvent(Event{Type: "chat.received", AID: aid, Data: map[string]any{"peer": peer, "seq": uint64(1)}})
	_ = waitWakeSpawn(t, ch)
	s.onEvent(Event{Type: "chat.received", AID: aid, Data: map[string]any{"peer": peer, "seq": uint64(1)}})
	assertNoWakeSpawn(t, ch)
	s.onEvent(Event{Type: "chat.received", AID: aid, Data: map[string]any{"peer": peer, "seq": uint64(2)}})
	p := parseWakePayload(t, waitWakeSpawn(t, ch))
	if p.Events[0].Seq != 2 {
		t.Fatalf("%#v", p.Events)
	}
}

func TestWake_fireNowSkipsDelivered(t *testing.T) {
	s, ch := testWakeScheduler(t)
	aid := wakeTestAID(10)
	s.bindings[aid] = wakeBinding{AID: aid, Via: "exec", Cmd: "helper"}
	peer := wakeTestAID(5).String()
	s.onEvent(Event{Type: "chat.received", AID: aid, Data: map[string]any{"peer": peer, "seq": uint64(1)}})
	_ = waitWakeSpawn(t, ch)
	if !s.fireNow(aid) {
		t.Fatal("fireNow")
	}
	_ = waitWakeSpawn(t, ch)
}

func TestWake_payloadIncludesHandle(t *testing.T) {
	s, ch := testWakeScheduler(t)
	aid := wakeTestAID(11)
	s.bindings[aid] = wakeBinding{AID: aid, Via: "exec", Cmd: "helper"}
	s.setHandle(aid, "tid-9")
	s.onEvent(Event{Type: "chat.received", AID: aid, Data: map[string]any{"peer": wakeTestAID(6).String(), "seq": uint64(1)}})
	p := parseWakePayload(t, waitWakeSpawn(t, ch))
	if p.Handle != "tid-9" {
		t.Fatalf("handle %q", p.Handle)
	}
}

func TestExpandWakeArgs(t *testing.T) {
	if argsNeedHandle([]string{"queue", "--message", "x"}) {
		t.Fatal("dump helper should not need handle")
	}
	if !argsNeedHandle([]string{"queue", "--thread", "{{handle}}"}) {
		t.Fatal("need handle")
	}
	got := expandWakeArgs([]string{"queue", "--thread", "{{handle}}", "--x={{handle}}"}, "TID")
	if got[2] != "TID" || got[3] != "--x=TID" {
		t.Fatalf("%q", got)
	}
}

func TestWake_persistHandleAndLast(t *testing.T) {
	d := newTestDaemon(t)
	d.wake = newWakeScheduler(d)
	aid := newTestAgent(t, d)
	helper := filepath.Join(t.TempDir(), "h")
	if err := os.WriteFile(helper, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := d.wake.putBinding(wakeBinding{AID: aid, Via: "exec", Cmd: helper}); err != nil {
		t.Fatal(err)
	}
	d.wake.setHandle(aid, "TID")
	d.wake.setLast(aid, wakeLastResult{
		At: time.Now(), Ok: true, Spend: 9, Cap: 50, PID: 77, SessionID: "sess-1",
		CapUnit: wakeCostUnitTokens, SpendUnit: wakeCostUnitTokens, Source: wakeCostSourceACP,
	})
	s2 := newWakeScheduler(d)
	if s2.snapshotHandle(aid) != "TID" {
		t.Fatalf("handle %q", s2.snapshotHandle(aid))
	}
	_, last, ok := s2.snapshot(aid)
	if !ok || last.Spend != 9 || last.Cap != 50 || last.PID != 77 || last.SessionID != "sess-1" {
		t.Fatalf("last %#v bound %v", last, ok)
	}
}

func TestEffectiveWakeCap(t *testing.T) {
	if g := effectiveWakeCap(0, 50000, nil, ""); g != 50000 {
		t.Fatalf("default %d", g)
	}
	if g := effectiveWakeCap(100, 50000, nil, ""); g != 100 {
		t.Fatalf("bind %d", g)
	}
	rem := int64(40)
	if g := effectiveWakeCap(100, 50000, &rem, "tokens"); g != 40 {
		t.Fatalf("remaining tokens %d", g)
	}
	if g := effectiveWakeCap(100, 50000, &rem, "usd_cents"); g != 100 {
		t.Fatalf("unit mismatch %d", g)
	}
}
