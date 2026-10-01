// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

func testAID(t *testing.T, hexPair string) a2al.Address {
	t.Helper()
	aid, err := a2al.ParseAddress(strings.ToLower("A0" + strings.Repeat(hexPair, 20)))
	if err != nil {
		t.Fatal(err)
	}
	return aid
}

func TestConnPool_acquireCallerCancelKeepsDial(t *testing.T) {
	fresh := newStubConn()
	dialDone := make(chan struct{})
	var dials int
	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		dials++
		time.Sleep(300 * time.Millisecond)
		close(dialDone)
		return fresh, false, nil
	}, slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	local := testAID(t, "a1")
	remote := testAID(t, "a2")
	start := time.Now()
	_, _, err := p.acquire(ctx, local, remote, nil, false, true)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("caller blocked on the full dial")
	}
	select {
	case <-dialDone:
	case <-time.After(time.Second):
		t.Fatal("dial did not finish after the caller returned")
	}
	var conn quic.Connection
	deadline := time.Now().Add(time.Second)
	for {
		var ok bool
		conn, _, ok = p.cachedLive(connPoolKey{local: local, remote: remote})
		if ok && conn == fresh {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("finished dial must stay in the pool")
		}
		time.Sleep(10 * time.Millisecond)
	}

	got, _, err := p.acquire(context.Background(), local, remote, nil, false, true)
	if err != nil || got != fresh {
		t.Fatalf("second acquire got %v err=%v", got, err)
	}
	if dials != 1 {
		t.Fatalf("dials=%d want 1", dials)
	}
}

func TestConnPool_userSkipsBackoff(t *testing.T) {
	var dials int
	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		dials++
		return nil, false, errors.New("dial fail")
	}, slog.Default())

	ctx := context.Background()
	local := testAID(t, "ab")
	remote := testAID(t, "cd")

	if _, _, err := p.acquire(ctx, local, remote, nil, false, false); err == nil {
		t.Fatal("want auto dial error")
	}
	if dials != 1 {
		t.Fatalf("dials=%d want 1", dials)
	}

	_, _, err := p.acquire(ctx, local, remote, nil, false, false)
	if err == nil || !strings.Contains(err.Error(), "backoff") {
		t.Fatalf("want backoff, got %v", err)
	}
	if dials != 1 {
		t.Fatalf("auto must not redial in backoff, dials=%d", dials)
	}

	if _, _, err := p.acquire(ctx, local, remote, nil, false, true); err == nil {
		t.Fatal("want user dial error")
	}
	if dials != 2 {
		t.Fatalf("user must skip backoff, dials=%d", dials)
	}

	if _, _, err := p.acquire(ctx, local, remote, nil, false, true); err == nil {
		t.Fatal("want user dial error")
	}
	if dials != 3 {
		t.Fatalf("user fail must not write backoff, dials=%d", dials)
	}
}

type stubConn struct {
	ctx     context.Context
	cancel  context.CancelFunc
	openOK  bool
	openErr error
}

func newStubConn() *stubConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &stubConn{ctx: ctx, cancel: cancel}
}

func (c *stubConn) AcceptStream(context.Context) (quic.Stream, error) { panic("unused") }
func (c *stubConn) AcceptUniStream(context.Context) (quic.ReceiveStream, error) {
	panic("unused")
}
func (c *stubConn) OpenStream() (quic.Stream, error) { panic("unused") }
func (c *stubConn) OpenStreamSync(context.Context) (quic.Stream, error) {
	if c.openOK {
		return nil, nil
	}
	if c.openErr != nil {
		return nil, c.openErr
	}
	panic("unused")
}
func (c *stubConn) OpenUniStream() (quic.SendStream, error) { panic("unused") }
func (c *stubConn) OpenUniStreamSync(context.Context) (quic.SendStream, error) {
	panic("unused")
}
func (c *stubConn) LocalAddr() net.Addr  { return nil }
func (c *stubConn) RemoteAddr() net.Addr { return nil }
func (c *stubConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.cancel()
	return nil
}
func (c *stubConn) Context() context.Context { return c.ctx }
func (c *stubConn) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}
func (c *stubConn) SendDatagram([]byte) error { return nil }
func (c *stubConn) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, nil
}

func TestConnPool_evictUnheld(t *testing.T) {
	p := newModeAConnPool(nil, slog.Default())
	local := testAID(t, "11")
	remote := testAID(t, "22")
	stale := newStubConn()
	p.pool[connPoolKey{local: local, remote: remote}] = &connPoolEntry{conn: stale, lastUsed: time.Now()}

	if !p.evictUnheld(stale) {
		t.Fatal("want evict")
	}
	if stale.Context().Err() == nil {
		t.Fatal("conn must close")
	}
	if _, ok := p.pool[connPoolKey{local: local, remote: remote}]; ok {
		t.Fatal("slot still present")
	}

	held := newStubConn()
	p.pool[connPoolKey{local: local, remote: remote}] = &connPoolEntry{conn: held, refs: 1, lastUsed: time.Now()}
	if p.evictUnheld(held) {
		t.Fatal("retained conn must stay")
	}
	if held.Context().Err() != nil {
		t.Fatal("retained conn closed")
	}
}

func TestOpenPooled_redialsOnce(t *testing.T) {
	stale := newStubConn()
	fresh := newStubConn()
	var dials int
	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		dials++
		return fresh, false, nil
	}, slog.Default())
	local := testAID(t, "33")
	remote := testAID(t, "44")
	p.pool[connPoolKey{local: local, remote: remote}] = &connPoolEntry{conn: stale, lastUsed: time.Now()}

	d := &Daemon{connPool: p, log: slog.Default()}
	opens := 0
	conn, _, _, err := d.openPooled(context.Background(), local, remote, nil, false, true, stale, func(_ context.Context, c quic.Connection) (quic.Stream, error) {
		opens++
		if c == stale {
			return nil, context.DeadlineExceeded
		}
		if c != fresh {
			t.Fatalf("open on unexpected conn")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if conn != fresh {
		t.Fatal("want redialled conn")
	}
	if dials != 1 || opens != 2 {
		t.Fatalf("dials=%d opens=%d", dials, opens)
	}
	if stale.Context().Err() == nil {
		t.Fatal("stale must close")
	}
}

func TestOpenPooled_dialFailIsTheError(t *testing.T) {
	stale := newStubConn()
	dialErr := errors.New("dial boom")
	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		return nil, false, dialErr
	}, slog.Default())
	local := testAID(t, "55")
	remote := testAID(t, "66")
	p.pool[connPoolKey{local: local, remote: remote}] = &connPoolEntry{conn: stale, lastUsed: time.Now()}

	d := &Daemon{connPool: p, log: slog.Default()}
	_, _, _, err := d.openPooled(context.Background(), local, remote, nil, false, false, stale, func(context.Context, quic.Connection) (quic.Stream, error) {
		return nil, context.DeadlineExceeded
	})
	if !errors.Is(err, dialErr) {
		t.Fatalf("want dial error, got %v", err)
	}
}

func TestOpenPooled_accessDeniedNoDial(t *testing.T) {
	stale := newStubConn()
	var dials int
	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		dials++
		return nil, false, errors.New("dial")
	}, slog.Default())
	local := testAID(t, "77")
	remote := testAID(t, "88")
	p.pool[connPoolKey{local: local, remote: remote}] = &connPoolEntry{conn: stale, lastUsed: time.Now()}

	d := &Daemon{connPool: p, log: slog.Default()}
	_, _, _, err := d.openPooled(context.Background(), local, remote, nil, false, true, stale, func(context.Context, quic.Connection) (quic.Stream, error) {
		return nil, protocol.ErrAccessDenied
	})
	if !errors.Is(err, protocol.ErrAccessDenied) {
		t.Fatalf("got %v", err)
	}
	if dials != 0 {
		t.Fatalf("dials=%d", dials)
	}
	if stale.Context().Err() != nil {
		t.Fatal("must not close")
	}
}

func TestOpenPooled_callerCancelNoDial(t *testing.T) {
	stale := newStubConn()
	var dials int
	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		dials++
		return nil, false, errors.New("dial")
	}, slog.Default())
	local := testAID(t, "99")
	remote := testAID(t, "aa")
	p.pool[connPoolKey{local: local, remote: remote}] = &connPoolEntry{conn: stale, lastUsed: time.Now()}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &Daemon{connPool: p, log: slog.Default()}
	_, _, _, err := d.openPooled(ctx, local, remote, nil, false, true, stale, func(context.Context, quic.Connection) (quic.Stream, error) {
		return nil, context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if dials != 0 {
		t.Fatalf("dials=%d", dials)
	}
	if stale.Context().Err() != nil {
		t.Fatal("caller cancel must not close a live conn")
	}
}

func TestOpenPooled_repairWaitDoesNotStopDial(t *testing.T) {
	stale := newStubConn()
	fresh := newStubConn()
	dialDone := make(chan struct{})
	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		time.Sleep(400 * time.Millisecond)
		close(dialDone)
		return fresh, false, nil
	}, slog.Default())
	local := testAID(t, "b1")
	remote := testAID(t, "b2")
	p.pool[connPoolKey{local: local, remote: remote}] = &connPoolEntry{conn: stale, lastUsed: time.Now()}

	d := &Daemon{connPool: p, log: slog.Default()}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, _, err := d.openPooled(ctx, local, remote, nil, false, true, stale, func(context.Context, quic.Connection) (quic.Stream, error) {
		return nil, context.DeadlineExceeded
	})
	if err == nil {
		t.Fatal("want repair wait error")
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Fatal("caller blocked on the full dial")
	}
	select {
	case <-dialDone:
	case <-time.After(time.Second):
		t.Fatal("dial did not finish after the caller returned")
	}
	conn, _, ok := p.cachedLive(connPoolKey{local: local, remote: remote})
	if !ok || conn != fresh {
		t.Fatal("finished dial must stay in the pool")
	}
}

func TestOpenPooled_secondOpenDropsReplacement(t *testing.T) {
	stale := newStubConn()
	fresh := newStubConn()
	p := newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		return fresh, false, nil
	}, slog.Default())
	local := testAID(t, "c1")
	remote := testAID(t, "c2")
	p.pool[connPoolKey{local: local, remote: remote}] = &connPoolEntry{conn: stale, lastUsed: time.Now()}

	d := &Daemon{connPool: p, log: slog.Default()}
	_, _, _, err := d.openPooled(context.Background(), local, remote, nil, false, true, stale, func(context.Context, quic.Connection) (quic.Stream, error) {
		return nil, context.DeadlineExceeded
	})
	if err == nil {
		t.Fatal("want second open error")
	}
	if _, _, ok := p.cachedLive(connPoolKey{local: local, remote: remote}); ok {
		t.Fatal("replacement must be dropped")
	}
	if fresh.Context().Err() == nil {
		t.Fatal("replacement must close")
	}
}
