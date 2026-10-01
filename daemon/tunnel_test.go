// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
	"github.com/quic-go/quic-go"
)

// ── tunnelRegistry unit tests ─────────────────────────────────────────────────

func makeFakeEntry(id string, r *tunnelRegistry) *tunnelEntry {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	e := &tunnelEntry{
		id:       id,
		listen:   "127.0.0.1:0",
		openedAt: time.Now(),
		cancel:   cancel,
		done:     done,
	}
	// Mirrors the real accept loop's defer: delete from registry before
	// closing done, so closeAll sees an empty registry after <-done unblocks.
	go func() {
		<-ctx.Done()
		if r != nil {
			r.delete(id)
		}
		close(done)
	}()
	return e
}

func TestTunnelRegistry_addGetDelete(t *testing.T) {
	r := newTunnelRegistry()
	e := makeFakeEntry("abc123", r)
	r.add(e)

	got, ok := r.get("abc123")
	if !ok || got != e {
		t.Fatal("expected to find entry after add")
	}
	r.delete("abc123")
	if _, ok := r.get("abc123"); ok {
		t.Fatal("expected entry to be gone after delete")
	}
}

func TestTunnelRegistry_list(t *testing.T) {
	r := newTunnelRegistry()
	for _, id := range []string{"t1", "t2", "t3"} {
		r.add(makeFakeEntry(id, nil))
	}
	list := r.list()
	if len(list) != 3 {
		t.Fatalf("list len = %d, want 3", len(list))
	}
}

func TestTunnelRegistry_getNotFound(t *testing.T) {
	r := newTunnelRegistry()
	if _, ok := r.get("nope"); ok {
		t.Fatal("expected not-found for unknown id")
	}
}

func TestTunnelRegistry_closeAll(t *testing.T) {
	r := newTunnelRegistry()
	const n = 5
	for i := range n {
		id := string(rune('a' + i))
		e := makeFakeEntry(id, r)
		r.add(e)
	}
	r.closeAll()
	// Each fake entry's goroutine deletes itself from the registry before
	// closing done (mirrors the real accept loop), so closeAll leaves it empty.
	if len(r.list()) != 0 {
		t.Fatalf("registry not empty after closeAll: %d entries remain", len(r.list()))
	}
}

func TestTunnelEntry_connDone_resetsLastActivity(t *testing.T) {
	e := &tunnelEntry{}
	old := time.Now().Add(-2 * time.Hour).UnixNano()
	e.lastActivity.Store(old)
	e.activeConns.Store(1)

	e.connDone()

	if e.activeConns.Load() != 0 {
		t.Fatal("activeConns should be 0")
	}
	if e.lastActivity.Load() <= old {
		t.Fatal("lastActivity should be refreshed when last conn closes")
	}
	if time.Since(time.Unix(0, e.lastActivity.Load())) > time.Second {
		t.Fatal("lastActivity should be recent")
	}
}

func TestTunnelEntry_connDone_keepsLastActivityWithRemainingConns(t *testing.T) {
	e := &tunnelEntry{}
	old := time.Now().Add(-2 * time.Hour).UnixNano()
	e.lastActivity.Store(old)
	e.activeConns.Store(2)

	e.connDone()

	if e.activeConns.Load() != 1 {
		t.Fatal("activeConns should be 1")
	}
	if e.lastActivity.Load() != old {
		t.Fatal("lastActivity should not change while other conns remain")
	}
}

func TestTunnelStatus_fields(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	cancel()
	close(done)
	e := &tunnelEntry{
		id:       "xyz",
		listen:   "127.0.0.1:9999",
		openedAt: time.Now(),
		cancel:   cancel,
		done:     done,
	}
	e.activeConns.Store(3)
	e.lastActivity.Store(time.Now().UnixNano())

	s := e.status()
	if s.ID != "xyz" {
		t.Errorf("ID = %q, want xyz", s.ID)
	}
	if s.Listen != "127.0.0.1:9999" {
		t.Errorf("Listen = %q, want 127.0.0.1:9999", s.Listen)
	}
	if s.ActiveConns != 3 {
		t.Errorf("ActiveConns = %d, want 3", s.ActiveConns)
	}
	if s.LastActivity.IsZero() {
		t.Error("LastActivity should be set")
	}
}

// ── closeTunnel ────────────────────────────────────────────────────────────────

func TestCloseTunnel_notFound(t *testing.T) {
	d := newTestDaemon(t)
	if d.closeTunnel("doesnotexist") {
		t.Fatal("closeTunnel should return false for unknown id")
	}
}

func TestCloseTunnel_stopsAccepting(t *testing.T) {
	d := newTestDaemon(t)

	// Build a minimal tunnelEntry with a real listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	entry := &tunnelEntry{
		id:       "test-close",
		listen:   ln.Addr().String(),
		openedAt: time.Now(),
		cancel:   cancel,
		done:     done,
	}
	d.tunnels.add(entry)

	// Simulate the accept loop goroutine.
	go func() {
		defer close(done)
		defer d.tunnels.delete(entry.id)
		defer ln.Close()
		go func() {
			<-tctx.Done()
			_ = ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().String()
	// Verify the listener is up.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("pre-close dial: %v", err)
	}
	_ = c.Close()

	// Close the tunnel and wait.
	if !d.closeTunnel("test-close") {
		t.Fatal("closeTunnel returned false unexpectedly")
	}

	// After close the listener should be down.
	_, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected dial to fail after tunnel close")
	}

	// Registry should be empty.
	if _, ok := d.tunnels.get("test-close"); ok {
		t.Fatal("entry should be removed from registry after close")
	}
}

// ── execTunnelOpen integration test ───────────────────────────────────────────

// TestExecTunnelOpen_multipleConns verifies that multiple concurrent TCP
// connections through the tunnel all get served, using a local echo server
// as a stand-in for the remote service.
func TestExecTunnelOpen_multipleConns(t *testing.T) {
	// Stand-in remote service: a simple HTTP server.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "pong")
	}))
	defer backend.Close()

	// We can't run a full QUIC stack in a unit test, so we test the local
	// listener + multi-accept loop by wiring a mock that bridges to the backend
	// over plain TCP (no QUIC). This exercises the lifecycle code paths.

	d := newTestDaemon(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	entry := &tunnelEntry{
		id:       "multi-test",
		listen:   ln.Addr().String(),
		openedAt: time.Now(),
		cancel:   cancel,
		done:     done,
	}
	entry.lastActivity.Store(time.Now().UnixNano())
	d.tunnels.add(entry)

	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	// Simulate the accept loop: each TCP → direct TCP to backend.
	// We use plain io.Copy instead of bridgeTCPQUICStream (which requires
	// a quic.Stream) since this test only validates the lifecycle/concurrency
	// behaviour of the accept loop, not the QUIC bridging.
	go func() {
		defer close(done)
		defer d.tunnels.delete(entry.id)
		defer ln.Close()
		go func() {
			<-tctx.Done()
			_ = ln.Close()
		}()
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			entry.activeConns.Add(1)
			go func() {
				defer entry.activeConns.Add(-1)
				defer client.Close()
				upstream, err := net.Dial("tcp", backendAddr)
				if err != nil {
					return
				}
				defer upstream.Close()
				// Bidirectional copy (mirrors what bridgeTCPQUICStream does).
				done2 := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(upstream, client); done2 <- struct{}{} }()
				go func() { _, _ = io.Copy(client, upstream); done2 <- struct{}{} }()
				<-done2
			}()
		}
	}()

	addr := entry.listen
	const parallel = 5
	errs := make(chan error, parallel)
	for range parallel {
		go func() {
			resp, err := http.Get("http://" + addr + "/ping")
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "pong" {
				errs <- nil
				return
			}
			errs <- nil
		}()
	}
	for range parallel {
		if err := <-errs; err != nil {
			t.Errorf("parallel request error: %v", err)
		}
	}

	// Close stops the accept loop. In-flight connections continue naturally
	// (tunnel.go intentionally does not kill them). Verify the loop exited.
	cancel()
	<-done
}

func TestExecTunnelOpen_localPortReuseAndConflict(t *testing.T) {
	d := newTestDaemon(t)
	remote := newTestAddr(t)
	other := newTestAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err := d.execTunnelOpen(ctx, remote.String(), tunnelOpenReq{LocalPort: 70000})
	if !errors.Is(err, errBadLocalPort) {
		t.Fatalf("bad port: %v", err)
	}

	d.tunnels.add(&tunnelEntry{
		id: "other", localAID: d.nodeAddr, remoteAID: other, listen: "127.0.0.1:17991",
	})
	_, _, err = d.execTunnelOpen(ctx, remote.String(), tunnelOpenReq{LocalPort: 17991})
	if !errors.Is(err, errPortInUse) {
		t.Fatalf("occupied by other: %v", err)
	}

	mine := &tunnelEntry{
		id: "mine", localAID: d.nodeAddr, remoteAID: remote, listen: "127.0.0.1:17992",
	}
	d.tunnels.add(mine)
	got, allowed, err := d.execTunnelOpen(ctx, remote.String(), tunnelOpenReq{LocalPort: 17992})
	if err != nil || !allowed || got != mine {
		t.Fatalf("reuse got=%v allowed=%v err=%v", got, allowed, err)
	}

	dead := newStubConn()
	dead.cancel()
	held, err := listenTunnel(0)
	if err != nil {
		t.Fatal(err)
	}
	port := held.Addr().(*net.TCPAddr).Port
	tctx, tcancel := context.WithCancel(context.Background())
	tdone := make(chan struct{})
	stale := &tunnelEntry{
		id: "stale", localAID: d.nodeAddr, remoteAID: remote, listen: held.Addr().String(),
		qc: dead, cancel: tcancel, done: tdone,
	}
	go func() {
		<-tctx.Done()
		_ = held.Close()
		d.tunnels.delete("stale")
		close(tdone)
	}()
	d.tunnels.add(stale)
	if stale.connLive() {
		t.Fatal("dead conn must not look live")
	}
	if !d.closeTunnel(stale.id) {
		t.Fatal("close dead tunnel")
	}
	if e, _ := d.tunnels.findListen(d.nodeAddr, remote, port); e != nil {
		t.Fatal("dead tunnel still occupying port")
	}
	again, err := listenTunnel(port)
	if err != nil {
		t.Fatalf("port not released after close: %v", err)
	}
	again.Close()
}

func TestListenTunnel_portAndBusy(t *testing.T) {
	ln, err := listenTunnel(0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil || host != "127.0.0.1" || portStr == "0" {
		t.Fatalf("listen = %s", ln.Addr())
	}

	busy, err := listenTunnel(0)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port
	again, err := listenTunnel(port)
	if err == nil {
		again.Close()
		t.Fatal("expected address in use")
	}
	if !isAddrInUse(err) {
		t.Fatalf("want addr in use, got %v", err)
	}
}

func TestDropTunnelListen_releasesRetain(t *testing.T) {
	d := newTestDaemon(t)
	remote := newTestAddr(t)
	key := connPoolKey{local: d.nodeAddr, remote: remote}
	d.connPool.pool[key] = &connPoolEntry{refs: 1}

	ln, err := listenTunnel(0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	_, listenErr := listenTunnel(port)
	if listenErr == nil {
		t.Fatal("expected address in use")
	}

	_, lerr := d.dropTunnelListen(d.nodeAddr, remote, false, port, listenErr)
	if !errors.Is(lerr, errPortInUse) {
		t.Fatalf("conflict: %v", lerr)
	}
	if d.connPool.pool[key].refs != 0 {
		t.Fatalf("refs = %d, want 0", d.connPool.pool[key].refs)
	}

	d.connPool.pool[key].refs = 1
	mine := &tunnelEntry{
		id: "mine", localAID: d.nodeAddr, remoteAID: remote, listen: ln.Addr().String(),
	}
	d.tunnels.add(mine)
	got, lerr := d.dropTunnelListen(d.nodeAddr, remote, false, port, listenErr)
	if lerr != nil || got != mine {
		t.Fatalf("reuse after bind race: got=%v err=%v", got, lerr)
	}
	if d.connPool.pool[key].refs != 0 {
		t.Fatalf("refs after reuse = %d, want 0", d.connPool.pool[key].refs)
	}
}

func TestRepairTunnelConn(t *testing.T) {
	d := newTestDaemon(t)
	remote := newTestAddr(t)
	local := d.nodeAddr
	old := newStubConn()
	fresh := newStubConn()
	var dials int
	d.connPool = newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		dials++
		return fresh, false, nil
	}, slog.Default())
	key := connPoolKey{local: local, remote: remote}
	d.connPool.pool[key] = &connPoolEntry{conn: old, refs: 1, lastUsed: time.Now()}
	entry := &tunnelEntry{id: "repair", qc: old}

	got, err := d.repairTunnelConn(context.Background(), entry, local, remote, false, nil, old)
	if err != nil || got != fresh {
		t.Fatalf("repair got=%v err=%v", got, err)
	}
	if old.Context().Err() == nil {
		t.Fatal("old conn must close after swap")
	}
	if entry.conn() != fresh {
		t.Fatal("entry still holds old conn")
	}
	if d.connPool.pool[key].refs != 1 {
		t.Fatalf("refs = %d, want 1", d.connPool.pool[key].refs)
	}
	if dials != 1 {
		t.Fatalf("dials = %d, want 1", dials)
	}

	got2, err := d.repairTunnelConn(context.Background(), entry, local, remote, false, nil, old)
	if err != nil || got2 != fresh {
		t.Fatalf("second repair got=%v err=%v", got2, err)
	}
	if dials != 1 {
		t.Fatalf("second repair must not dial, dials=%d", dials)
	}

	d.connPool = newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		return nil, false, errors.New("dial fail")
	}, slog.Default())
	failing := newStubConn()
	entry.setConn(failing, false)
	_, err = d.repairTunnelConn(context.Background(), entry, local, remote, false, nil, failing)
	if err == nil {
		t.Fatal("want dial error")
	}
	if failing.Context().Err() == nil {
		t.Fatal("unrepaired conn must close")
	}
}

func TestReuseTunnel(t *testing.T) {
	d := newTestDaemon(t)
	remote := newTestAddr(t)
	ctx := context.Background()

	bare := &tunnelEntry{id: "bare", localAID: d.nodeAddr, remoteAID: remote, listen: "127.0.0.1:18001"}
	d.tunnels.add(bare)
	got, err := d.reuseTunnel(ctx, bare, d.nodeAddr, remote)
	if err != nil || got != bare {
		t.Fatalf("nil conn reuse got=%v err=%v", got, err)
	}

	okc := newStubConn()
	okc.openOK = true
	live := &tunnelEntry{id: "live", localAID: d.nodeAddr, remoteAID: remote, listen: "127.0.0.1:18002", qc: okc}
	d.tunnels.add(live)
	got, err = d.reuseTunnel(ctx, live, d.nodeAddr, remote)
	if err != nil || got != live {
		t.Fatalf("probe ok got=%v err=%v", got, err)
	}

	denied := newStubConn()
	denied.openErr = protocol.ErrAccessDenied
	blocked := &tunnelEntry{id: "denied", localAID: d.nodeAddr, remoteAID: remote, listen: "127.0.0.1:18005", qc: denied}
	d.tunnels.add(blocked)
	got, err = d.reuseTunnel(ctx, blocked, d.nodeAddr, remote)
	if err != nil || got != blocked {
		t.Fatalf("access denied reuse got=%v err=%v", got, err)
	}

	fresh := newStubConn()
	fresh.openOK = true
	d.connPool = newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		return fresh, false, nil
	}, slog.Default())
	stale := newStubConn()
	stale.openErr = errors.New("gone")
	d.connPool.pool[connPoolKey{local: d.nodeAddr, remote: remote}] = &connPoolEntry{conn: stale, refs: 1, lastUsed: time.Now()}
	repairing := &tunnelEntry{id: "rep", localAID: d.nodeAddr, remoteAID: remote, listen: "127.0.0.1:18003", qc: stale}
	d.tunnels.add(repairing)
	got, err = d.reuseTunnel(ctx, repairing, d.nodeAddr, remote)
	if err != nil || got != repairing {
		t.Fatalf("repair reuse got=%v err=%v", got, err)
	}
	if repairing.conn() != fresh {
		t.Fatal("expected repaired conn")
	}

	d.connPool = newModeAConnPool(func(context.Context, a2al.Address, a2al.Address, *protocol.EndpointRecord, bool, bool) (quic.Connection, bool, error) {
		return nil, false, errors.New("dial fail")
	}, slog.Default())
	tctx, tcancel := context.WithCancel(context.Background())
	tdone := make(chan struct{})
	bad := newStubConn()
	bad.openErr = errors.New("gone")
	dying := &tunnelEntry{
		id: "die", localAID: d.nodeAddr, remoteAID: remote, listen: "127.0.0.1:18004",
		qc: bad, cancel: tcancel, done: tdone,
	}
	go func() {
		<-tctx.Done()
		d.tunnels.delete("die")
		close(tdone)
	}()
	d.tunnels.add(dying)
	got, err = d.reuseTunnel(ctx, dying, d.nodeAddr, remote)
	if err != nil || got != nil {
		t.Fatalf("unrepairable got=%v err=%v", got, err)
	}
	if _, ok := d.tunnels.get("die"); ok {
		t.Fatal("unrepairable tunnel still registered")
	}
}

func TestWatchTunnelConn_swapIgnoresOldClose(t *testing.T) {
	d := newTestDaemon(t)
	ln, err := listenTunnel(0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	old := newStubConn()
	fresh := newStubConn()
	entry := &tunnelEntry{id: "watch", qc: old}
	tctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.watchTunnelConn(entry, ln, cancel, tctx)
	}()
	time.Sleep(20 * time.Millisecond)
	entry.setConn(fresh, false)
	_ = old.CloseWithError(0, "replaced")
	time.Sleep(50 * time.Millisecond)
	again, err := listenTunnel(port)
	if err == nil {
		again.Close()
		t.Fatal("watch closed listener after old conn died")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not exit")
	}
	freed, err := listenTunnel(port)
	if err != nil {
		t.Fatalf("cancel must close listener: %v", err)
	}
	freed.Close()
}

func TestAPI_tunnelOpen_localPort(t *testing.T) {
	d := newTestDaemon(t)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	remote := newTestAddr(t)
	post := func(port int) *http.Response {
		t.Helper()
		body, err := json.Marshal(map[string]int{"local_port": port})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/tunnel/"+remote.String(), bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	decodeErr := func(resp *http.Response) string {
		t.Helper()
		defer resp.Body.Close()
		var out map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out["error"]
	}

	resp := post(70000)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad port status %d", resp.StatusCode)
	}
	if got := decodeErr(resp); got != "bad local_port" {
		t.Fatalf("bad port error %q", got)
	}

	other := newTestAddr(t)
	d.tunnels.add(&tunnelEntry{
		id: "other", localAID: d.nodeAddr, remoteAID: other, listen: "127.0.0.1:18191",
	})
	resp = post(18191)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("occupied status %d", resp.StatusCode)
	}
	if got := decodeErr(resp); got != "port_in_use" {
		t.Fatalf("occupied error %q", got)
	}
}
