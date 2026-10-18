// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWakeAPI_bindTestUnbind(t *testing.T) {
	d := newTestDaemon(t)
	d.wake = newWakeScheduler(d)
	t.Cleanup(d.wake.stop)
	ch := make(chan []byte, 4)
	d.wake.spawn = func(_ wakeBinding, stdin []byte) {
		ch <- append([]byte(nil), stdin...)
	}
	aid := newTestAgent(t, d)
	helper := filepath.Join(t.TempDir(), "wake-helper")
	if err := os.WriteFile(helper, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	base := srv.URL + "/agents/" + aid.String() + "/wake"

	putBody, _ := json.Marshal(map[string]any{"via": "exec", "cmd": helper, "args": []string{"--flag"}})
	req, _ := http.NewRequest(http.MethodPut, base, bytes.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put %d", resp.StatusCode)
	}

	resp, err = http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["bound"] != true {
		t.Fatalf("get %#v", got)
	}

	req, _ = http.NewRequest(http.MethodPost, base+"/test", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test %d", resp.StatusCode)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("test did not spawn")
	}

	req, _ = http.NewRequest(http.MethodDelete, base, bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete %d", resp.StatusCode)
	}
	resp, err = http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got = map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["bound"] != false {
		t.Fatalf("after delete %#v", got)
	}
}

func TestWakeAPI_loopbackOnly(t *testing.T) {
	d := newTestDaemon(t)
	d.wake = newWakeScheduler(d)
	t.Cleanup(d.wake.stop)
	aid := newTestAgent(t, d)
	body := []byte(`{"via":"exec","cmd":"/nope"}`)
	req := httptest.NewRequest(http.MethodPut, "/agents/"+aid.String()+"/wake", bytes.NewReader(body))
	req.RemoteAddr = "8.8.8.8:9"
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	d.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
}

func TestWakeAPI_rejectsShellAndUnknownVia(t *testing.T) {
	d := newTestDaemon(t)
	d.wake = newWakeScheduler(d)
	t.Cleanup(d.wake.stop)
	aid := newTestAgent(t, d)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	base := srv.URL + "/agents/" + aid.String() + "/wake"

	put := func(body string) int {
		req, _ := http.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if put(`{"via":"ssh","cmd":"helper"}`) != http.StatusBadRequest {
		t.Fatal("ssh")
	}
	if put(`{"via":"exec","cmd":"bash"}`) != http.StatusBadRequest {
		t.Fatal("bash")
	}
}

func TestWakeAPI_bindACP(t *testing.T) {
	d := newTestDaemon(t)
	d.wake = newWakeScheduler(d)
	t.Cleanup(d.wake.stop)
	aid := newTestAgent(t, d)
	helper := filepath.Join(t.TempDir(), "acp-helper")
	if err := os.WriteFile(helper, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	base := srv.URL + "/agents/" + aid.String() + "/wake"

	body, _ := json.Marshal(map[string]any{"via": "acp", "cmd": helper, "args": []string{"acp"}, "cwd": cwd})
	req, _ := http.NewRequest(http.MethodPut, base, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put %d", resp.StatusCode)
	}
	resp, err = http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["via"] != "acp" || got["bound"] != true {
		t.Fatalf("get %#v", got)
	}
	want, err := resolveWakeCwd(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if got["cwd"] != want {
		t.Fatalf("cwd %#v want %s", got["cwd"], want)
	}

	bad, _ := json.Marshal(map[string]any{"via": "acp", "cmd": helper, "cwd": filepath.Join(cwd, "nope")})
	req, _ = http.NewRequest(http.MethodPut, base, bytes.NewReader(bad))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad cwd %d", resp.StatusCode)
	}

	body, _ = json.Marshal(map[string]any{
		"via": "acp", "cmd": helper, "session_cwd": "/work/in-container", "cap": 12000,
	})
	req, _ = http.NewRequest(http.MethodPut, base, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session cwd %d", resp.StatusCode)
	}
	resp, err = http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got = map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["session_cwd"] != "/work/in-container" {
		t.Fatalf("session_cwd %#v", got["session_cwd"])
	}
	if got["cap"] != float64(12000) {
		t.Fatalf("cap %#v", got["cap"])
	}
}

func TestWakeAPI_handle(t *testing.T) {
	d := newTestDaemon(t)
	d.wake = newWakeScheduler(d)
	t.Cleanup(d.wake.stop)
	aid := newTestAgent(t, d)
	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	base := srv.URL + "/agents/" + aid.String() + "/wake/handle"

	req, _ := http.NewRequest(http.MethodPut, base, bytes.NewReader([]byte(`{"handle":"tid-1"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put %d", resp.StatusCode)
	}
	resp, err = http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["handle"] != "tid-1" {
		t.Fatalf("%#v", got)
	}
	req, _ = http.NewRequest(http.MethodDelete, base, bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("del %d", resp.StatusCode)
	}
}

func TestWakeAPI_unboundAIDUnchanged(t *testing.T) {
	d := newTestDaemon(t)
	d.wake = newWakeScheduler(d)
	t.Cleanup(d.wake.stop)
	aid := newTestAgent(t, d)
	d.bus.Publish(Event{
		Type: "chat.received",
		AID:  aid,
		Data: map[string]any{"peer": wakeTestAID(1).String(), "seq": uint64(1)},
	})
	time.Sleep(50 * time.Millisecond)
	_, _, ok := d.wake.snapshot(aid)
	if ok {
		t.Fatal("unbound aid should stay unbound")
	}
}

func TestLastMap_pidSessionError(t *testing.T) {
	m := lastMap(wakeLastResult{
		At: time.Now(), PID: 42, SessionID: "sess-1", Error: "boom", Step: "prompt",
	})
	if m["pid"] != 42 || m["session_id"] != "sess-1" || m["error"] != "boom" || m["step"] != "prompt" {
		t.Fatalf("%#v", m)
	}
}

func TestWake_spawnLastDiagnostics(t *testing.T) {
	d := newTestDaemon(t)
	d.wake = newWakeScheduler(d)
	t.Cleanup(d.wake.stop)
	aid := newTestAgent(t, d)
	bin := buildFakeACP(t)
	dir := agentTmpWork(t)

	execBind := wakeBinding{AID: aid, Via: "exec", Cmd: bin, Cwd: dir}
	if err := d.wake.putBinding(execBind); err != nil {
		t.Fatal(err)
	}
	d.spawnWakeCommand(execBind, []byte(`{"aid":"x"}`))
	_, last, ok := d.wake.snapshot(aid)
	if !ok || last.PID <= 0 || last.Error != "" || last.Step != "exec" {
		t.Fatalf("exec last %#v bound %v", last, ok)
	}

	acpBind := wakeBinding{AID: aid, Via: "acp", Cmd: bin, Cwd: dir, Cap: 1000}
	if err := d.wake.putBinding(acpBind); err != nil {
		t.Fatal(err)
	}
	t.Setenv("A2AL_ACP_MODE", "ok")
	t.Setenv("A2AL_ACP_DUMP", filepath.Join(dir, "dump.json"))
	d.spawnWakeCommand(acpBind, []byte(`{"aid":"x","events":[]}`))
	_, last, ok = d.wake.snapshot(aid)
	if !ok || last.PID <= 0 || last.SessionID == "" || last.Error != "" {
		t.Fatalf("acp last %#v bound %v", last, ok)
	}

	srv := httptest.NewServer(d.routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/agents/" + aid.String() + "/wake")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	lm, _ := got["last"].(map[string]any)
	if lm == nil {
		t.Fatalf("status %#v", got)
	}
	if lm["pid"] == nil || lm["session_id"] == "" || lm["error"] != nil {
		t.Fatalf("last %#v", lm)
	}
}
