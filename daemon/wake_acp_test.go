// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/a2al/a2al/config"
)

func TestResolveWakeCwd(t *testing.T) {
	dir := t.TempDir()
	got, err := resolveWakeCwd(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("empty cwd")
	}
	if _, err := resolveWakeCwd(filepath.Join(dir, "missing")); err != errWakeCwd {
		t.Fatalf("missing: %v", err)
	}
	home, err := resolveWakeCwd("")
	if err != nil || home == "" {
		t.Fatalf("home: %q %v", home, err)
	}
}

func TestDriveACP_promptContainsCoordinatesAndDropsNotify(t *testing.T) {
	dump := &testACPDump{}
	err := withFakeACP(t, "ok", dump, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{
			Payload:  []byte(`{"aid":"aa","events":[{"type":"chat.received","peer":"bb","seq":12}]}`),
			CWD:      t.TempDir(),
			MCPStdio: []any{map[string]any{"name": "a2al", "command": "a2ald", "args": []string{"--mcp-stdio"}}},
		}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if dump.prompt == "" || !containsAll(dump.prompt, `"aid":"aa"`, `"peer":"bb"`, `"seq":12`) {
		t.Fatalf("prompt %q", dump.prompt)
	}
	if dump.cwd == "" {
		t.Fatal("cwd not passed")
	}
	if len(dump.mcp) != 1 {
		t.Fatalf("mcp %#v", dump.mcp)
	}
}

func TestDriveACP_permissionAllow(t *testing.T) {
	dump := &testACPDump{}
	err := withFakeACP(t, "perm", dump, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{Payload: []byte(`{"aid":"x","events":[]}`), CWD: t.TempDir()}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !dump.permOK {
		t.Fatal("permission was not answered")
	}
}

func TestDriveACP_authError(t *testing.T) {
	err := withFakeACP(t, "auth", &testACPDump{}, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{Payload: []byte(`{}`), CWD: t.TempDir()}, nil)
	})
	if !errors.Is(err, errWakeACPAuth) {
		t.Fatalf("got %v", err)
	}
}

func TestWakeMCPHTTP_emptyHeaders(t *testing.T) {
	d := &Daemon{cfg: &config.Config{APIAddr: "127.0.0.1:2121"}}
	got := d.wakeMCPHTTP()
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) != 1 {
		t.Fatalf("%s", raw)
	}
	m := rows[0]
	if m["type"] != "http" || m["name"] != "a2al" || m["url"] != "http://127.0.0.1:2121/mcp/" {
		t.Fatalf("%s", raw)
	}
	hdrs, ok := m["headers"].([]any)
	if !ok || hdrs == nil || len(hdrs) != 0 {
		t.Fatalf("headers want [] got %#v in %s", m["headers"], raw)
	}
}

func TestDriveACP_prefersHTTPWhenAdvertised(t *testing.T) {
	dump := &testACPDump{}
	d := &Daemon{cfg: &config.Config{APIAddr: "127.0.0.1:2121"}}
	err := withFakeACP(t, "http", dump, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{
			Payload:  []byte(`{"events":[]}`),
			CWD:      t.TempDir(),
			MCPHTTP:  d.wakeMCPHTTP(),
			MCPStdio: []any{map[string]any{"name": "a2al", "command": "a2ald"}},
		}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dump.mcp) != 1 {
		t.Fatalf("mcp %#v", dump.mcp)
	}
	raw, _ := json.Marshal(dump.mcp[0])
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != "http" || m["url"] != "http://127.0.0.1:2121/mcp/" {
		t.Fatalf("mcp %s", raw)
	}
	hdrs, ok := m["headers"].([]any)
	if !ok || hdrs == nil || len(hdrs) != 0 {
		t.Fatalf("headers want [] got %#v in %s", m["headers"], raw)
	}
}

func TestSpawnWakeACP(t *testing.T) {
	bin := buildFakeACP(t)
	dir := agentTmpWork(t)
	dumpPath := filepath.Join(dir, "dump.json")
	t.Setenv("A2AL_ACP_MODE", "perm")
	t.Setenv("A2AL_ACP_DUMP", dumpPath)
	d := &Daemon{}
	payload := []byte(`{"aid":"zz","events":[{"type":"mailbox.received","count":1}]}`)
	res, _, err := d.spawnWakeACP(wakeBinding{Via: "acp", Cmd: bin, Cwd: dir}, payload, "", 0, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.PID <= 0 {
		t.Fatalf("pid %d", res.PID)
	}
	if res.SessionID == "" {
		t.Fatal("session_id")
	}
	raw, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatal(err)
	}
	var dump struct {
		Prompt string `json:"prompt"`
		CWD    string `json:"cwd"`
		PermOK bool   `json:"permOk"`
		MCP    []any  `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		t.Fatal(err)
	}
	if !containsAll(dump.Prompt, `"aid":"zz"`, `"mailbox.received"`) {
		t.Fatalf("prompt %s", dump.Prompt)
	}
	wantCwd, _ := resolveWakeCwd(dir)
	if !wakePathEqual(dump.CWD, wantCwd) {
		t.Fatalf("cwd %q want %q", dump.CWD, wantCwd)
	}
	if !dump.PermOK {
		t.Fatal("perm")
	}
	if len(dump.MCP) == 0 {
		t.Fatal("expected mcp inject")
	}
}

type testACPDump struct {
	mu       sync.Mutex
	prompt   string
	cwd      string
	mcp      []any
	permOK   bool
	loaded   string
	methods  []string
	cancel   bool
	newCount int
}

func withFakeACP(t *testing.T, mode string, dump *testACPDump, fn func(io.Writer, io.Reader) error) error {
	t.Helper()
	agentR, clientW := io.Pipe()
	clientR, agentW := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveFakeACP(agentR, agentW, mode, dump)
		_ = agentW.Close()
	}()
	errCh := make(chan error, 1)
	go func() {
		errCh <- fn(clientW, clientR)
		_ = clientW.Close()
	}()
	var err error
	select {
	case err = <-errCh:
	case <-time.After(8 * time.Second):
		_ = clientW.Close()
		_ = agentR.Close()
		t.Fatal("driveACP timeout")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = agentR.Close()
	}
	return err
}

func serveFakeACP(r io.Reader, w io.Writer, mode string, dump *testACPDump) {
	br := bufio.NewReader(r)
	var promptID json.RawMessage
	waitingPerm := false
	waitingCap := false
	write := func(env acpEnvelope) {
		b, err := json.Marshal(env)
		if err != nil {
			return
		}
		_, _ = w.Write(append(b, '\n'))
	}
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			var env acpEnvelope
			if json.Unmarshal(trimACPLine(line), &env) != nil {
				continue
			}
			if waitingPerm && len(env.ID) > 0 && env.Method == "" {
				dump.mu.Lock()
				dump.permOK = true
				dump.mu.Unlock()
				waitingPerm = false
				write(acpEnvelope{JSONRPC: "2.0", ID: promptID, Result: mustJSON(map[string]any{"stopReason": "end_turn"})})
				continue
			}
			if waitingCap && env.Method == "session/cancel" {
				dump.mu.Lock()
				dump.cancel = true
				dump.mu.Unlock()
				waitingCap = false
				write(acpEnvelope{JSONRPC: "2.0", ID: env.ID, Result: mustJSON(map[string]any{})})
				write(acpEnvelope{JSONRPC: "2.0", ID: promptID, Result: mustJSON(map[string]any{"stopReason": "cancelled"})})
				continue
			}
			if env.Method == "" {
				continue
			}
			switch env.Method {
			case "initialize":
				httpCap := mode == "http"
				loadSess := mode == "load" || mode == "loadfail" || mode == "loadmigrate" || mode == "usage" || mode == "cap" || mode == "capdrop"
				write(acpEnvelope{
					JSONRPC: "2.0",
					ID:      env.ID,
					Result: mustJSON(map[string]any{
						"protocolVersion": 1,
						"agentCapabilities": map[string]any{
							"loadSession":     loadSess,
							"mcpCapabilities": map[string]any{"http": httpCap},
						},
					}),
				})
			case "session/load":
				dump.mu.Lock()
				dump.methods = append(dump.methods, "session/load")
				dump.mu.Unlock()
				if mode == "loadfail" {
					write(acpEnvelope{
						JSONRPC: "2.0",
						ID:      env.ID,
						Error:   &acpRPCError{Code: -32000, Message: "unknown session"},
					})
					continue
				}
				var lp struct {
					SessionID string `json:"sessionId"`
					CWD       string `json:"cwd"`
				}
				_ = json.Unmarshal(env.Params, &lp)
				sid := lp.SessionID
				if mode == "loadmigrate" {
					sid = "sess-migrated"
				}
				dump.mu.Lock()
				dump.loaded = lp.SessionID
				if lp.CWD != "" {
					dump.cwd = lp.CWD
				}
				dump.mu.Unlock()
				write(acpEnvelope{JSONRPC: "2.0", ID: env.ID, Result: mustJSON(map[string]any{"sessionId": sid})})
			case "session/cancel":
				dump.mu.Lock()
				dump.cancel = true
				dump.mu.Unlock()
				write(acpEnvelope{JSONRPC: "2.0", ID: env.ID, Result: mustJSON(map[string]any{})})
			case "session/new":
				if mode == "auth" {
					write(acpEnvelope{
						JSONRPC: "2.0",
						ID:      env.ID,
						Error:   &acpRPCError{Code: -32000, Message: "login required"},
					})
					continue
				}
				var p struct {
					CWD string `json:"cwd"`
					MCP []any  `json:"mcpServers"`
				}
				_ = json.Unmarshal(env.Params, &p)
				dump.mu.Lock()
				dump.cwd = p.CWD
				dump.mcp = p.MCP
				dump.newCount++
				dump.mu.Unlock()
				write(acpEnvelope{JSONRPC: "2.0", ID: env.ID, Result: mustJSON(map[string]any{"sessionId": "sess-1"})})
			case "session/prompt":
				var p struct {
					Prompt []struct {
						Text string `json:"text"`
					} `json:"prompt"`
				}
				_ = json.Unmarshal(env.Params, &p)
				text := ""
				if len(p.Prompt) > 0 {
					text = p.Prompt[0].Text
				}
				dump.mu.Lock()
				dump.prompt = text
				dump.mu.Unlock()
				write(acpEnvelope{
					JSONRPC: "2.0",
					Method:  "session/update",
					Params:  mustJSON(map[string]any{"sessionId": "sess-1"}),
				})
				if mode == "drop" {
					return
				}
				if mode == "usage" || mode == "cap" || mode == "capdrop" {
					tokens := 12385
					if mode == "cap" || mode == "capdrop" {
						tokens = 99999
					}
					write(acpEnvelope{
						JSONRPC: "2.0",
						Method:  "session/update",
						Params: mustJSON(map[string]any{
							"sessionId": "sess-1",
							"update": map[string]any{
								"sessionUpdate": "usage_update",
								"used":          tokens,
								"token_count":   map[string]any{"total": tokens},
							},
						}),
					})
					if mode == "capdrop" {
						return
					}
					if mode == "cap" {
						promptID = append(json.RawMessage(nil), env.ID...)
						waitingCap = true
						continue
					}
				}
				if mode == "perm" {
					promptID = append(json.RawMessage(nil), env.ID...)
					waitingPerm = true
					write(acpEnvelope{
						JSONRPC: "2.0",
						ID:      json.RawMessage("99001"),
						Method:  "session/request_permission",
						Params: mustJSON(map[string]any{
							"sessionId": "sess-1",
							"options": []any{
								map[string]any{"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"},
							},
						}),
					})
					continue
				}
				write(acpEnvelope{JSONRPC: "2.0", ID: env.ID, Result: mustJSON(map[string]any{"stopReason": "end_turn"})})
			}
		}
		if err != nil {
			return
		}
	}
}

func agentTmpWork(t *testing.T) string {
	t.Helper()
	if d := strings.TrimSpace(os.Getenv("A2AL_AGENT_TMP")); d != "" {
		dir := filepath.Join(d, strings.ReplaceAll(t.Name(), "/", "_"))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir
	}
	return t.TempDir()
}

func buildFakeACP(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	src := filepath.Join(filepath.Dir(file), "testdata", "fake_acp")
	bin := filepath.Join(t.TempDir(), "fakeacp")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build fake_acp: %v\n%s", err, out)
	}
	return bin
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

func TestDriveACP_loadSession(t *testing.T) {
	dump := &testACPDump{}
	var res acpDriveResult
	err := withFakeACP(t, "load", dump, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{
			Payload: []byte(`{"events":[]}`),
			CWD:     "/work/in-container",
			Handle:  "sess-keep",
		}, &res)
	})
	if err != nil {
		t.Fatal(err)
	}
	if dump.loaded != "sess-keep" {
		t.Fatalf("loaded %q", dump.loaded)
	}
	if dump.newCount != 0 {
		t.Fatalf("new %d", dump.newCount)
	}
	if dump.cwd != "/work/in-container" {
		t.Fatalf("cwd %q", dump.cwd)
	}
	if !res.UsedLoad {
		t.Fatal("used load")
	}
}

func TestDriveACP_loadFailFallsBackToNew(t *testing.T) {
	dump := &testACPDump{}
	err := withFakeACP(t, "loadfail", dump, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{Payload: []byte(`{}`), CWD: t.TempDir(), Handle: "gone"}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if dump.newCount != 1 {
		t.Fatalf("new %d", dump.newCount)
	}
}

func TestDriveACP_usageAndCap(t *testing.T) {
	dump := &testACPDump{}
	var res acpDriveResult
	err := withFakeACP(t, "usage", dump, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{Payload: []byte(`{}`), CWD: t.TempDir(), Cap: 50000}, &res)
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Spend != 12385 {
		t.Fatalf("spend %d", res.Spend)
	}
	if res.StopReason != "end_turn" {
		t.Fatalf("stop %q", res.StopReason)
	}

	dump = &testACPDump{}
	res = acpDriveResult{}
	err = withFakeACP(t, "cap", dump, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{Payload: []byte(`{}`), CWD: t.TempDir(), Cap: 1000}, &res)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !dump.cancel {
		t.Fatal("expected session/cancel")
	}
	if res.CancelledFor != "cap" {
		t.Fatalf("cancelled %q", res.CancelledFor)
	}
	if res.StopReason != "cancelled" {
		t.Fatalf("stop %q", res.StopReason)
	}
}

func TestDriveACP_loadMigratesHandle(t *testing.T) {
	dump := &testACPDump{}
	got := ""
	err := withFakeACP(t, "loadmigrate", dump, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{
			Payload:     []byte(`{}`),
			CWD:         t.TempDir(),
			Handle:      "sess-old",
			OnSessionID: func(id string) { got = id },
		}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if dump.loaded != "sess-old" {
		t.Fatalf("loaded %q", dump.loaded)
	}
	if got != "sess-migrated" {
		t.Fatalf("handle %q", got)
	}
}

func TestDriveACP_exitBeforePromptReply(t *testing.T) {
	err := withFakeACP(t, "drop", &testACPDump{}, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{Payload: []byte(`{}`), CWD: t.TempDir()}, nil)
	})
	if !errors.Is(err, errWakeACPNoReply) {
		t.Fatalf("got %v", err)
	}
}

func TestDriveACP_capExitWithoutPromptReply(t *testing.T) {
	dump := &testACPDump{}
	var res acpDriveResult
	committed := false
	err := withFakeACP(t, "capdrop", dump, func(in io.Writer, out io.Reader) error {
		return driveACP(in, out, acpDriveOpts{
			Payload:    []byte(`{}`),
			CWD:        t.TempDir(),
			Cap:        1000,
			OnPromptOK: func() { committed = true },
		}, &res)
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.CancelledFor != "cap" {
		t.Fatalf("cancelled %q", res.CancelledFor)
	}
	if res.StopReason != "cancelled" {
		t.Fatalf("stop %q", res.StopReason)
	}
	if !committed {
		t.Fatal("expected delivered commit")
	}
}

func TestACPExtractSpend(t *testing.T) {
	n, _ := acpExtractSpend([]byte(`{"update":{"sessionUpdate":"usage_update","used":10,"token_count":{"total":74764}}}`))
	if n != 74764 {
		t.Fatalf("got %d", n)
	}
	n, _ = acpExtractSpend([]byte(`{"total_tokens":1059569}`))
	if n != 1059569 {
		t.Fatalf("got %d", n)
	}
}
