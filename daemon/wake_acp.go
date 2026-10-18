// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/a2al/a2al/internal/version"
)

var (
	errWakeACPClosed  = errors.New("wake acp: agent stdout closed")
	errWakeACPAuth    = errors.New("wake acp: agent requires login first")
	errWakeACPNoSess  = errors.New("wake acp: no sessionId")
	errWakeCwd        = errors.New("wake cwd must be an existing directory")
	errWakeACPNoReply = errors.New("wake acp: agent exited before prompt reply")
)

type acpEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *acpRPCError    `json:"error,omitempty"`
}

type acpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *acpRPCError) Error() string {
	if e == nil {
		return "wake acp: rpc error"
	}
	if e.Message == "" {
		return fmt.Sprintf("wake acp: rpc error %d", e.Code)
	}
	return "wake acp: " + e.Message
}

type acpDriveOpts struct {
	Payload     []byte
	CWD         string
	Handle      string
	Cap         int64
	MCPHTTP     []any
	MCPStdio    []any
	OnPromptOK  func()
	OnSessionID func(string)
	OnStep      func(string)
	OnSpend     func(int64)
	OnPID       func(int)
}

type acpDriveResult struct {
	SessionID    string
	PID          int
	StopReason   string
	Spend        int64
	Cap          int64
	ModelTag     string
	Step         string
	UsedLoad     bool
	LoadSession  bool
	CancelledFor string
	Stderr       string
}

func (d *Daemon) spawnWakeACP(b wakeBinding, payload []byte, handle string, capn int64, onPromptOK func(), onSession func(string), onStep func(string), onSpend func(int64), onPID func(int)) (acpDriveResult, error, error) {
	var res acpDriveResult
	res.Cap = capn
	cwd, err := resolveWakeCwd(b.Cwd)
	if err != nil {
		return res, nil, err
	}
	sessionCwd := strings.TrimSpace(b.SessionCwd)
	if sessionCwd == "" {
		sessionCwd = cwd
	}
	cmd := exec.Command(b.Cmd, b.Args...)
	cmd.Dir = cwd
	hideWakeWindow(cmd)
	stderr := newTailWriter(wakeStderrCap)
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return res, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return res, nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return res, nil, err
	}
	if cmd.Process != nil {
		res.PID = cmd.Process.Pid
		if onPID != nil {
			onPID(res.PID)
		}
	}
	opts := acpDriveOpts{
		Payload:     payload,
		CWD:         sessionCwd,
		Handle:      handle,
		Cap:         capn,
		OnPromptOK:  onPromptOK,
		OnSessionID: onSession,
		OnStep:      onStep,
		OnSpend:     onSpend,
		OnPID:       onPID,
	}
	if d != nil {
		opts.MCPHTTP = d.wakeMCPHTTP()
		opts.MCPStdio = d.wakeMCPStdio()
	}
	driveErr := driveACP(stdin, stdout, opts, &res)
	_ = stdin.Close()
	waitErr := cmd.Wait()
	res.Stderr = stderr.String()
	if driveErr != nil && errors.Is(driveErr, errWakeACPClosed) && res.StopReason == "" {
		driveErr = errWakeACPNoReply
	}
	return res, waitErr, driveErr
}

func driveACP(in io.Writer, out io.Reader, opts acpDriveOpts, res *acpDriveResult) error {
	if res == nil {
		res = &acpDriveResult{}
	}
	res.Cap = opts.Cap
	step := func(s string) {
		res.Step = s
		if opts.OnStep != nil {
			opts.OnStep(s)
		}
	}
	c := newACPClient(in)
	var trackSpend atomic.Bool
	var resMu sync.Mutex
	c.onNotify = func(method string, params json.RawMessage) {
		if method != "session/update" || !trackSpend.Load() {
			return
		}
		spend, model := acpExtractSpend(params)
		resMu.Lock()
		if model != "" {
			res.ModelTag = model
		}
		if spend > res.Spend {
			res.Spend = spend
			if opts.OnSpend != nil {
				opts.OnSpend(spend)
			}
		}
		hitCap := opts.Cap > 0 && res.Spend >= opts.Cap && res.CancelledFor == "" && res.SessionID != ""
		if hitCap {
			res.CancelledFor = "cap"
		}
		sid := res.SessionID
		resMu.Unlock()
		if hitCap && sid != "" {
			go func() {
				_, _ = c.call("session/cancel", map[string]any{"sessionId": sid})
			}()
		}
	}
	go c.readLoop(out)

	step("initialize")
	raw, err := c.call("initialize", map[string]any{
		"protocolVersion": 1,
		"clientCapabilities": map[string]any{
			"fs":       map[string]any{"readTextFile": false, "writeTextFile": false},
			"terminal": false,
		},
		"clientInfo": map[string]any{
			"name":    "a2ald",
			"title":   "A2AL Daemon",
			"version": version.Version,
		},
	})
	if err != nil {
		return err
	}
	var init struct {
		AgentCapabilities struct {
			LoadSession     bool `json:"loadSession"`
			MCPCapabilities struct {
				HTTP bool `json:"http"`
				SSE  bool `json:"sse"`
			} `json:"mcpCapabilities"`
		} `json:"agentCapabilities"`
	}
	_ = json.Unmarshal(raw, &init)
	res.LoadSession = init.AgentCapabilities.LoadSession

	mcp := opts.MCPStdio
	if init.AgentCapabilities.MCPCapabilities.HTTP && len(opts.MCPHTTP) > 0 {
		mcp = opts.MCPHTTP
	}
	if mcp == nil {
		mcp = []any{}
	}

	sessID := ""
	if opts.Handle != "" && init.AgentCapabilities.LoadSession {
		step("load")
		raw, err = c.call("session/load", map[string]any{
			"sessionId":  opts.Handle,
			"cwd":        opts.CWD,
			"mcpServers": mcp,
		})
		if err == nil {
			var loaded struct {
				SessionID string `json:"sessionId"`
			}
			_ = json.Unmarshal(raw, &loaded)
			sessID = loaded.SessionID
			if sessID == "" {
				sessID = opts.Handle
			}
			res.UsedLoad = true
			if opts.OnSessionID != nil && sessID != "" && sessID != opts.Handle {
				opts.OnSessionID(sessID)
			}
		}
	}
	if sessID == "" {
		step("new")
		raw, err = c.call("session/new", map[string]any{
			"cwd":        opts.CWD,
			"mcpServers": mcp,
		})
		if err != nil {
			if acpLooksLikeAuth(err) {
				return errWakeACPAuth
			}
			return err
		}
		var sess struct {
			SessionID string `json:"sessionId"`
		}
		if err := json.Unmarshal(raw, &sess); err != nil || sess.SessionID == "" {
			return errWakeACPNoSess
		}
		sessID = sess.SessionID
		if opts.OnSessionID != nil {
			opts.OnSessionID(sessID)
		}
	}
	res.SessionID = sessID

	text := "You were woken by a2al. This local identity has new notifications. " +
		"Use a2al tools (MCP server name \"a2al\") to read the ledger and reply if appropriate. " +
		"The JSON below is this batch's coordinates, not a complete todo list; consult pending and the ledger.\n\n" +
		string(opts.Payload)
	step("prompt")
	trackSpend.Store(true)
	raw, err = c.call("session/prompt", map[string]any{
		"sessionId": sessID,
		"prompt":    []any{map[string]any{"type": "text", "text": text}},
	})
	if err != nil {
		if acpLooksLikeAuth(err) {
			return errWakeACPAuth
		}
		if errors.Is(err, errWakeACPClosed) {
			resMu.Lock()
			capHit := res.CancelledFor == "cap"
			if capHit && res.StopReason == "" {
				res.StopReason = "cancelled"
			}
			resMu.Unlock()
			if capHit {
				if opts.OnPromptOK != nil {
					opts.OnPromptOK()
				}
				return nil
			}
			return errWakeACPNoReply
		}
		return err
	}
	var pr struct {
		StopReason string `json:"stopReason"`
	}
	_ = json.Unmarshal(raw, &pr)
	resMu.Lock()
	res.StopReason = pr.StopReason
	resMu.Unlock()
	if opts.OnPromptOK != nil {
		opts.OnPromptOK()
	}
	return nil
}

type acpClient struct {
	w        io.Writer
	wmu      sync.Mutex
	next     atomic.Uint64
	mu       sync.Mutex
	pending  map[string]chan acpEnvelope
	done     chan struct{}
	readErr  error
	onNotify func(method string, params json.RawMessage)
}

func newACPClient(w io.Writer) *acpClient {
	return &acpClient{
		w:       w,
		pending: make(map[string]chan acpEnvelope),
		done:    make(chan struct{}),
	}
}

func (c *acpClient) call(method string, params any) (json.RawMessage, error) {
	id := c.next.Add(1)
	idRaw, _ := json.Marshal(id)
	ch := make(chan acpEnvelope, 1)
	c.mu.Lock()
	if c.pending == nil {
		c.mu.Unlock()
		return nil, errWakeACPClosed
	}
	c.pending[string(idRaw)] = ch
	c.mu.Unlock()
	if err := c.write(acpEnvelope{
		JSONRPC: "2.0",
		ID:      idRaw,
		Method:  method,
		Params:  mustJSON(params),
	}); err != nil {
		return nil, err
	}
	select {
	case env, ok := <-ch:
		if !ok {
			return nil, errWakeACPClosed
		}
		if env.Error != nil {
			return nil, env.Error
		}
		return env.Result, nil
	case <-c.done:
		c.mu.Lock()
		err := c.readErr
		c.mu.Unlock()
		if err == nil {
			err = errWakeACPClosed
		}
		return nil, err
	}
}

func (c *acpClient) write(env acpEnvelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.w.Write(append(b, '\n'))
	return err
}

func (c *acpClient) readLoop(r io.Reader) {
	defer close(c.done)
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			c.handleLine(line)
		}
		if err != nil {
			c.mu.Lock()
			if c.readErr == nil {
				if errors.Is(err, io.EOF) {
					c.readErr = errWakeACPClosed
				} else {
					c.readErr = err
				}
			}
			for _, ch := range c.pending {
				close(ch)
			}
			c.pending = nil
			c.mu.Unlock()
			return
		}
	}
}

func (c *acpClient) handleLine(line []byte) {
	line = trimACPLine(line)
	if len(line) == 0 {
		return
	}
	var env acpEnvelope
	if err := json.Unmarshal(line, &env); err != nil {
		return
	}
	if env.Method != "" && len(env.ID) > 0 {
		c.replyAgent(env)
		return
	}
	if env.Method != "" {
		if c.onNotify != nil {
			c.onNotify(env.Method, env.Params)
		}
		return
	}
	if len(env.ID) == 0 {
		return
	}
	c.mu.Lock()
	ch := c.pending[string(env.ID)]
	delete(c.pending, string(env.ID))
	c.mu.Unlock()
	if ch == nil {
		return
	}
	ch <- env
}

func (c *acpClient) replyAgent(env acpEnvelope) {
	if env.Method != "session/request_permission" {
		_ = c.write(acpEnvelope{
			JSONRPC: "2.0",
			ID:      env.ID,
			Error:   &acpRPCError{Code: -32601, Message: "method not supported"},
		})
		return
	}
	var p struct {
		Options []struct {
			OptionID string `json:"optionId"`
			Kind     string `json:"kind"`
		} `json:"options"`
	}
	_ = json.Unmarshal(env.Params, &p)
	opt := ""
	for _, o := range p.Options {
		if o.Kind == "allow_once" || o.Kind == "allow_always" {
			opt = o.OptionID
			break
		}
	}
	if opt == "" && len(p.Options) > 0 {
		opt = p.Options[0].OptionID
	}
	var result any
	if opt == "" {
		result = map[string]any{"outcome": map[string]any{"outcome": "cancelled"}}
	} else {
		result = map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": opt}}
	}
	_ = c.write(acpEnvelope{
		JSONRPC: "2.0",
		ID:      env.ID,
		Result:  mustJSON(result),
	})
}

func (d *Daemon) wakeMCPHTTP() []any {
	if d == nil || d.cfg == nil || d.cfg.APIAddr == "" {
		return nil
	}
	return []any{map[string]any{
		"type":    "http",
		"name":    "a2al",
		"url":     "http://" + d.cfg.APIAddr + "/mcp/",
		"headers": []any{},
	}}
}

func (d *Daemon) wakeMCPStdio() []any {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return nil
	}
	return []any{map[string]any{
		"name":    "a2al",
		"command": exe,
		"args":    []string{"--mcp-stdio"},
		"env":     []any{},
	}}
}

func resolveWakeCwd(cwd string) (string, error) {
	cwd = filepath.Clean(cwd)
	if cwd == "." || cwd == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			wd, werr := os.Getwd()
			if werr != nil {
				return "", errWakeCwd
			}
			home = wd
		}
		cwd = home
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", errWakeCwd
	}
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() {
		return "", errWakeCwd
	}
	return abs, nil
}

func acpLooksLikeAuth(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errWakeACPAuth) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "auth") || strings.Contains(s, "login") || strings.Contains(s, "unauthor")
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

func trimACPLine(line []byte) []byte {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}

func acpExtractSpend(params json.RawMessage) (int64, string) {
	var v any
	if err := json.Unmarshal(params, &v); err != nil {
		return 0, ""
	}
	return acpWalkSpend(v)
}

func acpWalkSpend(v any) (int64, string) {
	var best int64
	var model string
	var walk func(any)
	jsonNum := func(x any) int64 {
		switch n := x.(type) {
		case float64:
			if n > 0 {
				return int64(n)
			}
		case json.Number:
			i, _ := n.Int64()
			if i > 0 {
				return i
			}
		case int:
			if n > 0 {
				return int64(n)
			}
		case int64:
			if n > 0 {
				return n
			}
		}
		return 0
	}
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			if s, _ := t["model"].(string); s != "" {
				model = s
			}
			if s, _ := t["modelTag"].(string); s != "" {
				model = s
			}
			if tc, ok := t["token_count"].(map[string]any); ok {
				if n := jsonNum(tc["total"]); n > best {
					best = n
				}
				if n := jsonNum(tc["used"]); n > best {
					best = n
				}
			}
			if u, ok := t["usage"].(map[string]any); ok {
				if n := jsonNum(u["used"]); n > best {
					best = n
				}
				if n := jsonNum(u["total"]); n > best {
					best = n
				}
				if n := jsonNum(u["total_tokens"]); n > best {
					best = n
				}
			}
			if n := jsonNum(t["total_tokens"]); n > best {
				best = n
			}
			if n := jsonNum(t["used_tokens"]); n > best {
				best = n
			}
			switch used := t["used"].(type) {
			case float64, json.Number, int, int64:
				if n := jsonNum(used); n > best {
					best = n
				}
			case map[string]any:
				if n := jsonNum(used["total"]); n > 0 {
					if n > best {
						best = n
					}
				} else {
					sum := jsonNum(used["input"]) + jsonNum(used["output"])
					if sum > best {
						best = sum
					}
				}
			}
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(v)
	return best, model
}
