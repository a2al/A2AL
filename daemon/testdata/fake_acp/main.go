// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// fake_acp is a tiny ACP agent for wake driver tests.
package main

import (
	"bufio"
	"encoding/json"
	"os"
)

type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type dump struct {
	Methods []string `json:"methods"`
	CWD     string   `json:"cwd"`
	MCP     []any    `json:"mcpServers"`
	Prompt  string   `json:"prompt"`
	PermOK  bool     `json:"permOk"`
}

func main() {
	mode := os.Getenv("A2AL_ACP_MODE")
	if mode == "" {
		mode = "ok"
	}
	d := &dump{}
	br := bufio.NewReader(os.Stdin)
	var promptID json.RawMessage
	waitingPerm := false
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			handle(mode, d, trim(line), &promptID, &waitingPerm)
		}
		if err != nil {
			writeDump(d)
			return
		}
	}
}

func handle(mode string, d *dump, line []byte, promptID *json.RawMessage, waitingPerm *bool) {
	var env envelope
	if json.Unmarshal(line, &env) != nil {
		return
	}
	if *waitingPerm && len(env.ID) > 0 && env.Method == "" {
		d.PermOK = true
		*waitingPerm = false
		writeEnv(envelope{
			JSONRPC: "2.0",
			ID:      *promptID,
			Result:  raw(`{"stopReason":"end_turn"}`),
		})
		return
	}
	if env.Method == "" {
		return
	}
	d.Methods = append(d.Methods, env.Method)
	switch env.Method {
	case "initialize":
		httpCap := "false"
		if mode == "http" {
			httpCap = "true"
		}
		loadSess := "false"
		if mode == "load" || mode == "loadfail" || mode == "usage" || mode == "cap" {
			loadSess = "true"
		}
		writeEnv(envelope{
			JSONRPC: "2.0",
			ID:      env.ID,
			Result:  raw(`{"protocolVersion":1,"agentCapabilities":{"loadSession":` + loadSess + `,"mcpCapabilities":{"http":` + httpCap + `}}}`),
		})
	case "session/load":
		if mode == "loadfail" {
			writeEnv(envelope{
				JSONRPC: "2.0",
				ID:      env.ID,
				Error:   &rpcError{Code: -32000, Message: "unknown session"},
			})
			return
		}
		var p struct {
			SessionID string `json:"sessionId"`
			CWD       string `json:"cwd"`
		}
		_ = json.Unmarshal(env.Params, &p)
		if p.CWD != "" {
			d.CWD = p.CWD
		}
		writeEnv(envelope{
			JSONRPC: "2.0",
			ID:      env.ID,
			Result:  raw(`{"sessionId":"` + p.SessionID + `"}`),
		})
	case "session/cancel":
		writeEnv(envelope{JSONRPC: "2.0", ID: env.ID, Result: raw(`{}`)})
	case "session/new":
		if mode == "auth" {
			writeEnv(envelope{
				JSONRPC: "2.0",
				ID:      env.ID,
				Error:   &rpcError{Code: -32000, Message: "login required"},
			})
			return
		}
		var p struct {
			CWD string `json:"cwd"`
			MCP []any  `json:"mcpServers"`
		}
		_ = json.Unmarshal(env.Params, &p)
		d.CWD = p.CWD
		d.MCP = p.MCP
		writeEnv(envelope{
			JSONRPC: "2.0",
			ID:      env.ID,
			Result:  raw(`{"sessionId":"sess-1"}`),
		})
	case "session/prompt":
		var p struct {
			Prompt []struct {
				Text string `json:"text"`
			} `json:"prompt"`
		}
		_ = json.Unmarshal(env.Params, &p)
		if len(p.Prompt) > 0 {
			d.Prompt = p.Prompt[0].Text
		}
		writeEnv(envelope{
			JSONRPC: "2.0",
			Method:  "session/update",
			Params:  raw(`{"sessionId":"sess-1","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"ok"}}}`),
		})
		if mode == "perm" {
			*promptID = append(json.RawMessage(nil), env.ID...)
			*waitingPerm = true
			writeEnv(envelope{
				JSONRPC: "2.0",
				ID:      raw("99001"),
				Method:  "session/request_permission",
				Params:  raw(`{"sessionId":"sess-1","options":[{"optionId":"allow-once","name":"Allow once","kind":"allow_once"}]}`),
			})
			return
		}
		writeEnv(envelope{
			JSONRPC: "2.0",
			ID:      env.ID,
			Result:  raw(`{"stopReason":"end_turn"}`),
		})
	default:
		writeEnv(envelope{
			JSONRPC: "2.0",
			ID:      env.ID,
			Error:   &rpcError{Code: -32601, Message: "unknown method"},
		})
	}
}

func writeEnv(env envelope) {
	b, err := json.Marshal(env)
	if err != nil {
		return
	}
	_, _ = os.Stdout.Write(append(b, '\n'))
}

func writeDump(d *dump) {
	path := os.Getenv("A2AL_ACP_DUMP")
	if path == "" {
		return
	}
	b, err := json.Marshal(d)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0o600)
}

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func trim(line []byte) []byte {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}
