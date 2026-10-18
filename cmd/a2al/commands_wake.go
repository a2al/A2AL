// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const wakeUsage = `usage: a2al wake bind --cmd <path> [--via exec|acp] [--cwd <dir>] [--session-cwd <dir>] [--cap N] [--arg <arg>]... [--aid <local-aid>]
       a2al wake status [--aid <local-aid>]
       a2al wake test [--aid <local-aid>]
       a2al wake handle [--aid <local-aid>] [--set <handle>|--clear]
       a2al wake unbind [--aid <local-aid>]
  Bind a local command the daemon runs when this AID gets a notification.
  --via exec (default): run the command; JSON coordinates on stdin.
  --via acp: ACP JSON-RPC over stdio (initialize, session/new|load, session/prompt).
  --cwd is the process directory (must exist). --session-cwd is ACP session cwd (not checked here).
  --cap is the ACP per-turn token cap (soft: session/cancel, no process kill); omitted uses config wake.acp_cap.
  Repeat --arg for each argument. Use {{handle}} as an argv token to splice the stored handle.`

func cmdWake(c *Client, g globalOpts, args []string) {
	if len(args) == 0 || wakeArgsWantHelp(args) {
		fmt.Print(wakeUsage + "\n")
		return
	}
	switch args[0] {
	case "bind":
		cmdWakeBind(c, g, args[1:])
	case "status":
		cmdWakeStatus(c, g, args[1:])
	case "test":
		cmdWakeTest(c, g, args[1:])
	case "handle":
		cmdWakeHandle(c, g, args[1:])
	case "unbind":
		cmdWakeUnbind(c, g, args[1:])
	default:
		fatalf("unknown wake subcommand %q\n%s", args[0], wakeUsage)
	}
}

func wakeArgsWantHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			return true
		}
	}
	return false
}

func cmdWakeBind(c *Client, g globalOpts, args []string) {
	via := flagString(args, "--via")
	cmd := flagString(args, "--cmd")
	cwd := flagString(args, "--cwd")
	sessionCwd := flagString(args, "--session-cwd")
	capStr := flagString(args, "--cap")
	if strings.EqualFold(via, "codex") {
		via = "exec"
		if cmd == "" {
			cmd = "codex"
		}
	}
	if via == "" {
		via = "exec"
	}
	via = strings.ToLower(strings.TrimSpace(via))
	if via != "exec" && via != "acp" {
		fatalf("via must be exec or acp")
	}
	if cmd == "" {
		fatalf("%s", wakeUsage)
	}
	aid, err := pickWakeAID(c, flagString(args, "--aid"))
	if err != nil {
		fatal(err)
	}
	body := map[string]any{"via": via, "cmd": cmd, "args": flagRepeat(args, "--arg")}
	if cwd != "" {
		body["cwd"] = cwd
	}
	if sessionCwd != "" {
		body["session_cwd"] = sessionCwd
	}
	if capStr != "" {
		n, err := strconv.ParseInt(capStr, 10, 64)
		if err != nil || n < 0 {
			fatalf("cap must be a non-negative integer")
		}
		body["cap"] = n
	}
	var out map[string]any
	if _, _, err := c.DoRequest(http.MethodPut, "/agents/"+url.PathEscape(aid)+"/wake", body, &out); err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, out)
		return
	}
	fmt.Printf("wake bound %s via=%v → %v %v\n", aid, out["via"], out["cmd"], out["args"])
}

func cmdWakeStatus(c *Client, g globalOpts, args []string) {
	aid, err := pickWakeAID(c, flagString(args, "--aid"))
	if err != nil {
		fatal(err)
	}
	var out map[string]any
	if _, _, err := c.DoRequest(http.MethodGet, "/agents/"+url.PathEscape(aid)+"/wake", nil, &out); err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, out)
		return
	}
	if bound, _ := out["bound"].(bool); !bound {
		fmt.Printf("%s: not bound\n", aid)
		return
	}
	fmt.Printf("%s: via=%v %v %v\n", aid, out["via"], out["cmd"], out["args"])
	if cwd, ok := out["cwd"]; ok && cwd != "" {
		fmt.Printf("cwd: %v\n", cwd)
	}
	if sc, ok := out["session_cwd"]; ok && sc != "" {
		fmt.Printf("session_cwd: %v\n", sc)
	}
	if h, ok := out["handle"]; ok && h != "" {
		fmt.Printf("handle: %v\n", h)
	}
	if capn, ok := out["cap"]; ok {
		fmt.Printf("cap: %v\n", capn)
	}
	if last, ok := out["last"].(map[string]any); ok {
		fmt.Printf("last: ok=%v in_flight=%v step=%v %v\n", last["ok"], last["in_flight"], last["step"], last["error"])
		if pid, ok := last["pid"]; ok {
			fmt.Printf("pid: %v\n", pid)
		}
		if sid, ok := last["session_id"]; ok && sid != "" {
			fmt.Printf("session_id: %v\n", sid)
		}
		if cost, ok := last["cost"].(map[string]any); ok {
			fmt.Printf("cost: spend=%v cap=%v unit=%v\n", cost["spend"], cost["cap"], cost["spend_unit"])
		}
	}
}

func cmdWakeTest(c *Client, g globalOpts, args []string) {
	aid, err := pickWakeAID(c, flagString(args, "--aid"))
	if err != nil {
		fatal(err)
	}
	var out map[string]any
	if _, _, err := c.DoRequest(http.MethodPost, "/agents/"+url.PathEscape(aid)+"/wake/test", map[string]any{}, &out); err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, out)
		return
	}
	fmt.Println("queued")
}

func cmdWakeHandle(c *Client, g globalOpts, args []string) {
	aid, err := pickWakeAID(c, flagString(args, "--aid"))
	if err != nil {
		fatal(err)
	}
	clear := flagBool(args, "--clear")
	set := flagString(args, "--set")
	path := "/agents/" + url.PathEscape(aid) + "/wake/handle"
	var out map[string]any
	switch {
	case clear:
		if _, _, err := c.DoRequest(http.MethodDelete, path, map[string]any{}, &out); err != nil {
			fatal(err)
		}
	case set != "":
		if _, _, err := c.DoRequest(http.MethodPut, path, map[string]any{"handle": set}, &out); err != nil {
			fatal(err)
		}
	default:
		if _, _, err := c.DoRequest(http.MethodGet, path, nil, &out); err != nil {
			fatal(err)
		}
	}
	if g.JSON {
		printJSON(true, out)
		return
	}
	fmt.Printf("handle: %v\n", out["handle"])
}

func cmdWakeUnbind(c *Client, g globalOpts, args []string) {
	aid, err := pickWakeAID(c, flagString(args, "--aid"))
	if err != nil {
		fatal(err)
	}
	var out map[string]any
	if _, _, err := c.DoRequest(http.MethodDelete, "/agents/"+url.PathEscape(aid)+"/wake", map[string]any{}, &out); err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, out)
		return
	}
	fmt.Printf("wake unbound %s\n", aid)
}

func pickWakeAID(c *Client, flag string) (string, error) {
	aids, err := listAgentAIDs(c)
	if err != nil {
		return "", err
	}
	return pickInboundAID(aids, flag)
}

func flagRepeat(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			out = append(out, args[i+1])
			i++
			continue
		}
		if strings.HasPrefix(args[i], name+"=") {
			out = append(out, strings.TrimPrefix(args[i], name+"="))
		}
	}
	return out
}
