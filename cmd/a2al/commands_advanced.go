// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func cmdAgents(c *Client, g globalOpts, args []string) {
	if len(args) == 0 {
		var out struct {
			Agents []map[string]any `json:"agents"`
		}
		if _, _, err := c.DoRequest(http.MethodGet, "/agents", nil, &out); err != nil {
			fatal(err)
		}
		if g.JSON {
			printJSON(true, out)
			return
		}
		if g.Quiet {
			for _, a := range out.Agents {
				fmt.Println(a["aid"])
			}
			return
		}
		for _, a := range out.Agents {
			b, _ := json.MarshalIndent(a, "", "  ")
			fmt.Println(string(b))
			fmt.Println()
		}
		return
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "new":
		cmdAgentsNew(c, g, rest, false)
	case "new-eth":
		cmdAgentsNew(c, g, rest, true)
	case "get":
		if len(rest) != 1 {
			fatalf("usage: a2al agents get <local-aid>")
		}
		var m map[string]any
		if _, _, err := c.DoRequest(http.MethodGet, "/agents/"+url.PathEscape(rest[0]), nil, &m); err != nil {
			fatal(err)
		}
		if g.JSON || g.Quiet {
			printJSON(true, m)
			return
		}
		b, _ := json.MarshalIndent(m, "", "  ")
		fmt.Println(string(b))
	case "update":
		cmdAgentsUpdate(c, g, rest)
	case "del", "delete":
		if len(rest) != 1 {
			fatalf("usage: a2al agents del <local-aid>")
		}
		if _, _, err := c.DoRequest(http.MethodDelete, "/agents/"+url.PathEscape(rest[0]), map[string]any{}, new(map[string]any)); err != nil {
			fatal(err)
		}
		if g.JSON {
			printJSON(true, map[string]any{"ok": true})
		} else if !g.Quiet {
			fmt.Println("deleted", rest[0])
		}
	case "publish":
		if len(rest) != 1 {
			fatalf("usage: a2al agents publish <local-aid>")
		}
		var out map[string]any
		if _, _, err := c.DoRequest(http.MethodPost, "/agents/"+url.PathEscape(rest[0])+"/publish", map[string]any{}, &out); err != nil {
			fatal(err)
		}
		if g.JSON {
			printJSON(true, out)
			return
		}
		if !g.Quiet {
			fmt.Printf("published %s\n", rest[0])
		}
	case "heartbeat":
		if len(rest) != 1 {
			fatalf("usage: a2al agents heartbeat <local-aid>")
		}
		if _, _, err := c.DoRequest(http.MethodPost, "/agents/"+url.PathEscape(rest[0])+"/heartbeat", map[string]any{}, new(map[string]any)); err != nil {
			fatal(err)
		}
		if g.JSON {
			printJSON(true, map[string]any{"ok": true})
		}
	case "export":
		cmdAgentsExport(g, rest)
	case "import":
		cmdAgentsImport(c, g, rest)
	case "topic":
		cmdAgentsTopic(c, g, rest)
	default:
		fatalf("unknown agents subcommand: %s", sub)
	}
}

func cmdAgentsNew(c *Client, g globalOpts, args []string, eth bool) {
	// Thin wrapper: same flags as register without command name.
	if eth {
		registerEthereum(c, g, flagString(args, "--service-tcp"), flagString(args, "--eth-key"), flagBool(args, "--no-publish"), "")
		return
	}
	registerEd25519(c, g, flagString(args, "--service-tcp"), flagString(args, "--save-master"), flagBool(args, "--no-publish"))
}

func flagString(args []string, name string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], name+"=") {
			return strings.TrimPrefix(args[i], name+"=")
		}
	}
	return ""
}

func flagBool(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func cmdAgentsUpdate(c *Client, g globalOpts, args []string) {
	if len(args) < 1 {
		fatalf("usage: a2al agents update <local-aid> [--service-tcp <addr>]")
	}
	aid := args[0]
	tcp := flagString(args[1:], "--service-tcp")
	id, err := loadAgentIdentity(aid)
	if err != nil {
		fatal(fmt.Errorf("load identity: %w", err))
	}
	body := map[string]any{
		"operational_private_key_hex": id.OperationalPrivateKeyHex,
		"service_tcp":                 tcp,
	}
	if _, _, err := c.DoRequest(http.MethodPatch, "/agents/"+aid, body, new(map[string]any)); err != nil {
		fatal(err)
	}
	id.ServiceTCP = tcp
	_ = saveAgentIdentity(id)
	if g.JSON {
		printJSON(true, map[string]any{"ok": true})
	} else if !g.Quiet {
		fmt.Println("updated", aid)
	}
}

func cmdAgentsExport(g globalOpts, args []string) {
	if len(args) < 1 {
		fatalf("usage: a2al agents export <local-aid> [-o file]")
	}
	aid := args[0]
	outPath := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "-o" && i+1 < len(args) {
			i++
			outPath = args[i]
		}
	}
	id, err := loadAgentIdentity(aid)
	if err != nil {
		fatal(err)
	}
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		fatal(err)
	}
	if outPath != "" {
		if err := os.WriteFile(outPath, b, 0o600); err != nil {
			fatal(err)
		}
		if !g.Quiet && !g.JSON {
			fmt.Println("exported to", outPath)
		}
		return
	}
	if g.JSON {
		printJSON(true, id)
		return
	}
	fmt.Println(string(b))
}

func cmdAgentsImport(c *Client, g globalOpts, args []string) {
	if len(args) != 1 {
		fatalf("usage: a2al agents import <file>")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		fatal(err)
	}
	var id agentIdentityFile
	if err := json.Unmarshal(b, &id); err != nil {
		fatal(err)
	}
	body := map[string]any{
		"operational_private_key_hex": id.OperationalPrivateKeyHex,
		"delegation_proof_hex":        id.DelegationProofHex,
		"service_tcp":                 id.ServiceTCP,
	}
	var reg struct {
		AID string `json:"aid"`
	}
	if _, _, err := c.DoRequest(http.MethodPost, "/agents", body, &reg); err != nil {
		fatal(err)
	}
	if reg.AID != "" {
		id.AID = reg.AID
	}
	if err := saveAgentIdentity(&id); err != nil {
		fatal(err)
	}
	if g.JSON {
		printJSON(true, map[string]any{"ok": true, "aid": id.AID})
	} else if !g.Quiet {
		fmt.Println("imported", id.AID)
	}
}

func cmdAgentsTopic(c *Client, g globalOpts, args []string) {
	if len(args) < 1 {
		fatalf("usage: a2al agents topic add|del …")
	}
	switch args[0] {
	case "add":
		if len(args) < 3 {
			fatalf("usage: a2al agents topic add <aid> <service> [<service>…] [flags]  (e.g. lang.translate)")
		}
		aid := args[1]
		rest := args[2:]
		var topics []string
		for len(rest) > 0 && !strings.HasPrefix(rest[0], "--") {
			topics = append(topics, rest[0])
			rest = rest[1:]
		}
		if len(topics) == 0 {
			fatalf("no service names given")
		}
		var name, brief, u string
		var ttl uint32 = 3600
		var protos, tags []string
		for i := 0; i < len(rest); i++ {
			a := rest[i]
			switch {
			case a == "--name" && i+1 < len(rest):
				i++
				name = rest[i]
			case a == "--brief" && i+1 < len(rest):
				i++
				brief = rest[i]
			case a == "--url" && i+1 < len(rest):
				i++
				u = rest[i]
			case a == "--ttl" && i+1 < len(rest):
				i++
				_, _ = fmt.Sscanf(rest[i], "%d", &ttl)
			case a == "--protocol" && i+1 < len(rest):
				i++
				protos = append(protos, rest[i])
			case a == "--tag" && i+1 < len(rest):
				i++
				tags = append(tags, rest[i])
			default:
				fatalf("unknown flag: %s", a)
			}
		}
		meta := map[string]any{}
		if u != "" {
			meta["url"] = u
		}
		body := map[string]any{
			"services": topics, "name": name, "brief": brief,
			"protocols": protos, "tags": tags, "ttl": ttl,
		}
		if len(meta) > 0 {
			body["meta"] = meta
		}
		if _, _, err := c.DoRequest(http.MethodPost, "/agents/"+url.PathEscape(aid)+"/services", body, new(map[string]any)); err != nil {
			fatal(err)
		}
		if g.JSON {
			printJSON(true, map[string]any{"ok": true})
		}
	case "del":
		if len(args) != 3 {
			fatalf("usage: a2al agents topic del <aid> <service>")
		}
		p := "/agents/" + url.PathEscape(args[1]) + "/services/" + url.PathEscape(args[2])
		if _, _, err := c.DoRequest(http.MethodDelete, p, map[string]any{}, new(map[string]any)); err != nil {
			fatal(err)
		}
		if g.JSON {
			printJSON(true, map[string]any{"ok": true})
		}
	default:
		fatalf("usage: a2al agents topic add|del …")
	}
}

func cmdIdentity(c *Client, g globalOpts, args []string) {
	if len(args) < 1 {
		fatalf("usage: a2al identity new | new-eth")
	}
	switch args[0] {
	case "new":
		var gen map[string]any
		if _, _, err := c.DoRequest(http.MethodPost, "/identity/generate", map[string]any{}, &gen); err != nil {
			fatal(err)
		}
		printJSON(true, gen)
	case "new-eth":
		var out map[string]any
		if _, _, err := c.DoRequest(http.MethodPost, "/agents/generate", map[string]any{"chain": "ethereum"}, &out); err != nil {
			fatal(err)
		}
		printJSON(true, out)
	default:
		fatalf("unknown identity subcommand")
	}
}

func cmdResolve(c *Client, g globalOpts, args []string) {
	if len(args) != 1 {
		fatalf("usage: a2al resolve <remote-aid>")
	}
	var m map[string]any
	if _, _, err := c.DoRequest(http.MethodPost, "/resolve/"+args[0], map[string]any{}, &m); err != nil {
		fatal(err)
	}
	if g.JSON || g.Quiet {
		printJSON(!g.Quiet, m)
		return
	}
	if eps, ok := m["endpoints"].([]any); ok {
		var ss []string
		for _, x := range eps {
			if s, ok := x.(string); ok {
				ss = append(ss, s)
			}
		}
		fmt.Printf("Endpoints:  %s\n", strings.Join(ss, ", "))
	}
	if nt, ok := m["nat_type"]; ok && nt != nil {
		fmt.Printf("NAT:        %v\n", nt)
	}
	if seq, ok := m["seq"].(float64); ok {
		fmt.Printf("Seq:        %.0f\n", seq)
	}
}

func cmdConnect(c *Client, g globalOpts, args []string) {
	if len(args) < 1 {
		fatalf("usage: a2al connect <remote-aid> [--local-aid …]")
	}
	remote := args[0]
	la := flagString(args[1:], "--local-aid")
	body := map[string]any{}
	if la != "" {
		body["local_aid"] = la
	}
	if !g.Quiet && !g.JSON {
		label := resolveLocalIdentityLabel(c, la)
		fmt.Fprintf(os.Stderr, "Connecting as %s → %s\n", label, shortAID(remote))
	}
	var tun map[string]string
	if _, _, err := c.DoRequest(http.MethodPost, "/connect/"+remote, body, &tun); err != nil {
		fatal(err)
	}
	addr := tun["tunnel"]
	if g.JSON {
		printJSON(true, tun)
		return
	}
	fmt.Println(addr)
}

func cmdNote(c *Client, g globalOpts, args []string) {
	if len(args) < 1 {
		fatalf("usage: a2al note send|poll …")
	}
	switch args[0] {
	case "send":
		if len(args) < 4 {
			fatalf("usage: a2al note send <local-aid> <recipient-aid> <body-base64> [--msg-type N]")
		}
		local, recip, b64 := args[1], args[2], args[3]
		mt := uint8(1)
		for i := 4; i < len(args); i++ {
			if args[i] == "--msg-type" && i+1 < len(args) {
				i++
				var n int
				if _, err := fmt.Sscanf(args[i], "%d", &n); err != nil {
					fatalf("invalid --msg-type: %v", err)
				}
				mt = uint8(n)
			}
		}
		body := map[string]any{"recipient": recip, "msg_type": mt, "body_base64": b64}
		if _, _, err := c.DoRequest(http.MethodPost, "/agents/"+local+"/mailbox/send", body, new(map[string]any)); err != nil {
			fatal(err)
		}
		if g.JSON {
			printJSON(true, map[string]any{"ok": true})
		}
	case "poll":
		if len(args) != 2 {
			fatalf("usage: a2al note poll <local-aid>")
		}
		var out map[string]any
		if _, _, err := c.DoRequest(http.MethodPost, "/agents/"+args[1]+"/mailbox/poll", map[string]any{}, &out); err != nil {
			fatal(err)
		}
		printJSON(true, out)
	default:
		fatalf("unknown note subcommand")
	}
}

func cmdConfig(c *Client, g globalOpts, args []string) {
	if len(args) < 1 {
		fatalf("usage: a2al config get [key] | set <key> <value>")
	}
	switch args[0] {
	case "get":
		var m map[string]any
		if _, _, err := c.DoRequest(http.MethodGet, "/config", nil, &m); err != nil {
			fatal(err)
		}
		if len(args) == 1 {
			printJSON(true, m)
			return
		}
		k := args[1]
		v, ok := m[k]
		if !ok {
			fatalf("unknown key: %s", k)
		}
		fmt.Println(v)
	case "set":
		if len(args) != 3 {
			fatalf("usage: a2al config set <key> <value>")
		}
		key, val := args[1], args[2]
		patch := map[string]any{key: jsonRawValue(val)}
		var out map[string]any
		if _, _, err := c.DoRequest(http.MethodPatch, "/config", patch, &out); err != nil {
			fatal(err)
		}
		printJSON(true, out)
	default:
		fatalf("unknown config subcommand")
	}
}

// jsonRawValue parses value as JSON if it looks like literal, else string.
func jsonRawValue(val string) any {
	val = strings.TrimSpace(val)
	switch val {
	case "true":
		return true
	case "false":
		return false
	}
	if len(val) > 0 && (val[0] == '{' || val[0] == '[') {
		var raw json.RawMessage
		if json.Unmarshal([]byte(val), &raw) == nil {
			return raw
		}
	}
	if n, err := parseInt(val); err == nil {
		return n
	}
	return val
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func cmdHelp() {
	fmt.Print(`a2al — A2AL daemon CLI

Usage:
  a2al [global flags] <command> [args...]

Global flags:
  --api <addr>    Daemon base URL (default http://127.0.0.1:2121, env A2AL_API)
  --token <tok>   Bearer token (env A2AL_TOKEN)
  --json          JSON output
  --quiet         Minimal output

Commands:
  status, register, publish, unpublish, search, info, get, post
  agents, identity, resolve, connect, note, config, help

Examples:
  a2al status
  a2al register
  a2al register --ethereum --eth-key 0x...
  a2al publish lang.translate --from http://localhost:9000 -y
  a2al search lang.translate
  a2al info <aid>
  a2al get <aid> /.well-known/agent.json
`)
}
