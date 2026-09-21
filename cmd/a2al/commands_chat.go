// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"
	"strconv"
)

func cmdChat(c *Client, g globalOpts, args []string) {
	if len(args) == 0 {
		chatHelp()
		os.Exit(1)
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "request":
		chatRequest(c, g, rest)
	case "accept":
		chatAccept(c, g, rest)
	case "refuse":
		chatRefuse(c, g, rest)
	case "remove":
		chatRemove(c, g, rest)
	case "block":
		chatBlock(c, g, rest)
	case "send":
		chatSend(c, g, rest)
	case "read":
		chatRead(c, g, rest)
	case "mark-read":
		chatMarkRead(c, g, rest)
	case "contacts":
		chatContacts(c, g, rest)
	default:
		chatHelp()
		os.Exit(1)
	}
}

func chatHelp() {
	fmt.Print(`a2al chat — one-to-one messages between AIDs

Usage:
  a2al chat request  --aid <aid> --peer <aid> [--note <text>]
  a2al chat accept   --aid <aid> --peer <aid>
  a2al chat refuse   --aid <aid> --peer <aid>
  a2al chat remove   --aid <aid> --peer <aid>
  a2al chat block    --aid <aid> --peer <aid>
  a2al chat send     --aid <aid> --peer <aid> [--text <text>] [--file <path>]
  a2al chat read      --aid <aid> --peer <aid> [--after-seq <n>] [--limit <n>]
  a2al chat mark-read --aid <aid> --peer <aid> [--after-seq <n>]
  a2al chat contacts  --aid <aid>

Global flags: --api <url>  --token <tok>  --json  --quiet
`)
}

func chatRequest(c *Client, g globalOpts, args []string) {
	var aid, peer, note string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--peer": &peer, "--note": &note})
	if aid == "" || peer == "" {
		fatalf("usage: a2al chat request --aid <aid> --peer <aid> [--note <text>]")
	}
	argsMap := map[string]any{"aid": aid, "peer": peer}
	if note != "" {
		argsMap["note"] = note
	}
	res := callMCP(c, "chat_request", argsMap)
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("state: %v\n", res["state"])
}

func chatAccept(c *Client, g globalOpts, args []string) {
	var aid, peer string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--peer": &peer})
	if aid == "" || peer == "" {
		fatalf("usage: a2al chat accept --aid <aid> --peer <aid>")
	}
	res := callMCP(c, "chat_accept", map[string]any{"aid": aid, "peer": peer})
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("state: %v\n", res["state"])
}

func chatRefuse(c *Client, g globalOpts, args []string) {
	var aid, peer string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--peer": &peer})
	if aid == "" || peer == "" {
		fatalf("usage: a2al chat refuse --aid <aid> --peer <aid>")
	}
	res := callMCP(c, "chat_refuse", map[string]any{"aid": aid, "peer": peer})
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Println("ok")
}

func chatRemove(c *Client, g globalOpts, args []string) {
	var aid, peer string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--peer": &peer})
	if aid == "" || peer == "" {
		fatalf("usage: a2al chat remove --aid <aid> --peer <aid>")
	}
	res := callMCP(c, "chat_remove", map[string]any{"aid": aid, "peer": peer})
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Println("ok")
}

func chatBlock(c *Client, g globalOpts, args []string) {
	var aid, peer string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--peer": &peer})
	if aid == "" || peer == "" {
		fatalf("usage: a2al chat block --aid <aid> --peer <aid>")
	}
	res := callMCP(c, "chat_block", map[string]any{"aid": aid, "peer": peer})
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("state: %v\n", res["state"])
}

func chatSend(c *Client, g globalOpts, args []string) {
	var aid, peer, text, file string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--peer": &peer, "--text": &text, "--file": &file})
	if aid == "" || peer == "" {
		fatalf("usage: a2al chat send --aid <aid> --peer <aid> [--text <text>] [--file <path>]")
	}
	argsMap := map[string]any{"aid": aid, "peer": peer}
	if text != "" {
		argsMap["text"] = text
	}
	if file != "" {
		argsMap["path"] = file
	}
	res := callMCP(c, "chat_send", argsMap)
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("seq: %v  status: %v\n", res["seq"], res["status"])
}

func chatRead(c *Client, g globalOpts, args []string) {
	var aid, peer, after, limit string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--peer": &peer, "--after-seq": &after, "--limit": &limit})
	if aid == "" || peer == "" {
		fatalf("usage: a2al chat read --aid <aid> --peer <aid> [--after-seq <n>] [--limit <n>]")
	}
	argsMap := map[string]any{"aid": aid, "peer": peer}
	if after != "" {
		n, err := strconv.ParseUint(after, 10, 64)
		if err != nil {
			fatalf("after-seq: %v", err)
		}
		argsMap["after_seq"] = n
	}
	if limit != "" {
		n, err := strconv.Atoi(limit)
		if err != nil {
			fatalf("limit: %v", err)
		}
		argsMap["limit"] = n
	}
	res := callMCP(c, "chat_read", argsMap)
	if g.JSON {
		printJSON(true, res)
		return
	}
	entries, _ := res["entries"].([]any)
	for _, raw := range entries {
		e, _ := raw.(map[string]any)
		fmt.Printf("%v %v %v %v\n", e["idx"], e["dir"], e["status"], e["body"])
	}
}

func chatMarkRead(c *Client, g globalOpts, args []string) {
	var aid, peer, after string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--peer": &peer, "--after-seq": &after})
	if aid == "" || peer == "" {
		fatalf("usage: a2al chat mark-read --aid <aid> --peer <aid> [--after-seq <n>]")
	}
	argsMap := map[string]any{"aid": aid, "peer": peer}
	if after != "" {
		n, err := strconv.ParseUint(after, 10, 64)
		if err != nil {
			fatalf("after-seq: %v", err)
		}
		argsMap["scanned_to"] = n
	}
	res := callMCP(c, "chat_mark_read", argsMap)
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("read_cursor: %v  unread: %v\n", res["read_cursor"], res["unread_count"])
}

func chatContacts(c *Client, g globalOpts, args []string) {
	var aid string
	parseGroupFlags(args, map[string]*string{"--aid": &aid})
	if aid == "" {
		fatalf("usage: a2al chat contacts --aid <aid>")
	}
	res := callMCP(c, "chat_contacts", map[string]any{"aid": aid})
	if g.JSON {
		printJSON(true, res)
		return
	}
	printJSON(true, res)
}
