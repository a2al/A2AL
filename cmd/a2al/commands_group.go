// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// callMCP calls POST /mcp/call and returns the parsed result map.
// On tool error or HTTP error, it prints the error and exits.
func callMCP(c *Client, tool string, args map[string]any) map[string]any {
	var result map[string]any
	_, _, err := c.DoRequest(http.MethodPost, "/mcp/call", map[string]any{
		"tool": tool,
		"args": args,
	}, &result)
	if err != nil {
		fatal(err)
	}
	return result
}

// tryCallMCP is like callMCP but returns the error instead of exiting.
func tryCallMCP(c *Client, tool string, args map[string]any) (map[string]any, error) {
	var result map[string]any
	_, _, err := c.DoRequest(http.MethodPost, "/mcp/call", map[string]any{
		"tool": tool,
		"args": args,
	}, &result)
	return result, err
}

// parseGroupFlags parses common group flags from argv.
// Returns remaining positional args after consuming known flags.
func parseGroupFlags(argv []string, flags map[string]*string) []string {
	var pos []string
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		consumed := false
		for flag, ptr := range flags {
			if a == flag && i+1 < len(argv) {
				i++
				*ptr = argv[i]
				consumed = true
				break
			}
			if strings.HasPrefix(a, flag+"=") {
				*ptr = strings.TrimPrefix(a, flag+"=")
				consumed = true
				break
			}
		}
		if !consumed {
			pos = append(pos, a)
		}
	}
	return pos
}

func cmdGroup(c *Client, g globalOpts, args []string) {
	if len(args) == 0 {
		groupHelp()
		os.Exit(1)
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "create":
		groupCreate(c, g, rest)
	case "list":
		groupList(c, g, rest)
	case "join":
		groupJoin(c, g, rest)
	case "invite":
		groupInvite(c, g, rest)
	case "append":
		groupAppend(c, g, rest)
	case "read":
		groupRead(c, g, rest)
	case "head":
		groupHead(c, g, rest)
	case "sync":
		groupSync(c, g, rest)
	case "members":
		groupMembers(c, g, rest)
	case "get-link":
		groupGetLink(c, g, rest)
	case "mark-read":
		groupMarkRead(c, g, rest)
	case "retract":
		groupRetract(c, g, rest)
	case "object":
		groupObject(c, g, rest)
	case "help", "-h", "--help":
		groupHelp()
	default:
		fatalf("a2al group: unknown subcommand %q (try a2al group help)", sub)
	}
}

func groupHelp() {
	fmt.Print(`a2al group — manage collaboration Groups

Usage:
  a2al group create    --aid <aid> [--title <title>]
  a2al group list      --aid <aid>
  a2al group join      --aid <aid> (--link <url> | --group-id <id> --creator <aid> [--peer <aid>]) [--inviter <aid>] [--title <t>]
  a2al group invite    --aid <aid> --group-id <id> --target <aid>
  a2al group append    --aid <aid> --group-id <id> [--kind <kind>] [--body <text>] [--file <path>]
                       [--reply-to <entry-id>] [--to <aid>]
  a2al group read      --aid <aid> --group-id <id> [--after-seq <n>] [--limit <n>] [--kind <kind>]
  a2al group head      --aid <aid> --group-id <id>
  a2al group members   --aid <aid> --group-id <id>
  a2al group get-link  --aid <aid> --group-id <id>
  a2al group mark-read --aid <aid> --group-id <id> --seq <n>
  a2al group retract   --aid <aid> --group-id <id> --entry <entry-id>
  a2al group object put    --aid <aid> <file>
  a2al group object locate --aid <aid> --hash <hash> [--hint <aid>]
  a2al group object get    --aid <aid> --hash <hash> [--hint <aid>] [-o <file>] [--register]

Diagnostics only (the daemon aligns replicas on its own; you should not need this):
  a2al group sync      --aid <aid> --group-id <id> --peer <aid>

Global flags: --api <url>  --token <tok>  --json  --quiet
`)
}

func groupCreate(c *Client, g globalOpts, args []string) {
	var aid, title string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--title": &title})
	if aid == "" {
		fatalf("usage: a2al group create --aid <aid> [--title <title>]")
	}
	mcpArgs := map[string]any{"aid": aid}
	if title != "" {
		mcpArgs["title"] = title
	}
	res := callMCP(c, "group_create", mcpArgs)
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("group_id: %s\nlink:     %s\n", res["group_id"], res["link"])
}

func groupList(c *Client, g globalOpts, args []string) {
	var aid string
	parseGroupFlags(args, map[string]*string{"--aid": &aid})
	if aid == "" {
		fatalf("usage: a2al group list --aid <aid>")
	}
	res := callMCP(c, "group_list", map[string]any{"aid": aid})
	if g.JSON {
		printJSON(true, res)
		return
	}
	groups, _ := res["groups"].([]any)
	if len(groups) == 0 {
		fmt.Println("(no groups)")
		return
	}
	for _, gi := range groups {
		m, _ := gi.(map[string]any)
		title, _ := m["title"].(string)
		if title == "" {
			title = "(no title)"
		}
		gid, _ := m["group_id"].(string)
		cnt := m["entry_count"]
		fmt.Printf("%-20s %s  entries=%v\n", shortHex(gid), title, cnt)
	}
}

func groupJoin(c *Client, g globalOpts, args []string) {
	var aid, link, groupID, creator, peer, title, inviter string
	parseGroupFlags(args, map[string]*string{
		"--aid": &aid, "--link": &link, "--group-id": &groupID,
		"--creator": &creator, "--peer": &peer, "--title": &title,
		"--inviter": &inviter,
	})
	if aid == "" || (link == "" && (groupID == "" || creator == "")) {
		fatalf("usage: a2al group join --aid <aid> (--link <url> | --group-id <id> --creator <aid>) [--peer <aid>] [--inviter <aid>] [--title <t>]")
	}
	mcpArgs := map[string]any{"aid": aid}
	if link != "" {
		mcpArgs["link"] = link
	} else {
		mcpArgs["group_id"] = groupID
		mcpArgs["creator_aid"] = creator
	}
	if peer != "" {
		mcpArgs["peer_aid"] = peer
	}
	if title != "" {
		mcpArgs["title"] = title
	}
	if inviter != "" {
		mcpArgs["inviter_aid"] = inviter
	}
	res := callMCP(c, "group_join", mcpArgs)
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("group_id:    %s\nentry_count: %v\nis_member:   %v\n",
		res["group_id"], res["entry_count"], res["is_member"])
}

func groupInvite(c *Client, g globalOpts, args []string) {
	var aid, groupID, target string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--group-id": &groupID, "--target": &target})
	if aid == "" || groupID == "" || target == "" {
		fatalf("usage: a2al group invite --aid <aid> --group-id <id> --target <aid>")
	}
	res := callMCP(c, "group_invite", map[string]any{"aid": aid, "group_id": groupID, "target_aid": target})
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("invited: entry_id=%s\n", res["entry_id"])
}

func groupAppend(c *Client, g globalOpts, args []string) {
	var aid, groupID, kind, body, file, replyTo string
	var toAIDs []string
	// Collect --to flags manually before generic parse.
	filtered := args[:0:0]
	for i := 0; i < len(args); i++ {
		if args[i] == "--to" && i+1 < len(args) {
			toAIDs = append(toAIDs, args[i+1])
			i++
		} else {
			filtered = append(filtered, args[i])
		}
	}
	parseGroupFlags(filtered, map[string]*string{
		"--aid": &aid, "--group-id": &groupID, "--kind": &kind,
		"--body": &body, "--file": &file, "--reply-to": &replyTo,
	})
	if aid == "" || groupID == "" {
		fatalf("usage: a2al group append --aid <aid> --group-id <id> [--kind <k>] [--body <text>] [--file <path>] [--reply-to <id>] [--to <aid>]")
	}
	if kind == "" {
		kind = "msg"
	}
	mcpArgs := map[string]any{"aid": aid, "group_id": groupID, "kind": kind}
	if replyTo != "" {
		mcpArgs["reply_to"] = replyTo
	}
	if len(toAIDs) > 0 {
		mcpArgs["to"] = toAIDs
	}

	if file != "" {
		absFile, err := filepath.Abs(file)
		if err != nil {
			fatalf("path: %v", err)
		}
		objRes, putErr := tryCallMCP(c, "group_object_put", map[string]any{
			"aid":  aid,
			"path": absFile,
		})
		if putErr != nil {
			// a2ald cannot read the path; stream the bytes to it instead.
			var upErr error
			if objRes, upErr = uploadObject(c, aid, file); upErr != nil {
				fatalf("group_object_put: %v (and streaming upload failed: %v)", putErr, upErr)
			}
		}
		mcpArgs["ref"] = objRes["object_id"]
		name, _ := objRes["name"].(string)
		desc := map[string]any{"name": name, "size": objRes["size"]}
		raw, err := json.Marshal(desc)
		if err != nil {
			fatalf("object descriptor: %v", err)
		}
		mcpArgs["body"] = base64.StdEncoding.EncodeToString(raw)
		if kind == "msg" {
			mcpArgs["kind"] = "file"
		}
	} else if body != "" {
		mcpArgs["body"] = base64.StdEncoding.EncodeToString([]byte(body))
	}

	res := callMCP(c, "group_append", mcpArgs)
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("entry_id: %s  seq: %v\n", res["entry_id"], res["seq"])
}

func groupRead(c *Client, g globalOpts, args []string) {
	var aid, groupID, afterSeqStr, limitStr, kind, cursorStr string
	parseGroupFlags(args, map[string]*string{
		"--aid": &aid, "--group-id": &groupID,
		"--after-seq": &afterSeqStr, "--limit": &limitStr, "--kind": &kind,
		"--cursor": &cursorStr,
	})
	if cursorStr != "" {
		fatalf("--cursor was renamed to --after-seq")
	}
	if aid == "" || groupID == "" {
		fatalf("usage: a2al group read --aid <aid> --group-id <id> [--after-seq <n>] [--limit <n>] [--kind <kind>]")
	}
	mcpArgs := map[string]any{"aid": aid, "group_id": groupID}
	if afterSeqStr != "" {
		n, _ := strconv.ParseUint(afterSeqStr, 10, 64)
		mcpArgs["after_seq"] = n
	}
	if limitStr != "" {
		n, _ := strconv.Atoi(limitStr)
		mcpArgs["limit"] = n
	}
	if kind != "" {
		mcpArgs["kind"] = kind
	}
	res := callMCP(c, "group_read", mcpArgs)
	if g.JSON {
		printJSON(true, res)
		return
	}
	entries, _ := res["entries"].([]any)
	for _, ei := range entries {
		em, _ := ei.(map[string]any)
		seq := em["seq"]
		author, _ := em["author"].(string)
		ek, _ := em["kind"].(string)
		ts := em["ts_ms"]
		bodyRaw := em["body"]
		ref := em["ref"]
		var bodyStr string
		if bodyRaw != nil {
			if s, ok := bodyRaw.(string); ok {
				// body is base64; try to decode as UTF-8 text
				if b, err := base64.StdEncoding.DecodeString(s); err == nil {
					bodyStr = string(b)
				} else {
					bodyStr = s
				}
			}
		} else if ref != nil {
			bodyStr = fmt.Sprintf("[object: %v]", ref)
		}
		fmt.Printf("[%v] %s %s | %v | %s\n", seq, shortAID(author), ek, ts, bodyStr)
	}
	if more, _ := res["has_more"].(bool); more {
		fmt.Printf("  … (--after-seq %v for the next page)\n", res["scanned_to_seq"])
	}
}

func groupHead(c *Client, g globalOpts, args []string) {
	var aid, groupID string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--group-id": &groupID})
	if aid == "" || groupID == "" {
		fatalf("usage: a2al group head --aid <aid> --group-id <id>")
	}
	res := callMCP(c, "group_head", map[string]any{"aid": aid, "group_id": groupID})
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("entries:      %v\nmax_seq:      %v\nunread:       %v\nread_cursor:  %v\nwanted:       %v\nheads:\n",
		res["entry_count"], res["max_seq"], res["unread_count"], res["read_cursor"], res["wanted_count"])
	if heads, ok := res["heads"].([]any); ok {
		for _, h := range heads {
			fmt.Printf("  %v\n", h)
		}
	}
}

func groupSync(c *Client, g globalOpts, args []string) {
	var aid, groupID, peer string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--group-id": &groupID, "--peer": &peer})
	if aid == "" || groupID == "" || peer == "" {
		fatalf("usage: a2al group sync --aid <aid> --group-id <id> --peer <aid>")
	}
	res := callMCP(c, "group_sync", map[string]any{"aid": aid, "group_id": groupID, "peer_aid": peer})
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("new_entries: %v\n", res["new_entries"])
}

func groupMembers(c *Client, g globalOpts, args []string) {
	var aid, groupID string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--group-id": &groupID})
	if aid == "" || groupID == "" {
		fatalf("usage: a2al group members --aid <aid> --group-id <id>")
	}
	res := callMCP(c, "group_members", map[string]any{"aid": aid, "group_id": groupID})
	if g.JSON {
		printJSON(true, res)
		return
	}
	if head, ok := res["local_head"]; ok {
		fmt.Printf("local replica: %v entries\n", head)
	}
	members, _ := res["members"].([]any)
	for _, mi := range members {
		mm, _ := mi.(map[string]any)
		// replica_head is what we last observed, not proof of delivery.
		observed := "-"
		if h, ok := mm["replica_head"]; ok {
			observed = fmt.Sprintf("%v", h)
		}
		fmt.Printf("%-60s %-8s seen %s\n", mm["aid"], mm["role"], observed)
	}
}

func groupGetLink(c *Client, g globalOpts, args []string) {
	var aid, groupID string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--group-id": &groupID})
	if aid == "" || groupID == "" {
		fatalf("usage: a2al group get-link --aid <aid> --group-id <id>")
	}
	res := callMCP(c, "group_get_link", map[string]any{"aid": aid, "group_id": groupID})
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Println(res["link"])
}

func groupMarkRead(c *Client, g globalOpts, args []string) {
	var aid, groupID, seqStr string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--group-id": &groupID, "--seq": &seqStr})
	if aid == "" || groupID == "" || seqStr == "" {
		fatalf("usage: a2al group mark-read --aid <aid> --group-id <id> --seq <n>")
	}
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil {
		fatalf("invalid seq: %v", err)
	}
	res := callMCP(c, "group_mark_read", map[string]any{"aid": aid, "group_id": groupID, "seq": seq})
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("read_cursor: %v  unread: %v\n", res["read_cursor"], res["unread_count"])
}

func groupRetract(c *Client, g globalOpts, args []string) {
	var aid, groupID, entryID string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--group-id": &groupID, "--entry": &entryID})
	if aid == "" || groupID == "" || entryID == "" {
		fatalf("usage: a2al group retract --aid <aid> --group-id <id> --entry <entry-id>")
	}
	res := callMCP(c, "group_retract", map[string]any{"aid": aid, "group_id": groupID, "entry_id": entryID})
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("retracted: %s\n", res["retract_entry_id"])
}

func groupObject(c *Client, g globalOpts, args []string) {
	if len(args) == 0 {
		fatalf("usage: a2al group object <put|locate|get> ...")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "put":
		groupObjectPut(c, g, rest)
	case "locate":
		groupObjectLocate(c, g, rest)
	case "get":
		groupObjectGet(c, g, rest)
	default:
		fatalf("a2al group object: unknown subcommand %q (put | locate | get)", sub)
	}
}

func groupObjectPut(c *Client, g globalOpts, args []string) {
	var aid string
	pos := parseGroupFlags(args, map[string]*string{"--aid": &aid})
	if aid == "" || len(pos) == 0 {
		fatalf("usage: a2al group object put --aid <aid> <file>")
	}
	filePath := pos[0]
	abs, err := filepath.Abs(filePath)
	if err != nil {
		fatalf("path: %v", err)
	}
	res, putErr := tryCallMCP(c, "group_object_put", map[string]any{"aid": aid, "path": abs})
	if putErr != nil {
		// a2ald cannot read the path (files_root boundary, container, or a
		// filesystem it does not share). Hand it the bytes instead, streamed —
		// not base64 inside a JSON call, which would cap the file at ~768 KiB.
		var upErr error
		if res, upErr = uploadObject(c, aid, filePath); upErr != nil {
			fatalf("group_object_put: %v (and streaming upload failed: %v)", putErr, upErr)
		}
	}
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("object_id: %s  size: %v  name: %v\n", res["object_id"], res["size"], res["name"])
}

// uploadObject streams a local file to the daemon's object-ingest endpoint.
// The file is never held in memory, so size is bounded only by the sandbox's
// free disk space.
func uploadObject(c *Client, aid, filePath string) (map[string]any, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read file locally: %w", err)
	}
	defer f.Close()

	path := "/agents/" + url.PathEscape(aid) + "/cas?name=" + url.QueryEscape(filepath.Base(filePath))
	var res map[string]any
	if err := c.PostStream(path, f, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func groupObjectLocate(c *Client, g globalOpts, args []string) {
	var aid, hash, hint string
	parseGroupFlags(args, map[string]*string{"--aid": &aid, "--hash": &hash, "--hint": &hint})
	if aid == "" || hash == "" {
		fatalf("usage: a2al group object locate --aid <aid> --hash <hash> [--hint <aid>]")
	}
	mcpArgs := map[string]any{"aid": aid, "object_id": hash}
	if hint != "" {
		mcpArgs["hint_aid"] = hint
	}
	res := callMCP(c, "group_object_locate", mcpArgs)
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("status: %v\n", res["status"])
	if p, ok := res["path"]; ok {
		fmt.Printf("path: %v\n", p)
	}
	if u, ok := res["url"]; ok {
		fmt.Printf("url: %v\n", u)
	}
}

func groupObjectGet(c *Client, g globalOpts, args []string) {
	var aid, hash, hint, outFile string
	filtered := make([]string, 0, len(args))
	register := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--register" {
			register = true
			continue
		}
		filtered = append(filtered, args[i])
	}
	parseGroupFlags(filtered, map[string]*string{
		"--aid": &aid, "--hash": &hash, "--hint": &hint, "-o": &outFile,
	})
	if aid == "" || hash == "" {
		fatalf("usage: a2al group object get --aid <aid> --hash <hash> [--hint <aid>] [-o <file>] [--register]")
	}
	mcpArgs := map[string]any{"aid": aid, "object_id": hash, "register": register}
	if hint != "" {
		mcpArgs["hint_aid"] = hint
	}
	if outFile != "" {
		abs, err := filepath.Abs(outFile)
		if err != nil {
			fatalf("path: %v", err)
		}
		mcpArgs["dest"] = abs
	}
	res := callMCP(c, "group_object_get", mcpArgs)
	if g.JSON {
		printJSON(true, res)
		return
	}
	fmt.Printf("path: %v  size: %v\n", res["path"], res["size"])
}

// shortHex returns the first 8 + last 6 chars of a hex string for display.
func shortHex(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:8] + "…" + s[len(s)-6:]
}
