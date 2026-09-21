// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/a2al/a2al/config"
)

// handleMCPCmd implements "a2ald mcp <sub>".
//
// print states the facts (endpoint, transport, whether the daemon is up); the
// caller places them. add starts a daemon if none is running and writes known
// hosts. An unknown host is not guessed: the entry is printed and nothing is
// written. Hosts that ship their own CLI are preferred over editing a file.
func handleMCPCmd(args []string) {
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "print":
		mcpPrint(args)
	case "add":
		mcpAdd(args)
	default:
		fmt.Fprintln(os.Stderr, "usage: a2ald mcp print [--transport http|stdio] [--format json|toml] [--bare] [--npx]")
		fmt.Fprintln(os.Stderr, "       a2ald mcp add  [--client auto|<name>] [--config <path>] [--transport http|stdio] [--dry-run]")
		fmt.Fprintln(os.Stderr, "  add starts a daemon if none is running, then registers known hosts.")
		fmt.Fprintln(os.Stderr, "  unknown host: nothing is written; the entry is printed.")
		if sub != "" && sub != "help" && sub != "-h" && sub != "--help" {
			os.Exit(2)
		}
	}
}

// entryBody builds the MCP server entry body: the one fact this binary owns.
func entryBody(transport, mcpURL string, npx bool) (map[string]any, error) {
	switch transport {
	case "http":
		return map[string]any{"url": mcpURL}, nil
	case "stdio":
		cmdPath, cmdArgs := "a2ald", []string{"--mcp-stdio"}
		if npx {
			cmdPath, cmdArgs = "npx", []string{"-y", "a2ald", "--mcp-stdio"}
		} else if exe, err := os.Executable(); err == nil {
			cmdPath = exe
		}
		return map[string]any{"command": cmdPath, "args": cmdArgs}, nil
	default:
		return nil, fmt.Errorf("--transport must be http or stdio")
	}
}

func mcpPrint(args []string) {
	fs := flag.NewFlagSet("a2ald mcp print", flag.ExitOnError)
	transport := fs.String("transport", "http", "http (daemon must be running) or stdio (client spawns a2ald)")
	format := fs.String("format", "json", "json or toml")
	name := fs.String("name", "a2al", "server name to use in the entry")
	bare := fs.Bool("bare", false, "print only the entry body, without the servers wrapper")
	npx := fs.Bool("npx", false, "stdio transport: invoke via npx instead of this binary's path")
	dd := fs.String("data-dir", "", "data directory (to locate config.toml for the API address)")
	_ = fs.Parse(args)

	apiAddr := resolveAPIAddr(*dd)
	mcpURL := "http://" + apiAddr + "/mcp/"

	body, err := entryBody(*transport, mcpURL, *npx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "a2ald:", err)
		os.Exit(2)
	}

	switch *format {
	case "json":
		out := any(body)
		if !*bare {
			out = map[string]any{"mcpServers": map[string]any{*name: body}}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	case "toml":
		if *bare {
			printTOMLBody(body)
		} else {
			fmt.Printf("[mcp_servers.%s]\n", *name)
			printTOMLBody(body)
		}
	default:
		fmt.Fprintln(os.Stderr, "a2ald: --format must be json or toml")
		os.Exit(2)
	}

	// Invariants and caveats go to stderr so stdout stays machine-consumable.
	fmt.Fprintln(os.Stderr, "\n--- what must hold, regardless of your host's config shape ---")
	fmt.Fprintf(os.Stderr, "endpoint : %s\n", mcpURL)
	fmt.Fprintf(os.Stderr, "transport: %s\n", *transport)
	if *transport == "http" {
		if probeHTTPDaemon("http://" + apiAddr) {
			fmt.Fprintln(os.Stderr, "daemon   : reachable - nothing else to start")
		} else {
			fmt.Fprintln(os.Stderr, "daemon   : NOT reachable - start it and keep it running, or this entry is dead")
		}
	} else if probeHTTPDaemon("http://" + apiAddr) {
		fmt.Fprintln(os.Stderr, "daemon   : already running — stdio will proxy to it")
	} else {
		fmt.Fprintln(os.Stderr, "daemon   : the client spawns this process (proxies if a daemon is already running)")
	}
	fmt.Fprintln(os.Stderr, "\nThe wrapper key and nesting above are the common case, not a rule. If your host")
	fmt.Fprintln(os.Stderr, "uses a different shape, trust your host over this output and keep the facts above.")
}

func printTOMLBody(body map[string]any) {
	if url, ok := body["url"].(string); ok {
		fmt.Printf("url = %q\n", url)
		return
	}
	fmt.Printf("command = %q\n", body["command"])
	quoted := make([]string, 0, 2)
	for _, a := range body["args"].([]string) {
		quoted = append(quoted, fmt.Sprintf("%q", a))
	}
	fmt.Printf("args = [%s]\n", strings.Join(quoted, ", "))
}

// resolveAPIAddr reads config.toml from dd to determine the daemon API address.
func resolveAPIAddr(dd string) string {
	if dd == "" {
		base, _ := os.UserConfigDir()
		dd = filepath.Join(base, "a2al")
	}
	cfg := config.Default()
	if c, err := config.LoadFile(filepath.Join(dd, "config.toml")); err == nil {
		cfg = c
	}
	return cfg.APIAddr
}
