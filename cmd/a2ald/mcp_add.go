// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// mcpAdd registers the A2AL MCP server with the hosts on this machine.
//
// It is best-effort by design. Host config formats evolve independently of this
// binary, so every failure path ends in the same place: print the entry, name
// what we could not do, and hand the decision to the caller — an agent running
// inside the host knows its own current format better than this table does.
// Silently guessing a shape the host does not read is worse than failing.
func mcpAdd(args []string) {
	fs := flag.NewFlagSet("a2ald mcp add", flag.ExitOnError)
	client := fs.String("client", "auto", "host name, or auto to configure every host detected here")
	cfgPath := fs.String("config", "", "write to this config file instead of the table's path (requires --client for the shape, or assumes mcpServers)")
	transport := fs.String("transport", "http", "http (starts a daemon if needed) or stdio")
	name := fs.String("name", "a2al", "server name to use in the entry")
	dryRun := fs.Bool("dry-run", false, "report what would change, write nothing")
	noRefresh := fs.Bool("no-refresh", false, "do not fetch the host table from the network")
	npx := fs.Bool("npx", false, "stdio transport: invoke via npx instead of this binary's path")
	dd := fs.String("data-dir", "", "data directory")
	_ = fs.Parse(args)

	dataDir := *dd
	if dataDir == "" {
		base, _ := os.UserConfigDir()
		dataDir = filepath.Join(base, "a2al")
	}
	apiAddr := resolveAPIAddr(dataDir)
	mcpURL := "http://" + apiAddr + "/mcp/"

	printBody, err := entryBody(*transport, mcpURL, *npx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "a2ald:", err)
		os.Exit(2)
	}

	if !*dryRun {
		started, err := ensureDaemon(dataDir, apiAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "a2ald mcp add: could not start a daemon: %v\n", err)
		} else if started {
			fmt.Fprintf(os.Stderr, "started a daemon at %s\n  %s\n", apiAddr, persistenceHint())
		}
	}

	table, source := loadHosts(dataDir, !*noRefresh)
	fmt.Fprintf(os.Stderr, "host table: %s (%d hosts)\n", source, len(table.Hosts))

	// Pick targets.
	var targets []hostSpec
	switch {
	case *cfgPath != "":
		spec := hostSpec{Name: *client, Display: *cfgPath, Wrapper: []string{"mcpServers"}, Verified: true}
		if h, ok := table.find(*client); ok {
			spec = h
			spec.Verified = true // an explicit path is the caller's assertion
		}
		spec.CLI = nil
		spec.Paths = []string{*cfgPath}
		targets = []hostSpec{spec}
	case *client == "auto":
		for _, h := range table.Hosts {
			if h.installed() {
				targets = append(targets, h)
			}
		}
		if len(targets) == 0 {
			failLoudly(*name, printBody, mcpURL, "no known host detected on this machine")
		}
	default:
		h, ok := table.find(*client)
		if !ok {
			failLoudly(*name, printBody, mcpURL, fmt.Sprintf("unknown host %q (known: %s)", *client, strings.Join(hostNames(table), ", ")))
		}
		targets = []hostSpec{h}
	}

	if *transport == "http" && !probeHTTPDaemon("http://"+apiAddr) {
		fmt.Fprintf(os.Stderr, "\nwarning: no daemon reachable at %s — this entry stays dead until one runs.\n", apiAddr)
		fmt.Fprintln(os.Stderr, "         start a2ald, or if you meant a second node: -data-dir plus matching -api-addr/-listen.")
	}

	failures := 0
	for _, h := range targets {
		body, err := hostEntry(h, *transport, mcpURL, *npx)
		if err != nil {
			failures++
			fmt.Fprintf(os.Stderr, "\n%-15s FAIL  %v\n", h.Name, err)
			continue
		}
		if err := applyHost(h, *name, body, mcpURL, *dryRun); err != nil {
			failures++
			fmt.Fprintf(os.Stderr, "\n%-15s FAIL  %v\n", h.Name, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "%-15s OK\n", h.Name)
	}

	fmt.Fprintln(os.Stderr, "\n"+afterAddHint())

	if failures > 0 {
		fmt.Fprintln(os.Stderr, "")
		failLoudly(*name, printBody, mcpURL, fmt.Sprintf("%d host(s) not configured", failures))
	}
}

// hostEntry is the JSON body this host's own docs show for the chosen transport.
func hostEntry(h hostSpec, transport, mcpURL string, npx bool) (map[string]any, error) {
	if h.Stdio || transport == "stdio" {
		return entryBody("stdio", mcpURL, npx)
	}
	key := h.URLField
	if key == "" {
		key = "url"
	}
	m := map[string]any{key: mcpURL}
	if h.HTTPType != "" {
		m["type"] = h.HTTPType
	}
	return m, nil
}

// applyHost tries the host's own CLI first, then its config file.
func applyHost(h hostSpec, name string, body map[string]any, mcpURL string, dryRun bool) error {
	if len(h.CLI) > 0 && !h.Interactive {
		if _, err := exec.LookPath(h.CLI[0]); err == nil {
			argv := make([]string, 0, len(h.CLI))
			cliObj := map[string]any{"name": name}
			for k, v := range body {
				cliObj[k] = v
			}
			entry, _ := json.Marshal(cliObj)
			for _, a := range h.CLI {
				a = strings.ReplaceAll(a, "{NAME}", name)
				a = strings.ReplaceAll(a, "{URL}", mcpURL)
				a = strings.ReplaceAll(a, "{JSON}", string(entry))
				argv = append(argv, a)
			}
			if dryRun {
				fmt.Fprintf(os.Stderr, "%-15s would run: %s\n", h.Name, strings.Join(argv, " "))
				return nil
			}
			out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() //nolint:gosec
			if err != nil {
				return fmt.Errorf("%s: %v: %s", argv[0], err, strings.TrimSpace(string(out)))
			}
			return nil
		}
		if len(h.Paths) == 0 {
			return fmt.Errorf("%s CLI not on PATH and no config file known for this host", h.CLI[0])
		}
	}

	path := ""
	for _, p := range h.Paths {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		if len(h.Paths) == 0 {
			return fmt.Errorf("no config path known")
		}
		// The host is installed but none of the paths we know exist: it likely
		// moved them. Creating one would write where the host never reads.
		if !h.Verified {
			return fmt.Errorf("none of the known config files exist (%s) - pass --config <path>", strings.Join(h.Paths, ", "))
		}
		path = h.Paths[0]
		if _, err := os.Stat(filepath.Dir(path)); err != nil {
			return fmt.Errorf("neither %s nor its directory exists - pass --config <path>", path)
		}
	}

	switch h.Format {
	case "dsh-cordis":
		return mergeDSHCordis(path, name, body, dryRun)
	case "yaml":
		return mergeYAMLConfig(path, h, name, body, dryRun)
	}
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		return fmt.Errorf("%s is not JSON; merging it blind is unsafe - write the entry yourself (a2ald mcp print --format toml)", path)
	}
	return mergeJSONConfig(path, h, name, body, dryRun)
}

// mergeJSONConfig inserts the entry at h.Wrapper in a JSON config, preserving
// everything else. Unverified specs must find Wrapper already present: that is
// the file corroborating our assumption about its shape.
func mergeJSONConfig(path string, h hostSpec, name string, body map[string]any, dryRun bool) error {
	root := map[string]any{}
	raw, readErr := os.ReadFile(path)
	if readErr == nil && len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &root); err != nil {
			return fmt.Errorf("%s is not valid JSON (%v) - not touching it", path, err)
		}
	}

	wrapper := h.Wrapper
	if len(wrapper) == 0 {
		wrapper = []string{"mcpServers"}
	}

	// Walk to the server map, creating levels only where allowed.
	node := root
	for _, key := range wrapper {
		child, ok := node[key].(map[string]any)
		if !ok {
			if _, exists := node[key]; exists {
				return fmt.Errorf("%s: %q is not an object - not touching it", path, key)
			}
			if !h.Verified {
				return fmt.Errorf("%s exists but has no %q; this host's layout is unconfirmed, so nothing was written - write the entry yourself or pass --config", path, strings.Join(wrapper, "."))
			}
			child = map[string]any{}
			node[key] = child
		}
		node = child
	}

	if existing, ok := node[name]; ok {
		if same, _ := json.Marshal(existing); string(same) == mustJSON(body) {
			fmt.Fprintf(os.Stderr, "%-15s unchanged (%s)\n", h.Name, path)
			return nil
		}
		fmt.Fprintf(os.Stderr, "%-15s replacing existing %q entry (%s)\n", h.Name, name, path)
	}
	node[name] = body

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	if dryRun {
		fmt.Fprintf(os.Stderr, "%-15s would write %s:\n%s\n", h.Name, path, out)
		return nil
	}
	if readErr == nil {
		if err := os.WriteFile(path+".bak", raw, 0o600); err != nil {
			return fmt.Errorf("backup %s: %w", path+".bak", err)
		}
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%-15s wrote %s\n", h.Name, path)
	return nil
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func hostNames(t hostsTable) []string {
	names := make([]string, 0, len(t.Hosts))
	for _, h := range t.Hosts {
		names = append(names, h.Name)
	}
	return names
}

// failLoudly is the last rung of the ladder and the only one that never rots:
// state the facts, hand over the decision, exit non-zero.
func failLoudly(name string, body map[string]any, mcpURL, reason string) {
	fmt.Fprintf(os.Stderr, "a2ald mcp add: %s\n\n", reason)
	fmt.Fprintln(os.Stderr, "Nothing was guessed and nothing was written. The entry to place is:")
	entry, _ := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{name: body}}, "", "  ")
	fmt.Fprintln(os.Stderr, string(entry))
	fmt.Fprintf(os.Stderr, "\nendpoint %s must be reachable and the daemon must stay running.\n", mcpURL)
	fmt.Fprintln(os.Stderr, "The wrapper key and nesting above are the common case, not a rule - follow your host.")
	fmt.Fprintln(os.Stderr, "Host-agnostic reference: https://github.com/a2al/a2al/blob/main/doc/mcp-entry.md")
	fmt.Fprintln(os.Stderr, "Or point us at the file: a2ald mcp add --client <name> --config <path>")
	os.Exit(1)
}

func afterAddHint() string {
	return strings.Join([]string{
		"Reload the host (restart it or re-open its MCP settings), then confirm a2al_* tools appear in your own tool list.",
		"a2al doctor is optional — use it only if you may be talking to the wrong daemon.",
	}, "\n")
}
