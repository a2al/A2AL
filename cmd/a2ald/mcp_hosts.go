// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// hostsURL is refreshed at runtime so a host changing its config layout does not
// require a new a2ald release. Failure to fetch is never fatal: the cache, then
// the compiled-in table, then a loud fallback (see mcpAdd) take over.
const hostsURL = "https://a2al.org/mcp-hosts.json"

//go:embed mcp-hosts.json
var builtinHostsJSON []byte

// hostSpec describes how to register an MCP server with one host.
//
// Strategies are tried in the order they are listed here, and the order is the
// point: a host's own CLI owns its own config format, so using it cannot go
// stale. Editing config files ourselves is the fallback, and for specs we have
// not verified it additionally requires evidence from the file itself.
type hostSpec struct {
	Name    string   `json:"name"`
	Display string   `json:"display"`
	Aliases []string `json:"aliases,omitempty"`
	CLI     []string `json:"cli,omitempty"`     // argv template; {NAME} {URL} {JSON} substituted
	Detect  []string `json:"detect,omitempty"`  // paths whose existence means the host is installed
	Paths   []string `json:"paths,omitempty"`   // candidate config files, most specific first
	Wrapper []string `json:"wrapper,omitempty"` // key path holding the server map, e.g. ["mcpServers"]

	// URLField is the HTTP endpoint key this host documents. Empty means "url"
	// (Cursor). Windsurf's documented remote example uses "serverUrl".
	URLField string `json:"url_field,omitempty"`
	// HTTPType, if set, is written as "type" on HTTP entries. VS Code's HTTP
	// schema requires "http"; Cursor's documented remote example has no type.
	HTTPType string `json:"http_type,omitempty"`
	// Stdio means this host's documented local path is a spawned process, not
	// an HTTP URL. Claude Desktop's official local MCP tutorial is stdio.
	Stdio bool `json:"stdio,omitempty"`
	// Format is the config file syntax. Empty means JSON. "yaml" is a server
	// map (Hermes mcp_servers). "dsh-cordis" is a Cordis patch list.
	Format string `json:"format,omitempty"`
	// Interactive means the host's CLI prompts (tool picker, OAuth, …). mcp add
	// must not run it unattended; the documented file shape is written instead.
	Interactive bool `json:"interactive,omitempty"`

	// Verified reports whether we have confirmed Paths/Wrapper against the real
	// host. An unverified spec is only written to a file that already contains
	// Wrapper — writing a shape the host does not read is worse than failing.
	Verified bool `json:"verified"`
}

type hostsTable struct {
	Version int        `json:"version"`
	Hosts   []hostSpec `json:"hosts"`
}

func builtinHosts() hostsTable {
	t, err := parseHostsJSON(builtinHostsJSON)
	if err != nil {
		return hostsTable{}
	}
	return t
}

func parseHostsJSON(b []byte) (hostsTable, error) {
	var t hostsTable
	if err := json.Unmarshal(b, &t); err != nil {
		return t, err
	}
	if len(t.Hosts) == 0 {
		return t, errEmptyHosts
	}
	return expandHosts(t), nil
}

var errEmptyHosts = errors.New("empty host table")

func expandHosts(t hostsTable) hostsTable {
	out := hostsTable{Version: t.Version, Hosts: make([]hostSpec, 0, len(t.Hosts))}
	for _, h := range t.Hosts {
		h.Detect = expandPathList(h.Detect)
		h.Paths = expandPathList(h.Paths)
		out.Hosts = append(out.Hosts, h)
	}
	return out
}

func expandPathList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if e := expandPath(p); e != "" {
			out = append(out, e)
		}
	}
	return out
}

func expandPath(p string) string {
	home, _ := os.UserHomeDir()
	cfg, _ := os.UserConfigDir()
	repl := []struct{ token, val string }{
		{"{HOME}", home},
		{"{CONFIG}", cfg},
		{"{APPDATA}", os.Getenv("APPDATA")},
		{"{DSH_HOME}", os.Getenv("DSH_HOME")},
	}
	out := p
	for _, r := range repl {
		if !strings.Contains(out, r.token) {
			continue
		}
		if r.val == "" {
			return ""
		}
		out = strings.ReplaceAll(out, r.token, r.val)
	}
	return filepath.FromSlash(out)
}

// loadHosts returns the effective table: remote (cached on success), else cache,
// else builtin. The returned string names which source won, for reporting.
func loadHosts(dataDir string, refresh bool) (hostsTable, string) {
	cachePath := filepath.Join(dataDir, "mcp-hosts.json")
	if refresh {
		c := &http.Client{Timeout: 2 * time.Second}
		if resp, err := c.Get(hostsURL); err == nil {
			body, rerr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if rerr == nil && resp.StatusCode == 200 {
				if t, err := parseHostsJSON(body); err == nil {
					_ = os.MkdirAll(dataDir, 0o755)
					_ = os.WriteFile(cachePath, body, 0o644)
					return t, "remote"
				}
			}
		}
	}
	if b, err := os.ReadFile(cachePath); err == nil {
		if t, err := parseHostsJSON(b); err == nil {
			return t, "cache"
		}
	}
	return builtinHosts(), "builtin"
}

// installed reports whether the host looks present on this machine.
func (h hostSpec) installed() bool {
	if len(h.CLI) > 0 {
		if _, err := exec.LookPath(h.CLI[0]); err == nil {
			return true
		}
		if len(h.Paths) == 0 {
			return false
		}
	}
	for _, p := range append(append([]string{}, h.Detect...), h.Paths...) {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func (t hostsTable) find(name string) (hostSpec, bool) {
	for _, h := range t.Hosts {
		if strings.EqualFold(h.Name, name) {
			return h, true
		}
		for _, a := range h.Aliases {
			if strings.EqualFold(a, name) {
				return h, true
			}
		}
	}
	return hostSpec{}, false
}
