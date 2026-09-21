// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m
}

// A verified spec may create the wrapper, and must leave unrelated keys alone.
func TestMergePreservesOtherServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"other":{"url":"http://x/"}},"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := hostSpec{Name: "t", Wrapper: []string{"mcpServers"}, Verified: true}
	if err := mergeJSONConfig(path, h, "a2al", map[string]any{"url": "http://127.0.0.1:2121/mcp/"}, false); err != nil {
		t.Fatal(err)
	}
	got := readJSON(t, path)
	if got["theme"] != "dark" {
		t.Errorf("unrelated key lost: %v", got)
	}
	servers := got["mcpServers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Errorf("sibling server lost: %v", servers)
	}
	if servers["a2al"].(map[string]any)["url"] != "http://127.0.0.1:2121/mcp/" {
		t.Errorf("entry not written: %v", servers)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("no backup written: %v", err)
	}
}

// An unverified spec must not write into a file that shows no sign of our
// assumed layout: a wrong shape the host never reads is worse than failing.
func TestUnverifiedSpecRequiresCorroboration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"gateway":{"port":18080}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := hostSpec{Name: "openclaw", Wrapper: []string{"mcpServers"}, Verified: false}
	err := mergeJSONConfig(path, h, "a2al", map[string]any{"url": "http://x/"}, false)
	if err == nil {
		t.Fatal("expected refusal, got nil")
	}
	if !strings.Contains(err.Error(), "unconfirmed") {
		t.Errorf("unhelpful error: %v", err)
	}
	if got := readJSON(t, path); len(got) != 1 {
		t.Errorf("file was modified: %v", got)
	}

	// Same spec, but now the file corroborates the layout.
	if err := os.WriteFile(path, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mergeJSONConfig(path, h, "a2al", map[string]any{"url": "http://x/"}, false); err != nil {
		t.Fatalf("corroborated write refused: %v", err)
	}
}

func TestMalformedConfigIsLeftAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := hostSpec{Name: "t", Wrapper: []string{"mcpServers"}, Verified: true}
	if err := mergeJSONConfig(path, h, "a2al", map[string]any{"url": "http://x/"}, false); err == nil {
		t.Fatal("expected refusal on invalid JSON")
	}
	b, _ := os.ReadFile(path)
	if string(b) != `{"mcpServers":` {
		t.Errorf("file changed: %q", b)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := hostSpec{Name: "t", Wrapper: []string{"mcpServers"}, Verified: true}
	if err := mergeJSONConfig(path, h, "a2al", map[string]any{"url": "http://x/"}, true); err != nil {
		t.Fatal(err)
	}
	if got := readJSON(t, path)["mcpServers"].(map[string]any); len(got) != 0 {
		t.Errorf("dry run wrote: %v", got)
	}
}

// The offline floor must always yield a usable table.
func TestLoadHostsFallsBackToBuiltin(t *testing.T) {
	table, source := loadHosts(t.TempDir(), false)
	if source != "builtin" || len(table.Hosts) == 0 {
		t.Fatalf("source=%s hosts=%d", source, len(table.Hosts))
	}
	for _, name := range []string{"cursor", "openclaw", "claude-code", "vscode", "windsurf", "claude-desktop", "hermes", "deepseek-harness"} {
		if _, ok := table.find(name); !ok {
			t.Errorf("builtin table missing %s", name)
		}
	}
	if _, ok := table.find("dsh"); !ok {
		t.Error("deepseek-harness alias dsh missing")
	}
	h, _ := table.find("openclaw")
	if len(h.CLI) == 0 || len(h.Paths) != 0 {
		t.Errorf("openclaw must use its CLI, not a guessed file: %+v", h)
	}
	h, _ = table.find("hermes")
	if !h.Interactive || h.Format != "yaml" || strings.Join(h.Wrapper, ".") != "mcp_servers" {
		t.Errorf("hermes: interactive=%v format=%q wrapper=%v", h.Interactive, h.Format, h.Wrapper)
	}
	if strings.Join(h.CLI, " ") != "hermes mcp add --url {URL} {NAME}" {
		t.Errorf("hermes CLI must match official `hermes mcp add --url URL NAME`: %v", h.CLI)
	}
	h, _ = table.find("deepseek-harness")
	if h.Format != "dsh-cordis" || len(h.CLI) != 0 {
		t.Errorf("deepseek-harness: format=%q cli=%v", h.Format, h.CLI)
	}
	h, _ = table.find("windsurf")
	if h.URLField != "serverUrl" {
		t.Errorf("windsurf url_field=%q", h.URLField)
	}
	h, _ = table.find("claude-desktop")
	if !h.Stdio {
		t.Error("claude-desktop must use stdio (official local MCP path)")
	}
	h, _ = table.find("vscode")
	if h.HTTPType != "http" {
		t.Errorf("vscode http_type=%q", h.HTTPType)
	}
}

func TestHostEntryMatchesHostDocs(t *testing.T) {
	u := "http://127.0.0.1:2121/mcp/"
	got, err := hostEntry(hostSpec{}, "http", u, false)
	if err != nil || got["url"] != u || got["type"] != nil {
		t.Fatalf("cursor-shaped: %v %v", got, err)
	}
	got, err = hostEntry(hostSpec{URLField: "serverUrl"}, "http", u, false)
	if err != nil || got["serverUrl"] != u {
		t.Fatalf("windsurf: %v %v", got, err)
	}
	if _, ok := got["url"]; ok {
		t.Fatal("windsurf must not write url")
	}
	got, err = hostEntry(hostSpec{HTTPType: "http"}, "http", u, false)
	if err != nil || got["type"] != "http" || got["url"] != u {
		t.Fatalf("vscode: %v %v", got, err)
	}
	got, err = hostEntry(hostSpec{Stdio: true}, "http", u, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["command"]; !ok {
		t.Fatalf("claude-desktop stdio: %v", got)
	}
	if _, ok := got["url"]; ok {
		t.Fatal("claude-desktop must not write url")
	}
}

func TestBuiltinHostsJSONParses(t *testing.T) {
	if _, err := parseHostsJSON(builtinHostsJSON); err != nil {
		t.Fatal(err)
	}
}

func TestExpandPathHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	got := expandPath("{HOME}/.cursor/mcp.json")
	want := filepath.Join(home, ".cursor", "mcp.json")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLoadHostsCacheExpandsPlaceholders(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"version":1,"hosts":[{"name":"x","display":"X","paths":["{HOME}/x.json"],"verified":true}]}`)
	if err := os.WriteFile(filepath.Join(dir, "mcp-hosts.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	table, source := loadHosts(dir, false)
	if source != "cache" {
		t.Fatalf("source=%s", source)
	}
	h, ok := table.find("x")
	if !ok || len(h.Paths) != 1 {
		t.Fatalf("host=%v ok=%v", h, ok)
	}
	home, _ := os.UserHomeDir()
	if h.Paths[0] != filepath.Join(home, "x.json") {
		t.Fatalf("path=%q", h.Paths[0])
	}
}

func TestAfterAddHintDoesNotRequireDoctor(t *testing.T) {
	s := afterAddHint()
	if !strings.Contains(s, "a2al_*") {
		t.Errorf("hint does not tell the caller to confirm tools: %q", s)
	}
	if strings.Contains(s, "verify with: a2al doctor") {
		t.Errorf("doctor must not be a required next step: %q", s)
	}
	if !strings.Contains(s, "optional") {
		t.Errorf("doctor should be marked optional: %q", s)
	}
}

func TestEntryBodyHTTP(t *testing.T) {
	body, err := entryBody("http", "http://127.0.0.1:2121/mcp/", false)
	if err != nil {
		t.Fatal(err)
	}
	if body["url"] != "http://127.0.0.1:2121/mcp/" {
		t.Fatalf("%v", body)
	}
}

func TestEntryBodyStdioNpx(t *testing.T) {
	body, err := entryBody("stdio", "http://ignored/mcp/", true)
	if err != nil {
		t.Fatal(err)
	}
	if body["command"] != "npx" {
		t.Fatalf("command=%v", body["command"])
	}
}

func TestMergeYAMLPreservesOtherServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("model: keep\nmcp_servers:\n  other:\n    url: http://x/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := hostSpec{Name: "hermes", Wrapper: []string{"mcp_servers"}, Format: "yaml", Verified: true}
	u := "http://127.0.0.1:2121/mcp/"
	if err := mergeYAMLConfig(path, h, "a2al", map[string]any{"url": u}, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	s := string(b)
	if !strings.Contains(s, "model: keep") || !strings.Contains(s, "other:") || !strings.Contains(s, u) {
		t.Fatalf("merge lost data:\n%s", s)
	}
}

func TestMergeYAMLDropsCommandWhenWritingURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("mcp_servers:\n  a2al:\n    command: a2ald\n    args: [\"--mcp-stdio\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := hostSpec{Name: "hermes", Wrapper: []string{"mcp_servers"}, Format: "yaml", Verified: true}
	if err := mergeYAMLConfig(path, h, "a2al", map[string]any{"url": "http://127.0.0.1:2121/mcp/"}, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	s := string(b)
	if strings.Contains(s, "command:") || strings.Contains(s, "args:") {
		t.Fatalf("hermes forbids command and url together:\n%s", s)
	}
}

func TestMergeDSHCordisAppendsWithoutClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cordis.patch.yml")
	orig := "# keep me\n- insert:\n    - id: other-row\n      name: other\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	u := "http://127.0.0.1:2121/mcp/"
	if err := mergeDSHCordis(path, "a2al", map[string]any{"url": u}, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	s := string(b)
	if !strings.Contains(s, "# keep me") || !strings.Contains(s, "id: other-row") {
		t.Fatalf("existing patch clobbered:\n%s", s)
	}
	if !strings.Contains(s, "id: mcp-a2al") || !strings.Contains(s, dshMCPClient) {
		t.Fatalf("insert missing:\n%s", s)
	}
	if !strings.Contains(s, "transport: streamable-http") || !strings.Contains(s, u) {
		t.Fatalf("http fields missing:\n%s", s)
	}
}

func TestMergeDSHCordisUpdatesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cordis.patch.yml")
	orig := "- insert:\n    - id: mcp-a2al\n      name: '@deepseek-ai/dsh-mcp-client'\n      config:\n        serverName: a2al\n        transport: streamable-http\n        url: http://old/\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	u := "http://127.0.0.1:2121/mcp/"
	if err := mergeDSHCordis(path, "a2al", map[string]any{"url": u}, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	s := string(b)
	if strings.Contains(s, "http://old/") || strings.Count(s, "id: mcp-a2al") != 1 {
		t.Fatalf("expected one updated row:\n%s", s)
	}
	if !strings.Contains(s, u) {
		t.Fatalf("url not updated:\n%s", s)
	}
}

func TestApplyHostInteractiveWritesFileNotCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("mcp_servers: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := hostSpec{
		Name:        "hermes",
		CLI:         []string{"go", "mcp", "add", "--url", "{URL}", "{NAME}"},
		Interactive: true,
		Paths:       []string{path},
		Wrapper:     []string{"mcp_servers"},
		Format:      "yaml",
		Verified:    true,
	}
	u := "http://127.0.0.1:2121/mcp/"
	if err := applyHost(h, "a2al", map[string]any{"url": u}, u, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), u) {
		t.Fatalf("not written:\n%s", b)
	}
}

func TestExpandPathDSHHome(t *testing.T) {
	t.Setenv("DSH_HOME", `D:\dsh-home`)
	got := expandPath("{DSH_HOME}/cordis.patch.yml")
	want := filepath.Join(`D:\dsh-home`, "cordis.patch.yml")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	t.Setenv("DSH_HOME", "")
	if expandPath("{DSH_HOME}/cordis.patch.yml") != "" {
		t.Fatal("empty DSH_HOME must drop the path")
	}
}
