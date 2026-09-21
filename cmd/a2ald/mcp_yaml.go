// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const dshMCPClient = "@deepseek-ai/dsh-mcp-client"

func marshalYAML(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeWithBackup(path string, raw []byte, readErr error, out []byte, name string, dryRun bool) error {
	if dryRun {
		fmt.Fprintf(os.Stderr, "%-15s would write %s:\n%s\n", name, path, out)
		return nil
	}
	if readErr == nil {
		if err := os.WriteFile(path+".bak", raw, 0o600); err != nil {
			return fmt.Errorf("backup %s: %w", path+".bak", err)
		}
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%-15s wrote %s\n", name, path)
	return nil
}

// mergeYAMLConfig inserts the entry at h.Wrapper in a YAML mapping, preserving
// sibling keys. Hermes documents ~/.hermes/config.yaml / mcp_servers / url.
func mergeYAMLConfig(path string, h hostSpec, name string, body map[string]any, dryRun bool) error {
	root := map[string]any{}
	raw, readErr := os.ReadFile(path)
	if readErr == nil && len(strings.TrimSpace(string(raw))) > 0 {
		if err := yaml.Unmarshal(raw, &root); err != nil {
			return fmt.Errorf("%s is not valid YAML (%v) - not touching it", path, err)
		}
		if root == nil {
			root = map[string]any{}
		}
	}

	wrapper := h.Wrapper
	if len(wrapper) == 0 {
		wrapper = []string{"mcp_servers"}
	}

	node := root
	for _, key := range wrapper {
		child, ok := asStringMap(node[key])
		if !ok {
			if _, exists := node[key]; exists {
				return fmt.Errorf("%s: %q is not a mapping - not touching it", path, key)
			}
			if !h.Verified {
				return fmt.Errorf("%s exists but has no %q; this host's layout is unconfirmed, so nothing was written - write the entry yourself or pass --config", path, strings.Join(wrapper, "."))
			}
			child = map[string]any{}
			node[key] = child
		}
		node = child
	}

	if existing, ok := asStringMap(node[name]); ok {
		merged := overlayMCPBody(existing, body)
		if bytes.Equal(mustYAML(existing), mustYAML(merged)) {
			fmt.Fprintf(os.Stderr, "%-15s unchanged (%s)\n", h.Name, path)
			return nil
		}
		fmt.Fprintf(os.Stderr, "%-15s replacing existing %q entry (%s)\n", h.Name, name, path)
		node[name] = merged
	} else if _, exists := node[name]; exists {
		fmt.Fprintf(os.Stderr, "%-15s replacing existing %q entry (%s)\n", h.Name, name, path)
		node[name] = body
	} else {
		node[name] = body
	}

	out, err := marshalYAML(root)
	if err != nil {
		return err
	}
	return writeWithBackup(path, raw, readErr, out, h.Name, dryRun)
}

func overlayMCPBody(existing, body map[string]any) map[string]any {
	out := cloneMap(existing)
	for k, v := range body {
		out[k] = v
	}
	if _, ok := body["url"]; ok {
		delete(out, "command")
		delete(out, "args")
		delete(out, "cwd")
		delete(out, "env")
	}
	if _, ok := body["command"]; ok {
		delete(out, "url")
		delete(out, "headers")
	}
	return out
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mustYAML(v any) []byte {
	b, _ := yaml.Marshal(v)
	return b
}

// mergeDSHCordis inserts or updates an @deepseek-ai/dsh-mcp-client row in a
// Cordis patch list. Official persist path is $DSH_HOME/cordis.patch.yml
// (default ~/.dsh/cordis.patch.yml). Existing patches are not replaced: a first
// add appends; a later add with the same id updates that row only.
func mergeDSHCordis(path, name string, body map[string]any, dryRun bool) error {
	id := "mcp-" + name
	cfg := dshClientConfig(name, body)
	item := dshInsertItem(id, cfg)

	raw, readErr := os.ReadFile(path)
	exists := readErr == nil

	if exists && len(strings.TrimSpace(string(raw))) > 0 && dshHasID(raw, id) {
		var list []any
		if err := yaml.Unmarshal(raw, &list); err != nil {
			return fmt.Errorf("%s is not a YAML list (%v) - not touching it", path, err)
		}
		if !dshUpdateInsert(list, id, cfg) {
			list = append(list, item)
		}
		out, err := marshalYAML(list)
		if err != nil {
			return err
		}
		return writeWithBackup(path, raw, nil, out, "deepseek-harness", dryRun)
	}

	block, err := marshalYAML([]any{item})
	if err != nil {
		return err
	}
	var out []byte
	if exists && len(strings.TrimSpace(string(raw))) > 0 {
		out = raw
		if !bytes.HasSuffix(out, []byte("\n")) {
			out = append(out, '\n')
		}
		out = append(out, block...)
	} else {
		out = block
		readErr = os.ErrNotExist
		raw = nil
	}
	return writeWithBackup(path, raw, readErr, out, "deepseek-harness", dryRun)
}

func dshClientConfig(name string, body map[string]any) map[string]any {
	cfg := map[string]any{"serverName": name}
	if cmd, ok := body["command"]; ok {
		cfg["transport"] = "stdio"
		cfg["command"] = cmd
		if args, ok := body["args"]; ok {
			cfg["args"] = args
		}
		return cfg
	}
	cfg["transport"] = "streamable-http"
	if u, ok := body["url"]; ok {
		cfg["url"] = u
	} else if u, ok := body["serverUrl"]; ok {
		cfg["url"] = u
	}
	return cfg
}

func dshInsertItem(id string, cfg map[string]any) map[string]any {
	return map[string]any{
		"insert": []any{
			map[string]any{
				"id":     id,
				"name":   dshMCPClient,
				"config": cfg,
			},
		},
	}
}

func dshHasID(raw []byte, id string) bool {
	s := string(raw)
	for _, pat := range []string{
		"id: " + id,
		"id: \"" + id + "\"",
		"id: '" + id + "'",
	} {
		if strings.Contains(s, pat) {
			return true
		}
	}
	return false
}

func dshUpdateInsert(list []any, id string, cfg map[string]any) bool {
	for _, item := range list {
		m, ok := asStringMap(item)
		if !ok {
			continue
		}
		rows, ok := asSlice(m["insert"])
		if !ok {
			continue
		}
		for _, row := range rows {
			rm, ok := asStringMap(row)
			if !ok {
				continue
			}
			if fmt.Sprint(rm["id"]) == id {
				rm["name"] = dshMCPClient
				rm["config"] = cfg
				return true
			}
		}
	}
	return false
}

func asStringMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	default:
		return nil, false
	}
}

func asSlice(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	default:
		return nil, false
	}
}
