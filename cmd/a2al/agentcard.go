// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// topicDraft maps to daemon topicRegisterReq fields (subset).
type topicDraft struct {
	Name      string
	Brief     string
	Protocols []string
	Tags      []string
	URL       string
}

func fetchAgentCardDraft(from string) (*topicDraft, string, error) {
	if strings.HasPrefix(from, "http://") || strings.HasPrefix(from, "https://") {
		return fetchAgentCardFromURL(from)
	}
	b, err := os.ReadFile(from)
	if err != nil {
		return nil, "", err
	}
	d, kind, err := parseAgentCardJSON(b)
	if err != nil {
		return nil, "", err
	}
	return d, "file (" + kind + ")", nil
}

func fetchAgentCardFromURL(base string) (*topicDraft, string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	try := func(rel string) ([]byte, error) {
		u, err := url.Parse(base)
		if err != nil {
			return nil, err
		}
		ref, err := url.Parse(rel)
		if err != nil {
			return nil, err
		}
		full := u.ResolveReference(ref)
		req, err := http.NewRequest(http.MethodGet, full.String(), nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("http %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	if b, err := try("/.well-known/agent.json"); err == nil {
		d, _, err := parseAgentCardJSON(b)
		if err == nil {
			if d.URL == "" {
				d.URL = strings.TrimRight(base, "/")
			}
			return d, "A2A Agent Card", nil
		}
	}
	if b, err := try("/.well-known/mcp.json"); err == nil {
		d, _, err := parseAgentCardJSON(b)
		if err == nil {
			return d, "MCP Server Card", nil
		}
	}
	return nil, "", fmt.Errorf("could not fetch agent.json or mcp.json from %s", base)
}

func parseAgentCardJSON(b []byte) (*topicDraft, string, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, "", err
	}
	// Heuristic: A2A has "skills", MCP often has "capabilities" / serverInfo
	_, a2a := root["skills"]
	_, mcp := root["capabilities"]
	switch {
	case a2a:
		d, err := parseA2ACard(root)
		return d, "a2a", err
	case mcp:
		d, err := parseMCPCard(root)
		return d, "mcp", err
	default:
		// Try A2A shape without skills (minimal card)
		if _, ok := root["name"]; ok {
			d, err := parseA2ACard(root)
			return d, "a2a", err
		}
		if _, ok := root["title"]; ok {
			d, err := parseMCPCard(root)
			return d, "mcp", err
		}
		return nil, "", fmt.Errorf("unrecognized agent card JSON")
	}
}

func parseA2ACard(root map[string]json.RawMessage) (*topicDraft, error) {
	var name, desc, cardURL string
	_ = json.Unmarshal(root["name"], &name)
	_ = json.Unmarshal(root["description"], &desc)
	_ = json.Unmarshal(root["url"], &cardURL)
	var tags []string
	if raw, ok := root["skills"]; ok {
		var skills []struct {
			Tags []string `json:"tags"`
		}
		if json.Unmarshal(raw, &skills) == nil {
			for _, s := range skills {
				tags = append(tags, s.Tags...)
			}
		}
	}
	return &topicDraft{
		Name:      name,
		Brief:     truncateRunes(desc, 200),
		Protocols: []string{"a2a"},
		Tags:      tags,
		URL:       cardURL,
	}, nil
}

func parseMCPCard(root map[string]json.RawMessage) (*topicDraft, error) {
	var name, title, desc string
	_ = json.Unmarshal(root["name"], &name)
	_ = json.Unmarshal(root["title"], &title)
	_ = json.Unmarshal(root["description"], &desc)
	if name == "" {
		name = title
	}
	return &topicDraft{
		Name:      name,
		Brief:     truncateRunes(desc, 200),
		Protocols: []string{"mcp"},
	}, nil
}

func truncateRunes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	// byte truncate ok for brief limit per spec suggestion
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}
