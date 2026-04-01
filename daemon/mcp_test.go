// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// allExpectedTools lists every MCP tool the daemon must expose.
var allExpectedTools = []string{
	"a2al_identity_generate",
	"a2al_agents_list",
	"a2al_agents_generate_ethereum",
	"a2al_ethereum_delegation_message",
	"a2al_ethereum_register",
	"a2al_ethereum_proof",
	"a2al_agent_register",
	"a2al_agent_get",
	"a2al_agent_patch",
	"a2al_agent_publish",
	"a2al_agent_heartbeat",
	"a2al_agent_delete",
	"a2al_agent_publish_record",
	"a2al_status",
	"a2al_resolve_records",
	"a2al_resolve",
	"a2al_connect",
	"a2al_mailbox_send",
	"a2al_mailbox_poll",
	"a2al_service_register",
	"a2al_service_unregister",
	"a2al_discover",
}

// newMCPClientSession returns a ClientSession connected to the given server
// over an in-memory transport. The session is closed when t completes.
func newMCPClientSession(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st); err != nil {
		t.Fatal(err)
	}
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := c.Connect(ctx, ct)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestMCP_allToolsRegistered(t *testing.T) {
	d := newTestDaemon(t)
	cs := newMCPClientSession(t, buildMCPServer(d))

	res, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]bool, len(allExpectedTools))
	for _, n := range allExpectedTools {
		want[n] = true
	}
	got := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	for _, name := range allExpectedTools {
		if !got[name] {
			t.Errorf("missing tool: %s", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("unexpected extra tool: %s", name)
		}
	}
}

func TestMCP_identityGenerate(t *testing.T) {
	d := newTestDaemon(t)
	cs := newMCPClientSession(t, buildMCPServer(d))

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "a2al_identity_generate",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %v", res.Content)
	}
	sc := res.StructuredContent.(map[string]any)
	for _, key := range []string{"aid", "master_private_key_hex", "operational_private_key_hex", "delegation_proof_hex"} {
		if sc[key] == "" || sc[key] == nil {
			t.Errorf("missing or empty field %q in response", key)
		}
	}
}

func TestMCP_agentsList_empty(t *testing.T) {
	d := newTestDaemon(t)
	cs := newMCPClientSession(t, buildMCPServer(d))

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "a2al_agents_list",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %v", res.Content)
	}
	sc := res.StructuredContent.(map[string]any)
	if _, ok := sc["agents"]; !ok {
		t.Fatal("missing 'agents' key")
	}
}

func TestMCP_status(t *testing.T) {
	d := newTestDaemon(t)
	cs := newMCPClientSession(t, buildMCPServer(d))

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "a2al_status",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %v", res.Content)
	}
	sc := res.StructuredContent.(map[string]any)
	if sc["node_aid"] == nil || sc["node_aid"] == "" {
		t.Errorf("missing node_aid in status response")
	}
}

func TestMCP_agentHeartbeat_notRegistered(t *testing.T) {
	d := newTestDaemon(t)
	cs := newMCPClientSession(t, buildMCPServer(d))

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "a2al_agent_heartbeat",
		Arguments: map[string]any{"aid": d.nodeAddr.String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected tool error for unregistered agent, got success")
	}
}

func TestMCP_agentDelete_notRegistered(t *testing.T) {
	d := newTestDaemon(t)
	cs := newMCPClientSession(t, buildMCPServer(d))

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "a2al_agent_delete",
		Arguments: map[string]any{"aid": d.nodeAddr.String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected tool error for unregistered agent, got success")
	}
}
