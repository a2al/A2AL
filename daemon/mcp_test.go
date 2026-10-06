// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
	"a2al_agent_probe",
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
	"a2al_mailbox_list",
	"a2al_mailbox_poll",
	"a2al_service_register",
	"a2al_service_unregister",
	"a2al_discover",
	"a2al_fetch",
	"a2al_tunnel_open",
	"a2al_tunnel_close",
	"a2al_tunnel_list",
	"group_create",
	"group_list",
	"group_invite",
	"group_append",
	"group_read",
	"group_head",
	"group_sync",
	"group_join",
	"group_members",
	"group_mark_read",
	"group_object_put",
	"group_object_get",
	"group_object_locate",
	"group_get_link",
	"group_retract",
	"chat_request",
	"chat_accept",
	"chat_refuse",
	"chat_remove",
	"chat_block",
	"chat_send",
	"chat_read",
	"chat_mark_read",
	"chat_contacts",
	"a2al_events_poll",
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
	if sc["node_aid"] != d.nodeAddr.String() {
		t.Errorf("node_aid=%v want %s", sc["node_aid"], d.nodeAddr)
	}
	for _, key := range []string{"tunnel_active_count", "tunnel_bytes_up_total", "tunnel_bytes_down_total", "uptime_seconds", "network_ready", "update_enabled"} {
		if _, ok := sc[key]; !ok {
			t.Errorf("missing field %q in status response", key)
		}
	}
	if n, ok := sc["tunnel_active_count"].(float64); !ok || n != 0 {
		t.Errorf("tunnel_active_count=%v want 0", sc["tunnel_active_count"])
	}
}

func TestMCP_tunnelList_empty(t *testing.T) {
	d := newTestDaemon(t)
	cs := newMCPClientSession(t, buildMCPServer(d))

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "a2al_tunnel_list",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %v", res.Content)
	}
	sc := res.StructuredContent.(map[string]any)
	tunnels, ok := sc["tunnels"].([]any)
	if !ok {
		t.Fatalf("tunnels=%T want []any", sc["tunnels"])
	}
	if len(tunnels) != 0 {
		t.Fatalf("tunnels len=%d want 0", len(tunnels))
	}
}

func TestMCP_tunnelOpen_portInUse(t *testing.T) {
	d := newTestDaemon(t)
	remote := newTestAddr(t)
	other := newTestAddr(t)
	d.tunnels.add(&tunnelEntry{
		id: "other", localAID: d.nodeAddr, remoteAID: other, listen: "127.0.0.1:18192",
	})
	_, err := d.mcpTunnelOpen(context.Background(), nil, &mcp.CallToolParamsFor[mcpTunnelOpenArgs]{
		Arguments: mcpTunnelOpenArgs{RemoteAID: remote.String(), LocalPort: 18192},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "18192") {
		t.Fatalf("want port in error, got %v", err)
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

func TestMCP_objectPutLocateGet(t *testing.T) {
	d := newTestDaemon(t)
	cs := newMCPClientSession(t, buildMCPServer(d))
	src := filepath.Join(t.TempDir(), "blob.txt")
	if err := os.WriteFile(src, []byte("object-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	aid := d.nodeAddr.String()
	put, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "group_object_put",
		Arguments: map[string]any{"aid": aid, "path": src},
	})
	if err != nil || put.IsError {
		t.Fatalf("put: err=%v isError=%v %v", err, put != nil && put.IsError, put)
	}
	sc := put.StructuredContent.(map[string]any)
	oid, _ := sc["object_id"].(string)
	if oid == "" || sc["name"] != "blob.txt" {
		t.Fatalf("put result %#v", sc)
	}

	loc, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "group_object_locate",
		Arguments: map[string]any{"aid": aid, "object_id": oid},
	})
	if err != nil || loc.IsError {
		t.Fatalf("locate: %v", err)
	}
	lsc := loc.StructuredContent.(map[string]any)
	if lsc["status"] != "available" {
		t.Fatalf("status %#v", lsc)
	}

	dest := filepath.Join(t.TempDir(), "out.txt")
	got, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "group_object_get",
		Arguments: map[string]any{
			"aid": aid, "object_id": oid, "dest": dest, "register": true,
		},
	})
	if err != nil || got.IsError {
		t.Fatalf("get: %v %#v", err, got)
	}
	b, err := os.ReadFile(dest)
	if err != nil || string(b) != "object-bytes" {
		t.Fatalf("dest %q err=%v", b, err)
	}
}
