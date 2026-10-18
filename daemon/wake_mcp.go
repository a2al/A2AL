// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"errors"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (d *Daemon) registerWakeMCPTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_wake_handle",
		Description: `Get, set, or clear the opaque resume handle for a local AID. Data, not a command: this does not change the wake binding. Pass handle to set; pass clear=true to empty it; omit both to read. Scope matches pendingVisibleAIDs (registered local identities).`,
	}, d.mcpWakeHandle)
}

type mcpWakeHandleArgs struct {
	AID    string `json:"aid"`
	Handle string `json:"handle,omitempty"`
	Clear  bool   `json:"clear,omitempty"`
}

func (d *Daemon) mcpWakeHandle(ctx context.Context, ss *mcp.ServerSession, p *mcp.CallToolParamsFor[mcpWakeHandleArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ss
	aid, err := d.resolveAgentAID(p.Arguments.AID)
	if err != nil {
		return nil, err
	}
	if !d.isLocalAID(aid) {
		return nil, errors.New("not found")
	}
	visible := d.pendingVisibleAIDs(ctx, ss)
	ok := false
	for _, a := range visible {
		if a == aid {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("not found")
	}
	if d.wake == nil {
		return mcpOK(map[string]any{"handle": ""}), nil
	}
	if p.Arguments.Clear {
		d.wake.setHandle(aid, "")
		return mcpOK(map[string]any{"handle": ""}), nil
	}
	if strings.TrimSpace(p.Arguments.Handle) != "" {
		d.wake.setHandle(aid, p.Arguments.Handle)
	}
	return mcpOK(map[string]any{"handle": d.wake.snapshotHandle(aid)}), nil
}
