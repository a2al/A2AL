// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (d *daemon) mcpHTTPHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return d.mcpInstance()
	}, nil)
}

func (d *daemon) mcpInstance() *mcp.Server {
	d.mcpOnce.Do(func() {
		d.mcpSrv = buildMCPServer(d)
	})
	return d.mcpSrv
}

func buildMCPServer(d *daemon) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "a2ald", Title: "A2AL Daemon", Version: "0.1"}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_identity_generate",
		Description: "Generate master + operational Ed25519 keys and delegation proof (POST /identity/generate).",
	}, d.mcpIdentityGenerate)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agents_list",
		Description: "List registered agents (GET /agents).",
	}, d.mcpAgentsList)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_register",
		Description: "Register an agent with delegation proof and reachable service_tcp (POST /agents).",
	}, d.mcpAgentRegister)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_get",
		Description: "Get agent status: service_tcp, seq, reachability, published DHT fields (GET /agents/{aid}).",
	}, d.mcpAgentGet)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_patch",
		Description: "Update service_tcp for a registered agent; requires operational_private_key_hex (PATCH /agents/{aid}).",
	}, d.mcpAgentPatch)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_publish",
		Description: "Publish endpoint record for an agent to the DHT (POST /agents/{aid}/publish).",
	}, d.mcpAgentPublish)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_resolve",
		Description: "Resolve an AID to signed endpoint record (POST /resolve/{aid}).",
	}, d.mcpResolve)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_connect",
		Description: "Open local TCP tunnel to remote agent via QUIC (POST /connect/{aid}); optional local_aid.",
	}, d.mcpConnect)

	return s
}

func structToMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (d *daemon) mcpIdentityGenerate(ctx context.Context, _ *mcp.ServerSession, _ *mcp.CallToolParamsFor[struct{}]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	out, err := d.execIdentityGenerate()
	if err != nil {
		return nil, err
	}
	m, err := structToMap(out)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: m}, nil
}

func (d *daemon) mcpAgentsList(ctx context.Context, _ *mcp.ServerSession, _ *mcp.CallToolParamsFor[struct{}]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	agents := d.execAgentsList()
	return &mcp.CallToolResultFor[map[string]any]{
		StructuredContent: map[string]any{"agents": agents},
	}, nil
}

type mcpRegisterArgs struct {
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	ServiceTCP               string `json:"service_tcp"`
}

func (d *daemon) mcpAgentRegister(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpRegisterArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	req := registerAgentReq{
		OperationalPrivateKeyHex: params.Arguments.OperationalPrivateKeyHex,
		DelegationProofHex:       params.Arguments.DelegationProofHex,
		ServiceTCP:               params.Arguments.ServiceTCP,
	}
	aid, err := d.execAgentRegister(req)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{
		StructuredContent: map[string]any{"aid": aid.String(), "status": "registered"},
	}, nil
}

func (d *daemon) mcpAgentGet(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	gctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := d.execAgentGet(gctx, params.Arguments.AID)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: out}, nil
}

type mcpPatchArgs struct {
	AID                      string `json:"aid"`
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	ServiceTCP               string `json:"service_tcp"`
}

func (d *daemon) mcpAgentPatch(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpPatchArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	req := patchAgentReq{
		OperationalPrivateKeyHex: params.Arguments.OperationalPrivateKeyHex,
		ServiceTCP:               params.Arguments.ServiceTCP,
	}
	if err := d.execAgentPatch(params.Arguments.AID, req); err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{
		StructuredContent: map[string]any{"status": "updated"},
	}, nil
}

type mcpAIDArgs struct {
	AID string `json:"aid"`
}

func (d *daemon) mcpAgentPublish(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	seq, err := d.execAgentPublish(pctx, params.Arguments.AID)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{
		StructuredContent: map[string]any{"ok": true, "seq": seq},
	}, nil
}

func (d *daemon) mcpResolve(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := d.execResolve(rctx, params.Arguments.AID)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: out}, nil
}

type mcpConnectArgs struct {
	RemoteAID string `json:"remote_aid"`
	LocalAID  string `json:"local_aid,omitempty"`
}

func (d *daemon) mcpConnect(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpConnectArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	body := connectReq{LocalAID: params.Arguments.LocalAID}
	tun, err := d.execConnect(cctx, params.Arguments.RemoteAID, body)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{
		StructuredContent: map[string]any{"tunnel": tun},
	}, nil
}

func mcpRunErr(err error) bool {
	return err != nil && !errors.Is(err, context.Canceled)
}
