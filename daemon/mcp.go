// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (d *Daemon) mcpHTTPHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return d.mcpInstance()
	}, nil)
}

func (d *Daemon) mcpInstance() *mcp.Server {
	d.mcpOnce.Do(func() {
		d.mcpSrv = buildMCPServer(d)
	})
	return d.mcpSrv
}

func buildMCPServer(d *Daemon) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "a2ald", Title: "A2AL Daemon", Version: "0.1"}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_identity_generate",
		Description: "Generate master + operational Ed25519 keys and delegation proof.",
	}, d.mcpIdentityGenerate)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agents_list",
		Description: "List registered agents.",
	}, d.mcpAgentsList)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_register",
		Description: "Register an agent with delegation proof and reachable service_tcp.",
	}, d.mcpAgentRegister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_get",
		Description: "Get agent status: service_tcp, seq, reachability, published DHT fields.",
	}, d.mcpAgentGet)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_patch",
		Description: "Update service_tcp for a registered agent; requires operational_private_key_hex.",
	}, d.mcpAgentPatch)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_publish",
		Description: "Publish endpoint record for an agent to the DHT.",
	}, d.mcpAgentPublish)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_publish_record",
		Description: "Publish sovereign custom DHT record RecType 0x02-0x0f.",
	}, d.mcpAgentPublishRecord)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_resolve_records",
		Description: "List signed records for a remote AID (type 0 = all).",
	}, d.mcpResolveRecords)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_resolve",
		Description: "Resolve an AID to its signed endpoint record.",
	}, d.mcpResolve)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_connect",
		Description: "Open local TCP tunnel to remote agent via QUIC; optional local_aid.",
	}, d.mcpConnect)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_mailbox_send",
		Description: "Send encrypted DHT mailbox message.",
	}, d.mcpMailboxSend)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_mailbox_poll",
		Description: "Poll and decrypt mailbox for a registered agent.",
	}, d.mcpMailboxPoll)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_topic_register",
		Description: "Register DHT topic discovery entries for an agent.",
	}, d.mcpTopicRegister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_topic_unregister",
		Description: "Remove a topic from agent renewal list; DHT TTL expires naturally.",
	}, d.mcpTopicUnregister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_discover",
		Description: "Search agents by topic(s) on the DHT.",
	}, d.mcpDiscover)

	return s
}

func (d *Daemon) mcpIdentityGenerate(ctx context.Context, _ *mcp.ServerSession, _ *mcp.CallToolParamsFor[struct{}]) (*mcp.CallToolResultFor[map[string]any], error) {
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

func (d *Daemon) mcpAgentsList(ctx context.Context, _ *mcp.ServerSession, _ *mcp.CallToolParamsFor[struct{}]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	return &mcp.CallToolResultFor[map[string]any]{
		StructuredContent: map[string]any{"agents": d.execAgentsList()},
	}, nil
}

type mcpRegisterArgs struct {
	OperationalPrivateKeyHex string `json:"operational_private_key_hex"`
	DelegationProofHex       string `json:"delegation_proof_hex"`
	ServiceTCP               string `json:"service_tcp"`
}

func (d *Daemon) mcpAgentRegister(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpRegisterArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	aid, err := d.execAgentRegister(registerAgentReq{
		OperationalPrivateKeyHex: params.Arguments.OperationalPrivateKeyHex,
		DelegationProofHex:       params.Arguments.DelegationProofHex,
		ServiceTCP:               params.Arguments.ServiceTCP,
	})
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{
		StructuredContent: map[string]any{"aid": aid.String(), "status": "registered"},
	}, nil
}

type mcpAIDArgs struct {
	AID string `json:"aid"`
}

func (d *Daemon) mcpAgentGet(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
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

func (d *Daemon) mcpAgentPatch(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpPatchArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	if err := d.execAgentPatch(params.Arguments.AID, patchAgentReq{
		OperationalPrivateKeyHex: params.Arguments.OperationalPrivateKeyHex,
		ServiceTCP:               params.Arguments.ServiceTCP,
	}); err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"status": "updated"}}, nil
}

func (d *Daemon) mcpAgentPublish(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	seq, err := d.execAgentPublish(pctx, params.Arguments.AID)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"ok": true, "seq": seq}}, nil
}

type mcpPublishRecordArgs struct {
	AID           string `json:"aid"`
	RecType       uint8  `json:"rec_type"`
	PayloadBase64 string `json:"payload_base64"`
	TTL           uint32 `json:"ttl,omitempty"`
}

func (d *Daemon) mcpAgentPublishRecord(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpPublishRecordArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := d.execAgentPublishRecord(tctx, params.Arguments.AID, agentPublishRecordReq{
		RecType:       params.Arguments.RecType,
		PayloadBase64: params.Arguments.PayloadBase64,
		TTL:           params.Arguments.TTL,
	}); err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"ok": true}}, nil
}

type mcpResolveRecordsArgs struct {
	AID  string `json:"aid"`
	Type uint8  `json:"type"`
}

func (d *Daemon) mcpResolveRecords(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpResolveRecordsArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	records, err := d.execResolveRecords(rctx, params.Arguments.AID, params.Arguments.Type)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"records": records}}, nil
}

func (d *Daemon) mcpResolve(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
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

func (d *Daemon) mcpConnect(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpConnectArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	tun, err := d.execConnect(cctx, params.Arguments.RemoteAID, connectReq{LocalAID: params.Arguments.LocalAID})
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"tunnel": tun}}, nil
}

type mcpMailboxSendArgs struct {
	AID        string `json:"aid"`
	Recipient  string `json:"recipient"`
	MsgType    uint8  `json:"msg_type"`
	BodyBase64 string `json:"body_base64"`
}

func (d *Daemon) mcpMailboxSend(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpMailboxSendArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	if params.Arguments.Recipient == "" {
		return nil, errors.New("recipient required")
	}
	raw, err := base64.StdEncoding.DecodeString(params.Arguments.BodyBase64)
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := d.execMailboxSend(sctx, params.Arguments.AID, params.Arguments.Recipient, params.Arguments.MsgType, raw); err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"ok": true}}, nil
}

func (d *Daemon) mcpMailboxPoll(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	msgs, err := d.execMailboxPoll(pctx, params.Arguments.AID)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"messages": msgs}}, nil
}

type mcpTopicRegisterArgs struct {
	AID       string         `json:"aid"`
	Topics    []string       `json:"topics"`
	Name      string         `json:"name"`
	Protocols []string       `json:"protocols"`
	Tags      []string       `json:"tags"`
	Brief     string         `json:"brief"`
	Meta      map[string]any `json:"meta,omitempty"`
	TTL       uint32         `json:"ttl"`
}

func (d *Daemon) mcpTopicRegister(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpTopicRegisterArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	a := params.Arguments
	if err := d.execTopicRegister(tctx, a.AID, topicRegisterReq{
		Topics: a.Topics, Name: a.Name, Protocols: a.Protocols,
		Tags: a.Tags, Brief: a.Brief, Meta: a.Meta, TTL: a.TTL,
	}); err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"ok": true}}, nil
}

type mcpTopicUnregisterArgs struct {
	AID   string `json:"aid"`
	Topic string `json:"topic"`
}

func (d *Daemon) mcpTopicUnregister(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpTopicUnregisterArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	if params.Arguments.Topic == "" {
		return nil, errors.New("topic required")
	}
	if err := d.execTopicUnregister(params.Arguments.AID, params.Arguments.Topic); err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"ok": true}}, nil
}

func (d *Daemon) mcpDiscover(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[discoverReq]) (*mcp.CallToolResultFor[map[string]any], error) {
	dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	entries, err := d.execDiscover(dctx, params.Arguments)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"entries": entries}}, nil
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
