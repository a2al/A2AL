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
		Name:        "a2al_agents_generate_ethereum",
		Description: "Generate Ethereum AID (0x…), secp256k1 owner key, Ed25519 op key, and EIP-191 delegation proof; keys are not stored by the daemon.",
	}, d.mcpAgentsGenerateEthereum)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_ethereum_delegation_message",
		Description: "Build UTF-8 text for wallet personal_sign. Use operational_public_key_hex OR operational_private_key_seed_hex (exactly one), agent 0x address, issued_at, expires_at.",
	}, d.mcpEthereumDelegationMessage)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_ethereum_register",
		Description: "Register after EIP-191 signature: eth_signature_hex, agent, timestamps, service_tcp, operational_private_key_hex OR operational_private_key_seed_hex.",
	}, d.mcpEthereumRegister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_ethereum_proof",
		Description: "Create DelegationProof CBOR using ethereum_private_key_hex (automation only). Optional op keys; if omitted a new Ed25519 op key is generated and returned.",
	}, d.mcpEthereumProof)
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
		Name:        "a2al_agent_heartbeat",
		Description: "Record agent liveness for auto-republish (within TTL); use when service is not on local service_tcp.",
	}, d.mcpAgentHeartbeat)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_delete",
		Description: "Unregister agent: remove from registry, stop auto-republish, delete operational key.",
	}, d.mcpAgentDelete)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_status",
		Description: "Return node auto-publish status: auto_publish flag, node_aid, node_seq, last and next publish timestamps.",
	}, d.mcpStatus)
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
		Name:        "a2al_service_register",
		Description: "Register DHT service discovery entries for an agent.",
	}, d.mcpTopicRegister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_service_unregister",
		Description: "Remove a service from agent renewal list; DHT TTL expires naturally.",
	}, d.mcpTopicUnregister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_discover",
		Description: "Search agents by service(s) on the DHT.",
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

type mcpEthDelMsgArgs struct {
	OperationalPublicKeyHex      string `json:"operational_public_key_hex,omitempty"`
	OperationalPrivateKeySeedHex string `json:"operational_private_key_seed_hex,omitempty"`
	Agent                        string `json:"agent"`
	IssuedAt                     uint64 `json:"issued_at"`
	ExpiresAt                    uint64 `json:"expires_at"`
	Scope                        uint8  `json:"scope,omitempty"`
}

func (d *Daemon) mcpEthereumDelegationMessage(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpEthDelMsgArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	msg, err := d.execEthereumDelegationMessage(params.Arguments.OperationalPublicKeyHex, params.Arguments.OperationalPrivateKeySeedHex, params.Arguments.Agent, params.Arguments.IssuedAt, params.Arguments.ExpiresAt, params.Arguments.Scope)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"message": msg}}, nil
}

type mcpEthRegisterArgs struct {
	Agent                        string `json:"agent"`
	IssuedAt                     uint64 `json:"issued_at"`
	ExpiresAt                    uint64 `json:"expires_at"`
	Scope                        uint8  `json:"scope,omitempty"`
	EthSignatureHex              string `json:"eth_signature_hex"`
	ServiceTCP                   string `json:"service_tcp"`
	OperationalPrivateKeyHex     string `json:"operational_private_key_hex,omitempty"`
	OperationalPrivateKeySeedHex string `json:"operational_private_key_seed_hex,omitempty"`
}

func (d *Daemon) mcpEthereumRegister(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpEthRegisterArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	a := params.Arguments
	aid, err := d.execEthereumRegister(a.Agent, a.IssuedAt, a.ExpiresAt, a.Scope, a.EthSignatureHex, a.ServiceTCP, a.OperationalPrivateKeyHex, a.OperationalPrivateKeySeedHex)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"aid": aid.String(), "status": "registered"}}, nil
}

type mcpEthProofArgs struct {
	EthereumPrivateKeyHex        string `json:"ethereum_private_key_hex"`
	IssuedAt                     uint64 `json:"issued_at"`
	ExpiresAt                    uint64 `json:"expires_at"`
	Scope                        uint8  `json:"scope,omitempty"`
	OperationalPrivateKeyHex     string `json:"operational_private_key_hex,omitempty"`
	OperationalPrivateKeySeedHex string `json:"operational_private_key_seed_hex,omitempty"`
}

func (d *Daemon) mcpEthereumProof(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpEthProofArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	a := params.Arguments
	out, err := d.execEthereumProofFromKey(a.EthereumPrivateKeyHex, a.IssuedAt, a.ExpiresAt, a.Scope, a.OperationalPrivateKeyHex, a.OperationalPrivateKeySeedHex)
	if err != nil {
		return nil, err
	}
	m, err := structToMap(out)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: m}, nil
}

func (d *Daemon) mcpAgentsGenerateEthereum(ctx context.Context, _ *mcp.ServerSession, _ *mcp.CallToolParamsFor[struct{}]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	out, err := d.execEthereumIdentityGenerate()
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

func (d *Daemon) mcpAgentHeartbeat(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	if err := d.execAgentHeartbeat(params.Arguments.AID); err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"ok": true}}, nil
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
	AID      string         `json:"aid"`
	Services []string       `json:"services"`
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
		Services: a.Services, Name: a.Name, Protocols: a.Protocols,
		Tags: a.Tags, Brief: a.Brief, Meta: a.Meta, TTL: a.TTL,
	}); err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"ok": true}}, nil
}

type mcpTopicUnregisterArgs struct {
	AID     string `json:"aid"`
	Service string `json:"service"`
}

func (d *Daemon) mcpTopicUnregister(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpTopicUnregisterArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	if params.Arguments.Service == "" {
		return nil, errors.New("service required")
	}
	if err := d.execTopicUnregister(params.Arguments.AID, params.Arguments.Service); err != nil {
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

func (d *Daemon) mcpAgentDelete(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	if err := d.execAgentDelete(params.Arguments.AID); err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"ok": true}}, nil
}

func (d *Daemon) mcpStatus(ctx context.Context, _ *mcp.ServerSession, _ *mcp.CallToolParamsFor[struct{}]) (*mcp.CallToolResultFor[map[string]any], error) {
	_ = ctx
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: d.execStatus()}, nil
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
