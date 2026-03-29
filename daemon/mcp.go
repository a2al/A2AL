// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

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
		Description: "Create a new permanent cryptographic identity (AID) for an agent. Returns the AID address, keys, and delegation proof. Run once per agent; the master key is shown once and must be saved by the user — the daemon does not retain it.",
	}, d.mcpIdentityGenerate)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agents_list",
		Description: "List all agent identities currently registered with the daemon.",
	}, d.mcpAgentsList)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agents_generate_ethereum",
		Description: "Create a new agent identity linked to an Ethereum wallet address (0x…). Use when the user wants their crypto wallet to serve as their agent's identity. Keys are not stored by the daemon.",
	}, d.mcpAgentsGenerateEthereum)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_ethereum_delegation_message",
		Description: "Build the message text that the user must sign with their Ethereum wallet (personal_sign) to authorize an operational key. Provide the agent 0x address, operational key, and validity timestamps.",
	}, d.mcpEthereumDelegationMessage)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_ethereum_register",
		Description: "Complete Ethereum agent registration after the user has signed the delegation message with their wallet. Provide the signature, agent address, timestamps, service address, and operational key.",
	}, d.mcpEthereumRegister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_ethereum_proof",
		Description: "Create an Ethereum delegation proof from a raw private key (automation / scripting only — do not use when a human is signing). If no operational key is provided, a new one is generated and returned.",
	}, d.mcpEthereumProof)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_register",
		Description: "Register a generated agent identity with the daemon so it can publish to and connect via the Tangled Network. Requires the keys returned by identity_generate.",
	}, d.mcpAgentRegister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_get",
		Description: "Check a local agent's current status: service address, whether it is reachable on the network, and when it was last published.",
	}, d.mcpAgentGet)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_patch",
		Description: "Update the service address for a registered agent (e.g. after the local HTTP server moves to a different port).",
	}, d.mcpAgentPatch)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_publish",
		Description: "Announce an agent's current network address to the Tangled Network so other agents can discover and connect to it. The daemon auto-publishes on a schedule; call this to force an immediate refresh.",
	}, d.mcpAgentPublish)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_heartbeat",
		Description: "Keep a registered agent visible on the Tangled Network when it has no direct service address. Call periodically to prevent the agent from expiring off the network.",
	}, d.mcpAgentHeartbeat)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_delete",
		Description: "Permanently remove a local agent registration: stops auto-publish and deletes the operational key from the daemon.",
	}, d.mcpAgentDelete)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_status",
		Description: "Return the daemon's current status: this node's AID, whether auto-publish is enabled, and the last/next publish times.",
	}, d.mcpStatus)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_publish_record",
		Description: "Publish a custom signed data record for an agent on the Tangled Network (advanced use). Useful for attaching structured metadata beyond standard endpoint and service records.",
	}, d.mcpAgentPublishRecord)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_resolve_records",
		Description: "Fetch all signed records published by a remote agent (endpoint record, service registrations, custom records). Use type=0 for all, or specify a record type.",
	}, d.mcpResolveRecords)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_resolve",
		Description: "Look up a remote agent by its AID to get its current network endpoints and NAT type.",
	}, d.mcpResolve)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_connect",
		Description: "Establish a direct encrypted connection to a remote agent by AID. Returns a local TCP address (127.0.0.1:port) that proxies to the remote agent — use it like any local HTTP server.",
	}, d.mcpConnect)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_mailbox_send",
		Description: "Send an encrypted message to any agent by AID, even if they are currently offline. The message is stored on the Tangled Network until the recipient retrieves it.",
	}, d.mcpMailboxSend)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_mailbox_poll",
		Description: "Check for and decrypt any incoming messages for a local registered agent.",
	}, d.mcpMailboxPoll)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_service_register",
		Description: "Publish capability tags for an agent so other agents can find it by searching for services. Use dot-namespaced labels like 'ai.assistant', 'lang.translate', or 'code.review'.",
	}, d.mcpTopicRegister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_service_unregister",
		Description: "Remove a capability tag from an agent. The tag disappears from the Tangled Network after its TTL expires (up to 1 hour).",
	}, d.mcpTopicUnregister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_discover",
		Description: "Search the Tangled Network for agents offering specific capabilities. Returns matching agents with their names, protocols, and AIDs. Optionally filter by protocol (e.g. 'mcp', 'a2a') or tags.",
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
