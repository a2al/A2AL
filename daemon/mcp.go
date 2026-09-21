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

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
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

// mcpInstructions is the session-initialisation text: the L4 tier of the
// semantics guideline. It is injected into every session, so it carries only
// what the tool signatures, defaults and errors cannot — written as decision
// rules, not field glossaries. Named rather than inlined so that the V1
// anti-drift check can verify the identifiers it mentions still exist.
const mcpInstructions = `a2ald is the A2AL peer-to-peer daemon (DHT + QUIC).

Call a2al_status to see current conditions. dht_peers is who is in view — a signal, not a permission to proceed.

Same daemon: group_* and local tools need no wait.

Another machine: try resolve/fetch. If they are not reachable now and you can wait, leave a note. If a call fails and a2ald just started, wait 10–30 seconds and retry. Do not wait for a peer count.

If the public network was intended and after about a minute nothing works, check connectivity. Local-only and private clusters are fine with no public neighbors; agents on this daemon still work.

Publish (a2al_agent_publish) only if other machines must find this AID. Skip it for outbound-only or same-machine use. After publishing, keep a2ald running (records expire after it stops): a2ald service install -user.

MCP: HTTP at this daemon's api_addr (default http://127.0.0.1:2121/mcp/). Stdio (a2ald --mcp-stdio) proxies to a running daemon. A second node needs its own data directory and matching --api.

If they are not reachable now, leave a note (a2al_mailbox_send) — they will have it when they are back. That is not an immediate answer.
Incoming notes announce themselves — do not go looking when there is no hint:
  - A successful tool result may include envelope field "pending": {"<aid>": {"mailbox": N, "chat_invites": N, "chat_unread": N, ...}}. mailbox → a2al_mailbox_poll. chat_invites → chat_contacts then chat_accept. chat_unread → chat_read then chat_mark_read. Other keys belong to the app that registered them.
  - No hint means nothing is waiting.
  - Group invitations still arrive as ordinary mailbox notes (pending.mailbox). Chat invitations do not: they are pending.chat_invites, never mailbox_poll.

Collaboration Groups (the group_* tools) — the parts you cannot infer from the tool names:
  - group_list is local unread; use it when you need the Groups on this AID.
  - group_read's after_seq is per call and not remembered; omit it and you get the oldest entries, not the newest. Page with scanned_to_seq. Reading does not mark read: call group_mark_read when you have dealt with what you read.
  - group_append commits to your log only. There are no delivery or read receipts — the only evidence that a peer acted is an entry that peer wrote.
  - group.unread fires once when unread goes 0 to positive; group.appended is your own write, never other people's.
  - Being invited does not create a replica — call group_join. Pass inviter_aid from the mailbox sender. Each AID's Groups are its own.
  - group_sync is diagnostic; the conventional path does not need it.

One-to-one chat (the chat_* tools) is not mailbox and not a Group:
  - Do not use a2al_mailbox_send as chat. Invite with chat_request; send with chat_send.
  - chat_send to someone not on the list returns not_friends — call chat_request first. If already friends, chat_request resends the invite to heal a stale peer roster. chat_remove drops a friend (both sides); chat_block keeps them blocked.
  - Invitations: pending.chat_invites / chat.invites / chat_contacts (in_pending). Unread: pending.chat_unread / chat.unread / chat_read, then chat_mark_read. chat.received is for an open thread, not the red-dot.
`

func buildMCPServer(d *Daemon) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "a2ald", Title: "A2AL Daemon", Version: "0.1"}, &mcp.ServerOptions{
		Instructions: mcpInstructions,
	})

	s.AddReceivingMiddleware(pendingHitchMiddleware(d))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_identity_generate",
		Description: "Create a new permanent cryptographic identity (AID) for an agent. Each call produces a brand-new, unrelated AID — if the agent already has keys from a previous call, use a2al_agent_register to restore them instead of generating again. The master key is shown once and must be saved; the daemon does not retain it.",
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
		Description: "Register an agent identity with the daemon. Idempotent — safe to call again with the same keys to re-import after a daemon restart. Set service_tcp (e.g. '127.0.0.1:8080') to expose a local HTTP service so remote agents can reach this agent via a2al_fetch; omit if this agent only calls others.",
	}, d.mcpAgentRegister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_get",
		Description: "Get a local agent's configuration and publish status (service address, DHT publish times, replica count). Returns immediately from in-memory state — no network IO.",
	}, d.mcpAgentGet)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_probe",
		Description: "Check a local agent's live reachability: whether its service_tcp address is currently connectable, and the latest endpoints/NAT type from the DHT. Performs real network IO (TCP probe + DHT resolve); call only when the user explicitly wants a live status check.",
	}, d.mcpAgentProbe)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_patch",
		Description: "Update a registered agent's service_tcp (host:port of this agent's own HTTP, never the daemon api_addr). Empty string stops exposing a local service. After a non-empty bind you are callable: give other agents this AID and tell them to a2al_fetch (they add their own API path) or GET/POST http://<their a2ald>/aid/<AID>/<path>. If they cannot reach you now and can wait, a2al_mailbox_send — that is not an HTTP reply.",
	}, d.mcpAgentPatch)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_publish",
		Description: "Announce an agent's current network address to the Tangled Network so other agents can discover and connect to it. The daemon auto-publishes on a schedule; call this to force an immediate refresh.",
	}, d.mcpAgentPublish)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_heartbeat",
		Description: "Diagnostics only — the conventional path does not need this. Any MCP or REST call that acts as a registered local agent already records liveness. Use this only when you must refresh liveness without doing other work.",
	}, d.mcpAgentHeartbeat)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_agent_delete",
		Description: "Permanently remove a local agent registration: stops auto-publish and deletes the operational key from the daemon.",
	}, d.mcpAgentDelete)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_status",
		Description: "Return daemon status. dht_peers is who is currently in view (a signal, not a go/no-go). Do not treat network_ready as proof others can find you, or as a gate on calling others.",
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
		Description: "Leave a note for an agent by AID when they are not reachable now. They will have it when they are back. This is not an immediate answer.",
	}, d.mcpMailboxSend)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_mailbox_poll",
		Description: "Collect notes waiting for a local registered agent. Call this when a successful result told you a note is waiting; do not poll when there is no hint.",
	}, d.mcpMailboxPoll)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_service_register",
		Description: "Publish capability tags for an agent so other agents can discover it by service type. Use dot-namespaced labels like 'ai.assistant', 'lang.translate', or 'code.review'. Optional and independent from identity registration — an agent can be reachable by AID without publishing any service tags.",
	}, d.mcpTopicRegister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_service_unregister",
		Description: "Remove a capability tag from an agent. The tag disappears from the Tangled Network after its TTL expires (up to 1 hour).",
	}, d.mcpTopicUnregister)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_discover",
		Description: "Search the Tangled Network for agents by capability. Returns candidate agents with their names, protocols, and AIDs — results are not guaranteed exact matches, so apply your own judgment to select the right one. Optionally filter by protocol (e.g. 'mcp', 'a2a') or tags.",
	}, d.mcpDiscover)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_fetch",
		Description: "Send an HTTP request to a remote agent over the Tangled Network. End-to-end encrypted via QUIC; no ports are exposed. Returns {status, headers, body}. The remote agent must have a service_tcp registered; if they are not reachable now, the request fails — leave a note with a2al_mailbox_send if you can wait (that is not an HTTP response).",
	}, d.mcpFetch)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_tunnel_open",
		Description: "Open a persistent multiplexed tunnel to a remote agent's service. Returns a local TCP address (e.g. 127.0.0.1:PORT) and a tunnel_id. Unlike a2al_connect, the tunnel accepts unlimited concurrent TCP connections, each mapped to its own QUIC stream. Ideal for SSH forwarding, database clients, and any tool that opens multiple connections. Close with a2al_tunnel_close when done.",
	}, d.mcpTunnelOpen)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_tunnel_close",
		Description: "Close a multiplexed tunnel previously opened with a2al_tunnel_open. Stops accepting new TCP connections immediately; in-flight streams continue until they finish naturally. The underlying QUIC connection is retained in the pool for future use.",
	}, d.mcpTunnelClose)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "a2al_tunnel_list",
		Description: "List all currently open multiplexed tunnels, including their local listen address, remote agent, active connection count, and idle time.",
	}, d.mcpTunnelList)

	mcp.AddTool(s, &mcp.Tool{
		Name: "a2al_events_poll",
		Description: `Return queued daemon events for a local agent since a given sequence number. The types are exactly: mailbox.received, group.appended (your own write), group.unread (edge-triggered, 0 to positive only), group.mentioned (one per entry naming you), chat.invites, chat.unread (edge-triggered per peer, 0 to positive), chat.received.
Use last_seq from each response as after_seq on the next call. If truncated is true the cursor is too old — reset after_seq to 0 and do a full resync. For real-time delivery use GET /agents/{aid}/events (omit last_event_id for live frames; pass last_event_id=N to replay from that id). On connect that stream may first send event: pending with no id — same {"<aid>":{"mailbox":N,...}} shape as a tool result; it is local inventory, not a log event. mailbox → a2al_mailbox_poll; other keys belong to the app that registered them.
Events are droppable doorbells, not the record: an event you missed is not recoverable from here, so treat the Group log, the chat log, and the mailbox as the source of truth and use group_list / chat_contacts / a2al_mailbox_poll to find out what you actually have.`,
	}, d.mcpEventsPoll)

	d.registerGroupMCPTools(s)
	d.registerChatMCPTools(s)

	return s
}

// pendingHitchMiddleware attaches the local pending snapshot to every
// successful tools/call result — the interface-layer counterpart of the DHT
// hitchhike: the caller is told what is waiting for it on a reply it was going
// to receive anyway, so there is no "check for mail" step it can forget.
//
// It sits in middleware rather than in the result builders because there is no
// single builder: group_mcp.go funnels through mcpOK, but mcp.go constructs
// CallToolResultFor values inline in ~28 places. One middleware covers both, and
// covers stdio and HTTP alike since both modes go through buildMCPServer.
//
// MCP is the only surface that gets this on every reply, because it is the only
// one without an event loop — a turn-based agent cannot be woken by an event, so
// the reply is the only channel. HTTP/CLI hitch the same snapshot on overview
// endpoints and as an event: pending SSE envelope on subscribe (see routes.go).
//
// Known SDK coupling: AddTool infers an OutputSchema from map[string]any, and
// v0.2.0 does not yet validate StructuredContent against it. If a later SDK
// starts validating, re-check that an extra key is still permitted.
func pendingHitchMiddleware(d *Daemon) mcp.Middleware[*mcp.ServerSession] {
	return func(next mcp.MethodHandler[*mcp.ServerSession]) mcp.MethodHandler[*mcp.ServerSession] {
		return func(ctx context.Context, ss *mcp.ServerSession, method string, params mcp.Params) (mcp.Result, error) {
			res, err := next(ctx, ss, method, params)
			if err != nil || method != "tools/call" {
				return res, err
			}
			ctr, ok := res.(*mcp.CallToolResult)
			if !ok || ctr.IsError {
				// A failed call must not carry unrelated state.
				return res, err
			}
			m, ok := ctr.StructuredContent.(map[string]any)
			if !ok {
				return res, err
			}
			if _, taken := m["pending"]; taken {
				// A tool's own field always wins; never shadow business data.
				return res, err
			}
			if p := d.pendingSnapshot(ctx, ss); len(p) > 0 {
				m["pending"] = p
			}
			return res, err
		}
	}
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

func (d *Daemon) mcpAgentProbe(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpAIDArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	out, err := d.execAgentProbe(ctx, params.Arguments.AID)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: out}, nil
}

type mcpPatchArgs struct {
	AID                      string  `json:"aid"`
	OperationalPrivateKeyHex string  `json:"operational_private_key_hex"`
	ServiceTCP               *string `json:"service_tcp"`
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
	RemoteAID   string `json:"remote_aid"`
	LocalAID    string `json:"local_aid,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
}

func (d *Daemon) mcpConnect(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpConnectArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res, err := d.execConnect(cctx, params.Arguments.RemoteAID, connectReq{LocalAID: params.Arguments.LocalAID, AccessToken: params.Arguments.AccessToken})
	if err != nil {
		return nil, err
	}
	m, err := structToMap(res)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: m}, nil
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
	msgID, err := d.execMailboxSend(sctx, params.Arguments.AID, params.Arguments.Recipient, params.Arguments.MsgType, raw)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"ok": true, "message_id": msgID}}, nil
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
	Services  []string       `json:"services"`
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

// ── a2al_fetch ────────────────────────────────────────────────────────────────

// mcpFetchArgs extends fetchReq with a required remote_aid field.
// All other fetch parameters are promoted from the embedded fetchReq.
type mcpFetchArgs struct {
	RemoteAID string `json:"remote_aid"`
	fetchReq
}

func (d *Daemon) mcpFetch(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpFetchArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	remoteAID, err := a2al.ParseAddress(params.Arguments.RemoteAID)
	if err != nil {
		return nil, errors.New("bad remote_aid")
	}
	localAID, err := resolveLocalAID(params.Arguments.LocalAID, d.nodeAddr)
	if err != nil {
		return nil, errors.New("bad local_aid")
	}
	fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	result, err := d.execFetch(fctx, localAID, remoteAID, params.Arguments.fetchReq)
	if err != nil {
		switch {
		case errors.Is(err, errResolve):
			return nil, errors.New("resolve failed: remote agent not found on the network — try a2al_discover to search by capability, or leave a note with a2al_mailbox_send if you can wait")
		case errors.Is(err, errConnectQUIC):
			return nil, errors.New("connect failed: remote agent is not reachable now — leave a note with a2al_mailbox_send if you can wait")
		case isAccessDeniedErr(err):
			return nil, protocol.ErrAccessDenied
		default:
			return nil, err
		}
	}
	m, err := structToMap(result)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: m}, nil
}

// ── a2al_tunnel_open / _close / _list ────────────────────────────────────────

type mcpTunnelOpenArgs struct {
	RemoteAID      string `json:"remote_aid"`
	LocalAID       string `json:"local_aid,omitempty"`
	AccessToken    string `json:"access_token,omitempty"`
	IdleTimeoutSec int    `json:"idle_timeout_sec,omitempty"`
}

func (d *Daemon) mcpTunnelOpen(ctx context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpTunnelOpenArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	entry, _, err := d.execTunnelOpen(tctx, params.Arguments.RemoteAID, tunnelOpenReq{
		LocalAID:       params.Arguments.LocalAID,
		AccessToken:    params.Arguments.AccessToken,
		IdleTimeoutSec: params.Arguments.IdleTimeoutSec,
	})
	if err != nil {
		switch {
		case errors.Is(err, errBadAID):
			return nil, errors.New("bad remote_aid")
		case errors.Is(err, errResolve):
			return nil, errors.New("resolve failed: remote agent not found on the network — try a2al_discover to search by capability")
		case errors.Is(err, errConnectQUIC):
			return nil, errors.New("connect failed: could not establish QUIC connection to remote agent")
		default:
			return nil, err
		}
	}
	m, err := structToMap(entry.status())
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: m}, nil
}

type mcpTunnelCloseArgs struct {
	TunnelID string `json:"tunnel_id"`
}

func (d *Daemon) mcpTunnelClose(_ context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpTunnelCloseArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	if !d.closeTunnel(params.Arguments.TunnelID) {
		return nil, errors.New("tunnel not found")
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"closed": true}}, nil
}

func (d *Daemon) mcpTunnelList(_ context.Context, _ *mcp.ServerSession, _ *mcp.CallToolParamsFor[struct{}]) (*mcp.CallToolResultFor[map[string]any], error) {
	list := d.tunnels.list()
	items := make([]any, len(list))
	for i, s := range list {
		m, err := structToMap(s)
		if err != nil {
			return nil, err
		}
		items[i] = m
	}
	return &mcp.CallToolResultFor[map[string]any]{StructuredContent: map[string]any{"tunnels": items}}, nil
}

// ── a2al_events_poll ─────────────────────────────────────────────────────────

type mcpEventsPollArgs struct {
	AID      string `json:"aid"`
	AfterSeq uint64 `json:"after_seq"` // events with seq > AfterSeq; 0 = from the start of the buffer
}

func (d *Daemon) mcpEventsPoll(_ context.Context, _ *mcp.ServerSession, params *mcp.CallToolParamsFor[mcpEventsPollArgs]) (*mcp.CallToolResultFor[map[string]any], error) {
	aid, err := a2al.ParseAddress(params.Arguments.AID)
	if err != nil {
		return nil, errors.New("bad aid")
	}
	d.noteActingAgent(aid)

	events, oldestSeq, truncated := d.evtLog.Since(aid, params.Arguments.AfterSeq)

	// Compute last_seq: highest seq returned, or AfterSeq if nothing new.
	lastSeq := params.Arguments.AfterSeq
	items := make([]any, 0, len(events))
	for _, le := range events {
		items = append(items, map[string]any{
			"seq":  le.Seq,
			"type": le.Type,
			"ts":   le.Ts,
			"data": le.Data,
		})
		if le.Seq > lastSeq {
			lastSeq = le.Seq
		}
	}

	return &mcp.CallToolResultFor[map[string]any]{
		StructuredContent: map[string]any{
			"events":     items,
			"last_seq":   lastSeq,
			"oldest_seq": oldestSeq,
			"truncated":  truncated,
		},
	}, nil
}
