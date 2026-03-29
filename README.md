# A2AL — Agent-to-Agent Link Protocol

A2AL is a networking protocol that enables AI agents to publish themselves, discover each other, and establish secure connections — without relying on any central infrastructure.

Each agent receives a globally unique, cryptographic address (AID). Once published to the network, any agent worldwide can resolve that AID and initiate an authenticated, encrypted connection — regardless of network topology, NAT boundaries, or IP changes.

```
Your Agent  ──publish──▶  A2AL Network  ◀──discover──  Remote Agent
                                                            │
                                          direct authenticated connection
```

## The Problem

AI agent interoperability protocols (MCP, A2A, ANP) define how agents communicate, but assume you already know where the other agent is. In practice:

- No standard, open mechanism exists for agents to announce their availability or discover peers — whether deployed in data centers, on edge infrastructure, or on personal devices
- Agent connectivity depends on pre-configured endpoints, platform-specific registries, or manual coordination — none of which scale across organizational and network boundaries
- Agents behind NAT or with dynamic IPs face additional reachability barriers that existing protocols do not address

A2AL addresses the missing infrastructure layer: **agent-level addressing, discovery, and connectivity**.

## What A2AL Does

**Publish** — An agent announces its identity and reachable endpoints to a global peer-to-peer network. Endpoint records update automatically as network conditions change.

**Discover** — Resolve any agent by its AID, or search by capability (e.g. "translation agents supporting zh-en legal domain"). Discovery is fully decentralized — no registry to operate or depend on.

**Connect** — Establish a direct, end-to-end encrypted connection with mutual identity verification. A2AL handles NAT traversal transparently, ensuring agents behind firewalls and home networks are as reachable as cloud-hosted services.

## Getting Started

**For agent operators** — Install the A2AL daemon (`a2ald`) and open the web management interface. Configure your agent, and it becomes globally discoverable. No port forwarding, domain names, or cloud infrastructure required.

**For developers** — A2AL integrates into your existing stack:

| Integration | Audience | How |
|-------------|----------|-----|
| **Go library** | Go developers | `import "github.com/a2al/a2al"` — embed directly |
| **`a2ald` + REST API** | Any language | Local HTTP API for publish / discover / connect |
| **MCP Server** | AI agents | Native tool calls — agents acquire networking capability on demand |
| **`pip install a2al`** | Python developers | Bundled sidecar binary, zero infrastructure setup |

### SDK (Go)

```go
agent := a2al.New(a2al.Config{...})
agent.Start()

// Discover and connect to a remote agent
conn, err := agent.Connect(targetAID)
```

### MCP Integration

As an MCP Server, A2AL exposes tools (`publish`, `resolve`, `update`, `identity`) that any MCP-compatible agent can invoke directly — enabling agents to acquire networking capabilities without code-level integration.

**Claude Desktop / Cursor / Windsurf / Cline** — add to your MCP config:

```json
{
  "mcpServers": {
    "a2al": {
      "command": "a2ald",
      "args": ["--mcp-stdio"]
    }
  }
}
```

See [`doc/mcp-setup.md`](doc/mcp-setup.md) for platform-specific paths and full tool list.

## Design Principles

**Self-sovereign Identity** — Each agent's address is derived from its own key pair. No registration authority is involved. Identity is verifiable end-to-end: no agent can claim an AID it does not hold the private key for.

**Zero-configuration Discovery** — Agents publish signed endpoint records to a distributed network. Any agent can resolve an AID to a live endpoint. The network operates at any scale — from a handful of nodes to millions.

**Mutual Authentication** — Every connection cryptographically verifies both parties' identities. You always know the agent on the other end is who it claims to be.

**Network-agnostic** — A2AL works across NAT, firewalls, and dynamic IPs. Agents on home machines, mobile devices, and corporate networks are first-class participants alongside cloud-hosted services.

**Direct Communication** — A2AL resolves addresses and brokers the initial connection, then steps aside. Application data flows directly between agents, not through the protocol.

**Web3 Compatible** — Ethereum and Paralism blockchain wallet addresses can serve as AIDs. Cross-key attestation allows an agent to prove ownership of both a native AID and a blockchain identity. Web3 integration is supported, not required.

## Relationship to AI Protocols

A2AL is complementary to existing agent communication standards — it provides the networking foundation they assume but do not include.

| Protocol | Role | How A2AL fits in |
|----------|------|-----------------|
| **MCP** | Agent tool-calling interface | A2AL operates as an MCP-installable tool, giving agents networking capability |
| **A2A** | Agent collaboration semantics | A2AL provides the discovery and connectivity layer A2A relies on |
| **ANP** | Agent networking vision | A2AL implements the decentralized network layer ANP envisions |

## Try the Demo

**Discovery** (Demo 1 — AID address resolution):

```bash
cd examples/demo1-node

go run . -listen :4121 -debug :2634                                    # node 1
go run . -listen :4122 -bootstrap 127.0.0.1:4121 -debug :2635         # node 2
go run . -listen :4123 -bootstrap 127.0.0.1:4121 -debug :2636         # node 3
```

Type any node's AID to resolve its endpoint. Inspect network state at `http://127.0.0.1:2634/debug/routing`.

**Encrypted Chat** (publish → discover → connect → chat):

```bash
cd examples/demo2-chat

go run . -listen :4121 -quic :4122 -debug :2634                       # Alice
go run . -listen :4123 -quic :4124 -bootstrap 127.0.0.1:4121 -debug :2635  # Bob
```

Bob enters Alice's AID → automatic resolution → encrypted connection → bidirectional messaging.

## Status

A2AL is under active development. Core discovery and encrypted connection layers are functional. NAT traversal, the standalone daemon, MCP integration, and multi-language packages are in progress.

See [`doc/API.md`](doc/API.md) for the current library API.

## Disclaimer

A2AL is a networking protocol project. It is not associated with any cryptocurrency token, ICO, or financial product. Any use of the A2AL name or codebase in token offerings or financial promotions is unauthorized and not endorsed by the authors.

## Contributing

Contributions are welcome. Before your pull request can be merged, you must sign the [Contributor License Agreement](CLA.md). A bot will prompt you automatically when you open a PR.

Please open an issue before starting significant work.

## Author

XG.Shi — This project is not affiliated with or endorsed by any employer or organization.

## License

Copyright (c) 2026 The A2AL Authors

Licensed under the [Mozilla Public License 2.0](LICENSE).