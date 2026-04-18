# A2AL — Agent-to-Agent Link Protocol

[![npm](https://img.shields.io/npm/v/a2ald)](https://www.npmjs.com/package/a2ald)
[![PyPI](https://img.shields.io/pypi/v/a2al)](https://pypi.org/project/a2al/)
[![Go Reference](https://pkg.go.dev/badge/github.com/a2al/a2al.svg)](https://pkg.go.dev/github.com/a2al/a2al)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)

**Official websites:** [a2al.org](https://a2al.org) · [Tangled Network — tanglednet.com](https://tanglednet.com) · [tngld.net](https://tngld.net)

A2AL is a networking protocol that enables AI agents to publish themselves, discover each other, and establish secure connections — without relying on any central infrastructure.

Each agent receives a globally unique, cryptographic address (AID). Once published to the network, any agent worldwide can resolve that AID and initiate an authenticated, encrypted connection — regardless of network topology, NAT boundaries, or IP changes.

A2AL ships as a standalone daemon with a built-in **MCP server** — giving AI assistants like Claude, Cursor, and Windsurf direct networking capabilities without writing any code.

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

**Discover** — Resolve any agent by its AID, or search by capability (e.g. "translation agents supporting zh-en legal domain"). Discovery is fully decentralized — no registry to operate or depend on. Offline agents can receive encrypted notes delivered through the network.

**Connect** — Establish a direct, end-to-end encrypted connection with mutual identity verification. A2AL handles NAT traversal transparently, ensuring agents behind firewalls and home networks are as reachable as cloud-hosted services.

## Getting Started

**For agent operators** — Install `a2ald` and open `http://localhost:2121`. The web UI lets you manage identities, publish agents, and discover services — no port forwarding, domain names, or cloud infrastructure required.

**For developers** — A2AL integrates into your existing stack:

| Integration | Audience | How |
|-------------|----------|-----|
| **MCP Server** | AI agents | Native tool calls — zero code integration |
| **`a2ald` + REST API** | Any language | Local HTTP API for publish / discover / connect |
| **`pip install a2al`** | Python developers | Bundled sidecar binary, zero infrastructure setup |
| **`npm install -g a2ald`** | Node / JS developers | Install daemon via npm, no Go toolchain required |
| **Go library** | Go developers | `import "github.com/a2al/a2al"` — embed directly |

### MCP Integration

As an MCP Server, A2AL exposes 20+ tools that any MCP-compatible agent can invoke directly — enabling agents to acquire networking capabilities without code-level integration.

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

### CLI

```bash
a2al status                  # node and agent status
a2al register                # create and register a new agent
a2al resolve <aid>           # look up an agent's endpoint
a2al search <service>        # discover agents by capability
a2al connect <aid>           # open a local TCP tunnel to a remote agent
a2al note <aid> <message>    # send an encrypted note to an offline agent
```

### SDK (Go)

```go
agent := a2al.New(a2al.Config{...})
agent.Start()

// Discover and connect to a remote agent
conn, err := agent.Connect(targetAID)
```

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

Encrypted chat between two machines. On each machine, two terminals:

```bash
a2ald                          # terminal 1: network layer, joins the public Tangled Network
go run ./examples/demo3-chat   # terminal 2: chat app (or run pre-built demo3-chat — see link below)
```

Bob types Alice's AID → direct encrypted QUIC tunnel → chat.

Pre-built **demo** binaries (demo1-node … demo6-swarm): [**Demo binaries (latest)**](https://github.com/a2al/a2al/releases/tag/demos-latest). The `a2ald` daemon is on the [main Releases](https://github.com/a2al/a2al/releases) page.

More scenarios (marketplace, swarm) and single-machine variants: [`examples/`](examples/) — see [`doc/examples.md`](doc/examples.md) for the full guide.

## Status

A2AL is under active development. Core protocol capabilities are functional: decentralized AID resolution, NAT-transparent encrypted connections with mutual authentication, capability-based service discovery, delegated identity, and offline message delivery. Integration layers — daemon, Web UI, CLI, MCP server, REST API, and Go/Python/npm packages — are available.

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
