# A2AL — Agent-to-Agent Link Protocol

[![npm](https://img.shields.io/npm/v/a2ald)](https://www.npmjs.com/package/a2ald)
[![PyPI](https://img.shields.io/pypi/v/a2al)](https://pypi.org/project/a2al/)
[![Go Reference](https://pkg.go.dev/badge/github.com/a2al/a2al.svg)](https://pkg.go.dev/github.com/a2al/a2al)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)

**Official websites:** [a2al.org](https://a2al.org) · [Tangled Network](https://tanglednet.org) · [tngld.net](http://tngld.net)

A2AL is a networking protocol that enables AI agents to publish themselves, discover each other, and establish secure connections — without relying on any central infrastructure.

Each agent receives a globally unique, cryptographic address (AID). Once published to the network, any agent worldwide can resolve that AID and initiate an authenticated, encrypted connection — on a public server or a laptop, regardless of topology, NAT, or IP changes.

A2AL ships as a standalone daemon with a built-in **MCP server** — giving AI assistants like Claude, Cursor, and Windsurf direct networking capabilities without writing any code.

```
Your Agent  ──publish──▶  A2AL Network  ◀──discover──  Remote Agent
                                                            │
                                          direct authenticated connection
```

## The Problem

AI agent interoperability protocols (MCP, A2A, ANP) define how agents communicate, but assume you already know where the other agent is. In practice:

- No standard, open mechanism exists for agents to announce their availability or discover peers — in a datacenter, on the edge, or on a personal device
- Connectivity depends on pre-configured endpoints, platform-specific registries, or manual coordination — none of which survive a move or a private network
- There is no shared, permanent address that a person, an AI assistant, and a worker can all use without a vendor account

A2AL addresses the missing infrastructure layer: **agent-level addressing, discovery, and connectivity**.

## What A2AL Does

**Publish** — An agent announces its identity and reachable endpoints to a global peer-to-peer network. Endpoint records update automatically as network conditions change.

**Discover** — Resolve any agent by its AID, or search by capability (e.g. "translation agents supporting zh-en legal domain"). Discovery is fully decentralized — no registry to operate or depend on. Offline agents can receive encrypted notes delivered through the network.

**Connect** — Establish a direct, end-to-end encrypted connection with mutual identity verification. The same addressing works on a datacenter server and a home machine; NAT traversal is used where the path needs it.

## Getting Started

**For people** — Install `a2ald` and open `http://localhost:2121`. The web UI lets you create an identity, publish if others must find you, and look up a known AID. Persistent service is optional (`a2ald service install -user`). A known AID is also `http://127.0.0.1:2121/aid/{AID}/…`.

**For developers** — A2AL integrates into your existing stack:

| Integration | Audience | How |
|-------------|----------|-----|
| **MCP Server** | AI agents | Native tool calls — zero code integration |
| **`a2ald` + REST API** | Any language | Local HTTP API for publish / discover / fetch / tunnel |
| **`pip install a2al`** | Python developers | Bundled sidecar binary, zero infrastructure setup |
| **`npm install -g a2ald`** | Node / JS developers | Install daemon via npm, no Go toolchain required |
| **Go library** | Go developers | `import "github.com/a2al/a2al"` — embed directly |

### MCP Integration

As an MCP Server, A2AL exposes 25+ tools that any MCP-compatible agent can invoke directly — enabling agents to acquire networking capabilities without code-level integration.

**Claude Desktop / Cursor / Windsurf / Cline** — `npx -y a2ald mcp add`, or point the host at HTTP:

```json
{
  "mcpServers": {
    "a2al": {
      "url": "http://127.0.0.1:2121/mcp/"
    }
  }
}
```

Hosts that only spawn a process: `"command": "a2ald", "args": ["--mcp-stdio"]` (proxies to a running daemon). See [`doc/mcp-setup.md`](doc/mcp-setup.md).

### CLI

```bash
a2al status                         # node and agent status
a2al register                       # create and register a new agent
a2al search <service>               # discover agents by capability
a2al info <aid>                     # fetch agent info and card
a2al get  <aid> /path               # HTTP GET to a remote agent (encrypted QUIC)
a2al post <aid> /path -d '{}'       # HTTP POST to a remote agent
a2al tunnel open <aid>              # open a persistent local port for sustained access
a2al tunnel                         # list active tunnels
a2al tunnel close <id>              # close a tunnel
a2al note send <local> <aid> <b64>  # send an encrypted note to an offline agent
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

**Network-agnostic** — The same addressing applies on a public server as on a laptop. NAT, firewalls, and dynamic IPs are where that is most visible, not a product boundary.

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

```
a2ald        # terminal 1: network layer, joins the public Tangled Network
demo3-chat   # terminal 2: chat app — download pre-built binary below
```

Bob types Alice's AID → direct encrypted QUIC tunnel → chat.

> **Go developers:** replace `demo3-chat` with `go run ./examples/demo3-chat`.

**Download:** (demos require a2ald v0.1.8+)
- Pre-built **demo** binaries (demo1-node … demo6-swarm): [**Demo binaries (latest)**](https://github.com/a2al/a2al/releases/tag/demos-latest)
- The `a2ald` daemon: [Main Releases page](https://github.com/a2al/a2al/releases)

> **Windows users:** the binaries are currently unsigned. When Windows SmartScreen shows a warning, click **"More info" → "Run anyway"**. This is expected for open-source binaries without a paid code-signing certificate and does not indicate a security risk.

More scenarios (marketplace, swarm) and single-machine variants: [`doc/examples.md`](doc/examples.md).

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
