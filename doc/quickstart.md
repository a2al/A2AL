# Quick Start

Get two agents to find each other and communicate, in under five minutes.

---

## Concepts first

Before touching a command, understand three things.

**AID — your agent's permanent address.** A cryptographic address derived from a key pair you generate locally. No one assigns it, no registry records it. It looks like a ~44-character string (Ed25519) or `0x3a7f...` (Ethereum-style). As long as you hold the private key, the AID is yours — regardless of IP, network, or machine changes.

**The Tangled Network — a global P2P directory.** When you *publish* an AID, a signed record mapping it to your current endpoints is stored across a distributed hash table. Anyone can *resolve* any AID to find its live endpoints, without a central server. The network stores "where to find me now" — it never carries your application data.

**a2ald — your local daemon.** Runs on your machine and handles DHT participation, NAT traversal, QUIC connections, and identity signing. You talk to it via CLI, Web UI, REST API, or MCP. It establishes connections and steps aside — your data flows directly between agents.

The three operations:

| Operation | What happens |
|-----------|-------------|
| **Publish** | Sign your AID + current endpoints and store on the Tangled Network |
| **Discover** | Search agents by capability, or resolve a known AID to its endpoints |
| **Connect** | Negotiate a direct encrypted connection, handling NAT transparently |

---

## Install

Download the latest release for your platform from [GitHub Releases](https://github.com/a2al/a2al/releases). Each archive contains two binaries:

- `a2ald` — the daemon
- `a2al` — the CLI

Extract and place both in your PATH.

> **Other install methods** exist for specific integration scenarios: `npm install -g a2ald` for [MCP integration](mcp-setup.md), `pip install a2al` for the [Python SDK](api-reference.md). This guide uses the binary release.

---

## Start the daemon

```bash
a2ald
```

On first run, `a2ald` generates a node identity, joins the Tangled Network via public bootstrap nodes, and starts listening. No configuration needed.

## Open the Web UI

Go to **http://localhost:2121** in your browser.

### Register your agent

Click **New Agent**. An AID is generated instantly. Give your agent a name and click **Register** — your agent now has a permanent, globally unique identity.

### Publish to the network

Fill in the service form — service name, protocol, and a brief description of what your agent does. Click **Publish**. Your agent is now discoverable by anyone on the Tangled Network, worldwide.

### Discover other agents

Go to the **Discover** tab. Search by service name (e.g. `reason.qa`, `lang.translate`) to find agents offering that capability. Or paste an AID in the **Resolve** tab to look up a specific agent's endpoints.

### Connect

Click **Connect** on any discovered agent. The daemon negotiates a direct encrypted connection — NAT, firewalls, and dynamic IPs are handled automatically. A local tunnel address is returned; your application connects to that port to talk to the remote agent.

### Send a note to an offline agent

If the remote agent is offline, you can leave an encrypted note that it will pick up later — no need for both parties to be online at the same time.

> **Prefer the CLI?** Everything above can also be done via `a2al register`, `a2al search`, `a2al resolve`, `a2al connect`, and `a2al note`. Run `a2al help` for the full command list.

---

## What's next

| Goal | Where to go |
|------|-------------|
| Understand concepts, scenarios, and operations in depth | [User Guide](user-guide.md) |
| Integrate via REST API, Go SDK, Python, or MCP | [API Reference](api-reference.md) |
| Set up MCP for AI agents (Claude, Cursor, etc.) | [MCP Setup](mcp-setup.md) |
| Run demos: encrypted chat, marketplace, multi-agent swarm | [`examples/`](../examples/) — pre-built binaries: [Demo binaries (latest)](https://github.com/a2al/a2al/releases/tag/demos-latest) |
| Deploy on a Linux server | [`deploy/linux/`](../deploy/linux/README.md) |
