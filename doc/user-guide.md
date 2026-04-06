# User Guide

This guide is for anyone who wants to make their AI agent discoverable, connectable, and collaborative — using the Web UI, CLI, or by simply asking your AI assistant to handle it.

If you haven't run `a2ald` yet, start with the [Quick Start](quickstart.md).

---

## The AI Agent Networking Problem

AI agents are increasingly capable. The harder problem is getting them to work *together*.

Today's AI ecosystem has a structural gap: protocols like MCP, A2A, and ANP define how agents communicate once they're connected, but assume you already know where the other agent is. In practice, agents run on laptops, home machines, cloud VMs, containers — with dynamic IPs, behind NAT, across organizational boundaries. That assumption almost never holds.

**"Where is the other agent?"** — There's no standard, open way to announce availability or discover peers. What exists today: pre-configured endpoint lists that break when anything moves, platform-specific directories that lock you into one ecosystem, and manual coordination that doesn't scale.

**"Is this actually the agent I think it is?"** — Without a shared certificate authority, verifying you're talking to the right agent requires trusting the platform. A2AL replaces this with cryptographic identity: the agent's address *is* its public key fingerprint. Verification is built in, no CA required.

**"My agent is behind a firewall / NAT."** — Most agents aren't on public servers. NAT traversal is a solved problem at the infrastructure level, but nothing in the current AI stack handles it transparently for agents.

**"I need agents to find each other dynamically."** — Hardcoded endpoints are configuration debt. Every deployment is a coordination problem. Every endpoint change cascades into broken integrations.

A2AL is the missing layer:

| Problem | A2AL's answer |
|---------|--------------|
| No global discovery | Every AID is resolvable from anywhere, without a registry |
| Hardcoded endpoints | Agents publish current endpoints; the network always has the latest |
| NAT and firewalls | Built-in NAT traversal — no configuration, no VPN, no manual setup |
| No identity verification | Every connection cryptographically verifies both sides |
| Platform lock-in | Open protocol, no operator, no permission required |

---

## Core Concepts

### AID — identity and address unified

An **AID** (Agent Identifier) is a cryptographic address derived from a key pair you generate locally:

```
a2alEKFspDoevpFxLHiagvdBFqMVFq3sZ1JDsFdJKP    ← Ed25519 (native)
0x3a7fc8f294b4e53e91a5b7a4f2c9d0e1b3c8a2f9    ← Ethereum wallet address
```

What makes an AID different from a URL or IP address:

- **Self-sovereign.** No one assigns it to you. You generate the key pair; the AID is derived from the public key. The private key is the sole proof of ownership.
- **Permanent.** The AID never changes, even as your agent's IP, network, or machine changes. It's a stable identity anchor.
- **Verifiable.** Anyone can confirm that an entity claiming an AID holds the corresponding private key — no intermediary needed.
- **Portable.** The same AID works from a laptop, a cloud VM, a home network, or behind a corporate firewall.

An AID is both who your agent *is* and how others *address* it. There's no separation between identity and reachability. Share your AID like you'd share a contact — whoever has it can reach you, anywhere, anytime.

### The Tangled Network

When you publish an agent, a signed record — mapping its AID to its current endpoints — is distributed across a peer-to-peer network. This is the **Tangled Network**.

Key properties:

- **No central server.** Records are stored across participating nodes worldwide. No registry to operate, depend on, or get blocked by.
- **Not in the data path.** The Tangled Network only stores "where to find me now." Your application data never flows through it.
- **Self-healing.** If your IP changes, you publish a new record. Old records expire by TTL. The network converges to your new endpoints automatically.
- **Open participation.** Any `a2ald` instance is a node. Running `a2ald` means you contribute to and benefit from the same network.

### a2ald — your local daemon

`a2ald` is a background process that runs on your machine and handles everything network-related: DHT participation, NAT traversal, QUIC connection negotiation, and cryptographic signing. You interact with it through the Web UI, CLI, REST API, or MCP tools.

`a2ald` is a *gateway*, not a *proxy*. It resolves addresses and establishes connections, then steps aside. Your application data flows directly between agents — `a2ald` is never in the data path after the connection is established.

### Delegated identity — the master key stays offline

When you register an agent, A2AL generates two keys:

- **Master key**: derives the AID. This is the permanent identity. Keep it offline or in a hardware wallet — you only need it to prove ownership or issue new credentials.
- **Operational key**: what `a2ald` uses day-to-day to sign endpoint records and authenticate connections. It carries a cryptographic delegation proof from the master key.

This separation means your agent's permanent identity is never exposed to the network or held by the daemon. If an operational key is compromised, revoke it and issue a new one — the AID stays the same, and so do all your existing contacts.

For most users this is transparent — `a2al register` handles the key generation and delegation automatically. But it's why your AID remains safe even if your machine is compromised.

---

## The Three Operations

### Publish — announcing your agent

Publishing writes a signed record to the Tangled Network containing:

- Your AID and current network endpoints (including NAT-traversed and UPnP-mapped addresses)
- A service declaration (optional): what capability you offer, under what service name and tags
- A TTL — how long the record is valid

`a2ald` handles signing, endpoint detection, and automatic re-publication before TTL expiry. You don't manage any of this manually.

**Service publishing** adds a layer on top: alongside your endpoint record, you register what your agent *does* — a service name like `lang.translate` or `reason.plan`, a description, and optional tags. This is what makes capability-based discovery possible.

Publishing is not a commitment to be permanently online. If your agent goes offline, its record expires naturally. When it comes back and republishes, the network is updated.

### Discover — finding agents

Two modes:

**Resolve by AID** — If you have an agent's AID, look up its current endpoints directly. Deterministic, fast, exact.

**Search by service** — If you know what you need but not who has it, search by service name. Results include name, description, tags, and AID for every agent currently publishing that capability.

Service names follow a `category.function` convention:

| Service | Capability |
|---------|-----------|
| `lang.translate` | Language translation |
| `lang.chat` | Conversational AI |
| `reason.plan` | Task planning and orchestration |
| `reason.analyze` | Data analysis and research |
| `code.review` | Code review |
| `code.gen` | Code generation |
| `data.search` | Web or knowledge base search |
| `gen.image` | Image generation |
| `tool.browser` | Browser automation |

You can narrow results by tag: `a2al search reason.analyze --filter-tag finance`. See [Service Categories](service-categories.md) for the full taxonomy.

### Connect — direct encrypted link

Once you have an AID, `a2ald` negotiates a direct QUIC connection with the remote agent. Both sides verify each other's identity cryptographically before the connection is established — no trusted third party involved.

The result is a **local tunnel**: `a2ald` returns `127.0.0.1:<port>` and your application connects to that port. From your application's perspective, it's a plain TCP socket — encryption, NAT traversal, and identity verification happen transparently underneath.

This means zero code changes to your existing application. If it can talk over TCP, it can talk to any agent on the Tangled Network.

---

## Scenarios

### Making your agent globally reachable

Start `a2ald`, open `http://localhost:2121`, click **New Agent**. An AID is generated. Fill in your agent's service name and description, click **Publish**. Your agent is now discoverable worldwide — no port forwarding, domain registration, or cloud account required.

Share your AID with anyone who should be able to reach you directly. They resolve it and connect without needing anything else from you.

### An AI agent discovers and calls a specialized service

Your AI coding assistant (running in Cursor, Claude, or any MCP-compatible tool) needs code review capability. Instead of being hardcoded to a specific endpoint, it:

1. Calls `a2al_discover` with service `code.review`
2. Gets back a list of available agents — name, description, AID
3. Picks one, calls `a2al_connect` to open a tunnel
4. Sends code over the tunnel, receives a review

The assistant never knew the reviewer's IP, port, or network location. The entire flow — discovery, identity verification, NAT traversal — was handled by A2AL. This is the core value proposition for AI agents: *capability-based discovery replaces hardcoded dependencies.*

### Acquiring networking via MCP — no code required

If your AI uses an MCP-compatible tool (Claude Desktop, Cursor, Windsurf, Cline), install `a2ald` and add it to your MCP config. Your AI immediately has 20+ networking tools available as natural tool calls:

- *"Register an agent and publish it to the network"* → the AI calls `a2al_identity_generate`, `a2al_agent_register`, `a2al_agent_publish`
- *"Find me a translation agent that supports legal documents"* → calls `a2al_discover` with `lang.translate` and a tag filter
- *"Connect to agent `0x3a7f...`"* → calls `a2al_connect`, gets a tunnel address

Your agent is live, discoverable, and connected — without writing a single line of networking code.

See [MCP Setup](mcp-setup.md) for platform-specific configuration.

### Zero-configuration agent pipeline

You're building a pipeline: Planner → Researcher → Writer → Fact-checker. Each agent runs independently, possibly on different machines, possibly behind NAT.

Traditional setup: manually configure endpoints, write connection logic for each step, update everything whenever any agent moves.

With A2AL: each agent publishes under a service name (`reason.plan`, `data.search`, `lang.write`, `reason.evaluate`). The Planner searches for each capability at runtime, discovers whatever is currently available, and builds the pipeline dynamically. If the Researcher migrates to a new server, it republishes — the Planner reconnects automatically. No configuration files. No manual endpoint management.

### Agent swarm: dynamic discovery and parallel consultation

A Planner agent evaluates a business expansion strategy. Rather than routing through a fixed pipeline, it assembles a swarm:

1. Searches for available specialists: `reason.analyze`, `data.search`, `reason.evaluate`, `reason.recommend`
2. Discovers multiple available agents — with varying expertise, descriptions, and tags
3. Opens parallel QUIC tunnels to all of them
4. Sends each a relevant sub-question; collects responses concurrently
5. Synthesizes a final recommendation

The composition of the swarm is determined at runtime by what's discoverable — not by what's pre-wired. Agents can join or leave the network freely; the Planner handles partial availability gracefully. This is the Tangled Network as a live capability marketplace.

### Making a NAT-hosted agent reachable

Your agent runs on a home machine, behind a router you don't control. `a2ald` handles this automatically: it requests a UPnP port mapping, probes its own external IP via peer reflection, and includes all viable endpoint candidates in the published record. Remote agents trying to connect dial all candidates in parallel (Happy Eyeballs) and succeed on whichever path works.

You configure nothing. The reachability just works.

### Offline messaging — notes

Agents don't have to be online simultaneously. To reach an agent that may be offline:

1. Send a note: `a2al note <aid> "please process this when you're back"`
2. The note is encrypted with the recipient's public key and stored in the DHT
3. When the recipient's `a2ald` comes online, it retrieves and decrypts the note

Notes are end-to-end encrypted — only the holder of the recipient's private key can read them. This enables asynchronous agent collaboration for agents on intermittent schedules, mobile devices, or sleep-mode machines.

---

## Runtime Behavior

### NAT and firewalls

`a2ald` uses three techniques in combination:

- **Peer reflection**: peers report what external address they see your packets from, giving `a2ald` its likely public endpoint
- **UPnP**: on supporting routers, `a2ald` requests a port mapping automatically
- **ICE / hole-punching**: when direct connection isn't possible, `a2ald` attempts coordinated hole-punching through a signaling channel

This works transparently for most environments: home routers, corporate NAT, cloud instances. The one case that may not work without a relay is symmetric NAT on both sides simultaneously — `a2ald` will warn you in the Web UI if it detects this condition. TURN relay support for symmetric NAT is in development.

### Endpoint refresh

If your machine's IP changes — laptop switching networks, container restart, VM migration — `a2ald` detects the change and republishes before the previous record expires. From a caller's perspective, the AID is always resolvable. The underlying endpoints are an implementation detail.

### Bootstrap and network joining

When `a2ald` starts, it contacts built-in public bootstrap nodes to join the Tangled Network. No configuration needed under normal conditions.

In isolated environments (local testing, air-gapped networks), specify bootstrap addresses explicitly:

```bash
a2ald --bootstrap 192.168.1.10:4121
```

Once joined, `a2ald` builds its own routing table and no longer depends on the bootstrap node.

---

## Glossary

| Term | Definition |
|------|-----------|
| **AID** | Agent Identifier. A cryptographic address derived from a key pair. Permanent, self-issued, globally unique. |
| **Tangled Network** | The global peer-to-peer DHT network that stores and resolves AID endpoint records. |
| **a2ald** | The A2AL daemon. Runs locally; handles DHT, NAT traversal, QUIC connections, and identity signing. |
| **Publish** | Write a signed endpoint record for an AID to the Tangled Network. |
| **Resolve** | Look up the current endpoints for a given AID. |
| **Discover** | Search for agents by service capability name. |
| **Connect** | Negotiate a direct encrypted QUIC connection to a remote agent. Returns a local tunnel address. |
| **Tunnel** | A local TCP address (`127.0.0.1:<port>`) returned by `connect`; your application writes to this port to reach the remote agent. |
| **Service** | A declared capability published alongside an endpoint record (e.g. `lang.translate`, `code.review`). |
| **Note** | An encrypted asynchronous message stored on the DHT for an offline recipient to retrieve later. |
| **Master key** | The private key that derives the AID. Keep offline. Proof of permanent identity ownership. |
| **Operational key** | The key `a2ald` uses day-to-day. Carries a delegation proof from the master key. Rotatable without changing the AID. |
| **Delegation proof** | A cryptographic statement from the master key authorizing an operational key to publish on its behalf. |
| **Endpoint record** | The signed, TTL-bound record in the DHT mapping an AID to its current network endpoints. |
| **DHT** | Distributed Hash Table. The data structure underlying the Tangled Network's routing and storage. |
| **Bootstrap** | A known Tangled Network node used to join the network on first start. |
| **NAT traversal** | Techniques (UPnP, ICE, peer reflection) that allow agents behind routers and firewalls to accept inbound connections. |
| **TTL** | Time-to-live. How long a published record remains valid before expiring. |
| **MCP** | Model Context Protocol. A2AL exposes networking capabilities as MCP tools, letting AI agents use them via natural tool calls. |
