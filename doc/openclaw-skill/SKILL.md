---
name: a2al
description: >-
  Gives the OpenClaw agent decentralized networking identity and peer discovery
  via the A2AL Tangled Network. Use when the user wants to make their OpenClaw
  instance discoverable to other AI agents worldwide, find and connect to remote
  AI agents by capability, send encrypted offline messages to other agents, or
  set up direct agent-to-agent communication without relying on any central server,
  cloud service, or domain name.
---

# A2AL — Agent-to-Agent Link Protocol

A2AL gives this OpenClaw instance a permanent cryptographic identity (AID) and
lets it discover and directly connect to any other A2AL-enabled agent on the
Tangled Network — regardless of NAT, firewalls, or dynamic IPs.

## Prerequisites

`a2ald` must be running as an MCP server. Verify with `a2al_status`.

**Setup (if not yet installed):**
1. Download `a2ald` from https://github.com/a2al/a2al/releases
2. Add to OpenClaw MCP config and restart:

```json
{
  "mcpServers": {
    "a2al": { "command": "a2ald", "args": ["--mcp-stdio"] }
  }
}
```

## Core Concepts

- **AID** — This agent's permanent address, derived from a cryptographic key pair. Share it so others can find and connect to you.
- **Tangled Network** — The decentralized peer network. No servers to operate; agents participate by running `a2ald`.
- **Service** — A dot-namespaced capability label used for discovery (e.g. `ai.assistant`, `lang.translate`).
- **Fetch** — `a2al_fetch` sends an HTTP request to a remote agent and returns the response directly. The daemon handles QUIC transport internally — no local port needed.
- **One-shot tunnel** — `a2al_connect` returns a local TCP address (`127.0.0.1:<port>`) for a single TCP session (SSH, RDP, or custom protocols).
- **Persistent tunnel** — `a2al_tunnel_open` returns a long-lived local port that accepts many concurrent connections to the same remote agent.

## Workflows

### Make this OpenClaw instance discoverable

```
a2al_identity_generate   → create AID + keys (save master key — shown once)
a2al_agent_register      → register identity with daemon
a2al_agent_publish       → announce to Tangled Network
a2al_service_register    → tag with capability (e.g. "ai.assistant")
```

Print the AID for the user — this is their address to share.

### Call a remote agent's HTTP API

```
a2al_discover            → search by service (e.g. "lang.translate")
a2al_fetch               → send HTTP request, get {status, headers, body} back
```

Or if the remote AID is already known, skip discover and call `a2al_fetch` directly.

### Open a persistent tunnel (SSH, RDP, or sustained HTTP access)

```
a2al_tunnel_open         → returns {id, listen:"127.0.0.1:<port>"}
Connect your app to the local port — supports many concurrent connections
a2al_tunnel_close        → close when done
```

Use `a2al_connect` instead for a single TCP session that closes automatically.

### Send an encrypted message when remote agent is offline

```
a2al_mailbox_send        → encrypts and stores message on Tangled Network
a2al_mailbox_poll        → recipient retrieves messages when they come online
```

## Tool Reference

| Tool | When to use |
|------|-------------|
| `a2al_status` | Check daemon health and this node's AID |
| `a2al_identity_generate` | Create a new agent identity (run once per agent) |
| `a2al_agent_register` | Register a generated identity with the daemon |
| `a2al_agent_publish` | Announce agent's current address to the network |
| `a2al_agent_heartbeat` | Keep agent visible when it has no direct TCP address |
| `a2al_agents_list` | List all locally registered agents |
| `a2al_agent_get` | Check a local agent's reachability and publish status |
| `a2al_agent_delete` | Remove a local agent registration |
| `a2al_service_register` | Publish capability tags so others can search for you |
| `a2al_service_unregister` | Remove a capability tag |
| `a2al_discover` | Search the network for agents by capability |
| `a2al_resolve` | Look up a known AID's current network endpoints |
| `a2al_connect` | Open a one-shot encrypted tunnel (single TCP session, closes automatically) |
| `a2al_fetch` | Send an HTTP request to a remote agent; returns `{status, headers, body}` |
| `a2al_tunnel_open` | Open a persistent tunnel accepting many concurrent connections; returns `{id, listen}` |
| `a2al_tunnel_close` | Close a persistent tunnel by ID |
| `a2al_tunnel_list` | List active persistent tunnels |
| `a2al_mailbox_send` | Send an encrypted async message to any AID |
| `a2al_mailbox_poll` | Check for incoming encrypted messages |

## Service Naming

Use dot-separated namespaces. Register at multiple levels for better discoverability.

| Example | Meaning |
|---------|---------|
| `ai.assistant` | General AI assistant |
| `ai.assistant.openclaw` | OpenClaw specifically |
| `lang.translate` | Any translation |
| `lang.translate.zh-en` | Chinese→English |
| `code.review` | Code review |
| `img.generate` | Image generation |

## Notes

- **Master key**: displayed once after `a2al_identity_generate` — ask the user to save it offline. The daemon does not store it.
- **HTTP calls**: prefer `a2al_fetch` — the daemon handles QUIC transport internally, no local port required. Use `a2al_connect` for non-HTTP protocols or when you need a raw TCP socket.
- **Auto-publish**: `a2ald` republishes endpoint records automatically; `a2al_agent_publish` forces an immediate refresh.
- **Ethereum identity**: use `a2al_agents_generate_ethereum` if the user wants their crypto wallet address as their AID.
