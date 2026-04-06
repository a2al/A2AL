# API Reference

This document covers all integration paths for developers: REST API, MCP tools, Python SDK, and Go SDK.

If you're not sure which to use, start here:

| Path | Best for | Requires |
|------|----------|----------|
| **REST API** | Any language; most direct control | `a2ald` running locally |
| **MCP** | AI agents using Claude, Cursor, Windsurf, etc. | `a2ald` + MCP config |
| **Python SDK** | Python applications | `pip install a2al` |
| **Go SDK** | Go programs; embed without a separate process | Go 1.24+ |

All paths except Go SDK require `a2ald` running. The daemon binds to `http://127.0.0.1:2121` by default.

---

## REST API

### Authentication

If `api_token` is configured, every request must include:

```
Authorization: Bearer <token>
```

All mutating requests (`POST`, `PATCH`, `DELETE`) require `Content-Type: application/json`.

### Base URL

`http://127.0.0.1:2121` (default; set via `--api-addr`)

---

### Health and Status

#### `GET /health`

```json
{"status":"ok"}
```

#### `GET /status`

Returns the node's current state.

```json
{
  "node_aid": "a2alEKFspDoevpF...",
  "auto_publish": true,
  "node_seq": 4,
  "node_published": true,
  "node_last_publish_at": "2026-04-06T12:00:00Z",
  "node_next_republish_estimate": "2026-04-06T12:30:00Z",
  "republish_interval_s": 1800,
  "endpoint_ttl_s": 3600
}
```

---

### Identity

#### `POST /identity/generate`

Generate a new Ed25519 agent identity. Returns keys and delegation proof once — the daemon does not retain the master key.

**Response:**

```json
{
  "aid": "a2alEKFspDoevpF...",
  "master_private_key_hex": "...",
  "operational_private_key_hex": "...",
  "delegation_proof_hex": "...",
  "warning": "Save the master key — it will not be shown again."
}
```

#### `POST /agents/generate`

Generate a blockchain-linked identity (Ethereum or Paralism). Keys are not retained by the daemon.

**Request:**

```json
{"chain": "ethereum"}
```

`chain` is `"ethereum"` (default) or `"paralism"`.

---

### Agents

#### `POST /agents`

Register a previously generated agent identity with the daemon.

**Request:**

```json
{
  "operational_private_key_hex": "...",
  "delegation_proof_hex": "...",
  "service_tcp": "127.0.0.1:8080"
}
```

`service_tcp` is optional — the address of your local service endpoint, included in published records.

**Response:**

```json
{"aid": "a2alEKFspDoevpF...", "status": "registered"}
```

#### `GET /agents`

List all registered agents and their status.

```json
{
  "agents": [
    {
      "aid": "a2alEKFspDoevpF...",
      "service_tcp": "127.0.0.1:8080",
      "service_tcp_ok": true,
      "heartbeat_seconds_ago": 12,
      "last_publish_at": "2026-04-06T12:00:00Z"
    }
  ]
}
```

#### `GET /agents/{aid}`

Single agent status including reachability and publish info.

#### `PATCH /agents/{aid}`

Update `service_tcp` for a registered agent. Requires the operational private key to authorize.

**Request:**

```json
{
  "operational_private_key_hex": "...",
  "service_tcp": "127.0.0.1:9090"
}
```

#### `DELETE /agents/{aid}`

Unregister an agent. Body: `{}`.

#### `POST /agents/{aid}/publish`

Publish or refresh the agent's DHT endpoint record immediately.

**Response:** `{"ok": true, "seq": 5}`

#### `POST /agents/{aid}/heartbeat`

Signal that the agent is alive. Prevents auto-publish from skipping re-publication for idle agents. Implicit on any non-GET call through agent middleware.

#### `POST /agents/{aid}/records`

Publish a custom signed record (RecType `0x02`–`0x0f`) for the agent.

**Request:**

```json
{
  "rec_type": 2,
  "payload_base64": "...",
  "ttl": 3600
}
```

---

### Services (Capability Discovery)

#### `POST /agents/{aid}/services`

Register one or more capabilities for an agent, making it discoverable by service name.

**Request:**

```json
{
  "services": ["lang.translate"],
  "name": "My Translation Agent",
  "protocols": ["mcp", "http"],
  "tags": ["legal", "zh-en"],
  "brief": "Specialized in legal document translation.",
  "meta": {"url": "https://example.com/agent"},
  "ttl": 3600
}
```

#### `DELETE /agents/{aid}/services/{service...}`

Remove a service registration from the daemon's renewal list. Body: `{}`. The DHT entry expires after its TTL.

#### `POST /discover`

Search for agents by capability.

**Request:**

```json
{
  "services": ["lang.translate"],
  "filter": {
    "protocols": ["mcp"],
    "tags": ["legal"]
  }
}
```

**Response:**

```json
{
  "entries": [
    {
      "service": "lang.translate",
      "aid": "a2alEKFspDoevpF...",
      "name": "My Translation Agent",
      "brief": "Specialized in legal document translation.",
      "protocols": ["mcp"],
      "tags": ["legal", "zh-en"]
    }
  ]
}
```

---

### Resolve and Connect

#### `POST /resolve/{aid}`

Resolve a remote AID to its current endpoint record.

**Response:**

```json
{
  "aid": "a2alEKFspDoevpF...",
  "endpoints": ["quic://1.2.3.4:4122"],
  "nat_type": 1,
  "seq": 7,
  "ttl": 3600
}
```

#### `GET /resolve/{aid}/records?type={rec_type}`

Fetch raw `SignedRecord`s for a remote AID. Omit `type` or set `type=0` for all record types.

#### `POST /connect/{aid}`

Establish a direct encrypted tunnel to a remote agent. Returns a local TCP address your application connects to.

**Request (optional — only needed when multiple local agents are registered):**

```json
{"local_aid": "a2alXYZ..."}
```

**Response:**

```json
{"tunnel": "127.0.0.1:54321"}
```

Connect your application to `127.0.0.1:54321`. Traffic is forwarded over the QUIC tunnel to the remote agent. The tunnel closes when your TCP connection closes.

---

### Mailbox

#### `POST /agents/{aid}/mailbox/send`

Send an encrypted note to any agent by AID, even if they are offline.

**Request:**

```json
{
  "recipient": "a2alRemoteAID...",
  "msg_type": 1,
  "body_base64": "..."
}
```

#### `POST /agents/{aid}/mailbox/poll`

Retrieve and decrypt pending incoming notes for a local agent.

**Response:**

```json
{
  "messages": [
    {
      "sender": "a2alSenderAID...",
      "msg_type": 1,
      "body_base64": "..."
    }
  ]
}
```

---

### Ethereum Identity

#### `POST /agents/ethereum/delegation-message`

Build the EIP-191 `personal_sign` message for wallet-based delegation.

**Request:**

```json
{
  "agent": "0x3a7f...",
  "issued_at": 1712345678,
  "expires_at": 1743881678,
  "operational_public_key_hex": "..."
}
```

**Response:** `{"message": "Sign this message in your wallet:\n..."}`

#### `POST /agents/ethereum/register`

Register an Ethereum-linked agent after the user has signed the delegation message.

**Request:**

```json
{
  "agent": "0x3a7f...",
  "issued_at": 1712345678,
  "expires_at": 1743881678,
  "eth_signature_hex": "...",
  "service_tcp": "127.0.0.1:8080",
  "operational_private_key_seed_hex": "..."
}
```

#### `POST /agents/ethereum/proof`

Generate an Ethereum delegation proof directly from a private key (automation / scripting only).

#### `POST /agents/paralism/proof`

Generate a Paralism blockchain delegation proof from a private key.

---

### Config

#### `GET /config`

Current daemon configuration (`api_token` redacted as `***`).

#### `PATCH /config`

Partial config update. Fields that require restart are listed in the response.

**Request (any subset of fields):**

```json
{
  "auto_publish": true,
  "fallback_host": "1.2.3.4",
  "api_token": "mysecret"
}
```

**Response:** `{"ok": true, "restart_required": ["fallback_host"]}`

#### `GET /config/schema`

JSON Schema for all config fields (for UI / tooling).

---

## MCP Tools

`a2ald` exposes its capabilities as MCP tools. Two transport modes:

- **Streamable HTTP**: `http://127.0.0.1:2121/mcp/` (requires daemon running)
- **Stdio**: `a2ald --mcp-stdio` (standalone; no REST API in this mode)

See [MCP Setup](mcp-setup.md) for platform-specific config snippets.

### Tool list

| Tool | Description |
|------|-------------|
| `a2al_identity_generate` | Create a new Ed25519 agent identity (AID, keys, delegation proof). Master key shown once. |
| `a2al_agents_generate_ethereum` | Create a new Ethereum-linked agent identity. Keys not retained. |
| `a2al_ethereum_delegation_message` | Build the EIP-191 message for wallet signing. |
| `a2al_ethereum_register` | Complete Ethereum agent registration after wallet signature. |
| `a2al_ethereum_proof` | Generate Ethereum delegation proof from a raw private key (scripting only). |
| `a2al_agents_list` | List all agents registered with the daemon. |
| `a2al_agent_register` | Register a generated identity with the daemon. |
| `a2al_agent_get` | Get a local agent's status (reachability, last publish, service address). |
| `a2al_agent_patch` | Update a registered agent's service address. |
| `a2al_agent_publish` | Force-publish an agent's endpoint record to the Tangled Network. |
| `a2al_agent_heartbeat` | Keep an agent visible when it has no direct service address. |
| `a2al_agent_delete` | Remove a local agent registration. |
| `a2al_agent_publish_record` | Publish a custom signed data record for an agent. |
| `a2al_status` | Daemon status: node AID, auto-publish state, last/next publish times. |
| `a2al_resolve` | Look up a remote agent's current endpoints by AID. |
| `a2al_resolve_records` | Fetch all signed records published by a remote agent. |
| `a2al_connect` | Open a direct encrypted tunnel to a remote agent. Returns `127.0.0.1:<port>`. |
| `a2al_mailbox_send` | Send an encrypted note to any agent (offline delivery supported). |
| `a2al_mailbox_poll` | Retrieve pending incoming notes for a local agent. |
| `a2al_service_register` | Publish capability tags for an agent (e.g. `lang.translate`, `code.review`). |
| `a2al_service_unregister` | Remove a capability tag from an agent. |
| `a2al_discover` | Search the Tangled Network for agents by capability name, protocol, or tags. |

---

## Python SDK

```bash
pip install a2al
```

### `Daemon`

Starts `a2ald` as a sidecar process. The bundled binary is used automatically — no PATH setup required.

```python
from a2al import Daemon, Client

# Context manager — starts and stops cleanly
with Daemon() as d:
    c = Client(d.api_base, token=d.api_token)
    print(c.health())

# Or manually
d = Daemon()
d.start()          # blocks until /health responds
c = Client(d.api_base, token=d.api_token)
# ... use c ...
d.close()          # terminates the process and cleans up the temp data dir
```

**Constructor parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `a2ald_exe` | auto-detected | Path to `a2ald` binary. Falls back to `A2ALD_PATH` env, then bundled binary. |
| `api_token` | `None` | Bearer token for API auth. Falls back to `A2AL_API_TOKEN` env. |
| `extra_args` | `[]` | Additional CLI args passed to `a2ald` (e.g. `["--bootstrap", "1.2.3.4:4121"]`). |

After `start()`, `d.api_base` is the HTTP base URL (e.g. `http://127.0.0.1:52341`).

### `Client`

A thin REST client. All methods map to the REST API above.

```python
c = Client("http://127.0.0.1:2121", token="mysecret")

c.health()                          # GET /health
c.status()                          # GET /status
c.identity_generate()               # POST /identity/generate
c.agent_register(op_key, proof)     # POST /agents
c.agent_publish(aid)                # POST /agents/{aid}/publish
c.resolve(remote_aid)               # POST /resolve/{aid}
c.connect(remote_aid)               # POST /connect/{aid} → {"tunnel":"127.0.0.1:PORT"}
c.discover(services, filter=None)   # POST /discover
c.mailbox_send(aid, recipient, ...)  # POST /agents/{aid}/mailbox/send
c.mailbox_poll(aid)                 # POST /agents/{aid}/mailbox/poll
```

For the full method list, see the source at `python/src/a2al/_sidecar.py`.

---

## Go SDK

Import the module:

```
github.com/a2al/a2al
```

The primary entry point for most applications is `github.com/a2al/a2al/host`. Lower-level packages (`dht`, `protocol`, `identity`, `crypto`) are available when you need finer control.

See [`doc/API.md`](API.md) for the full Go API reference including `host.Host`, `dht.Node`, endpoint record types, and the `config` package.
