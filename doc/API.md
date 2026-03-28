# A2AL Go library — API reference

This document describes the **public surfaces** for application developers: discovery, signed endpoint records, QUIC sessions, the optional `a2ald` daemon HTTP API, and related packages. Module: `github.com/a2al/a2al`.

## Integration levels

| Level | Package / binary | Use when |
|--------|------------------|----------|
| **Node runtime** | `github.com/a2al/a2al/host` | DHT + QUIC on one or two UDP ports, mutual TLS between agents, publish/resolve/connect helpers. |
| **DHT only** | `github.com/a2al/a2al/dht` | You provide transport and only need routing, bootstrap, and iterative `FIND_VALUE` / `STORE`. |
| **Daemon** | `a2ald` (`cmd/a2ald`) | Local REST + embedded Web UI + MCP + DHT debug JSON under `/debug/*` on the configured API address. |

Lower-level packages (`transport`, `routing`, UDP mux internals) are building blocks; most applications should depend on `host`, `dht`, or the daemon only.

---

## `host` — `Host`

A `Host` runs a DHT `Node`, optional UDP demux for DHT+QUIC on a single port, a QUIC listener, and NAT/reflection hints via `natsense.Sense`.

### Configuration (`host.Config`)

| Field | Meaning |
|-------|---------|
| `KeyStore` | Required. Must list **exactly one** `Address` (see `crypto.KeyStore`). |
| `ListenAddr` | DHT UDP bind, e.g. `":4121"` (default). Currently uses IPv4 UDP (`udp4`). |
| `QUICListenAddr` | If non-empty, QUIC binds here **separately** from DHT. If empty, QUIC shares the DHT UDP socket (mux). |
| `PrivateKey` | Ed25519 key for QUIC/TLS. If nil, `EncryptedKeyStore.Ed25519PrivateKey` is used when available; otherwise set explicitly. |
| `MinObservedPeers` | Minimum distinct peers that must report the same reflected address before `Sense` treats it as trusted (default 3 if ≤0). |
| `FallbackHost` | Optional advertised host when bind address and reflection data are ambiguous (e.g. `0.0.0.0`). |
| `DisableUPnP` | If true, skips IGD UDP port mapping for the QUIC listen port. |

The DHT node created by `Host` sets `dht.Config.RecordAuth` so stored records must be either self-signed for their address or carry a valid operational-key delegation (see `identity`).

### Lifecycle

1. `host.New(cfg)` — starts the DHT receive loop and QUIC listener.  
2. `h.Node().BootstrapAddrs(ctx, []net.Addr{...})` (or `StartWithBootstrap` on a bare `Node`).  
3. Optionally `h.ObserveFromPeers(ctx, seeds)` to seed observed-address sampling.  
4. `h.PublishEndpoint`, `h.Resolve`, `h.Connect` / `h.ConnectFromRecord`, `h.Accept` as needed.  
5. `h.Close()` — also removes any UPnP mapping created for QUIC.

### Primary methods

| Method | Role |
|--------|------|
| `PublishEndpoint(ctx, seq, ttl)` | Builds multi-candidate `quic://` payload (reflection, public bind, fallback, optional UPnP), signs with the node identity, stores on the DHT. |
| `PublishEndpointForAgent(ctx, agentAddr, seq, ttl)` | Same as `PublishEndpoint` but for a **registered** delegated agent (operational key + delegation on the host). |
| `Resolve(ctx, target Address)` | Iterative lookup; returns `*protocol.EndpointRecord`. |
| `Connect(ctx, expectRemote Address, udpAddr)` | QUIC dial to one UDP address with mutual TLS + agent-route (see below). |
| `ConnectFromRecord(ctx, expectRemote Address, er)` | Happy Eyeballs: staggered dials over every `quic://` / `udp://` in `er` (deduped); first success wins. |
| `ConnectFromRecordFor(ctx, localAgent, expectRemote Address, er)` | Same as `ConnectFromRecord` but dials using TLS credentials for `localAgent` (must be registered on this host). |
| `Accept(ctx)` | Blocks for inbound QUIC; returns `*AgentConn` with `Local` / `Remote` addresses. |
| `FirstQUICAddr(er)` | First `quic://` or legacy `udp://` entry as `*net.UDPAddr` (same order as `QUICDialTargets`). |
| `QUICDialTargets(er)` | Ordered, deduplicated `[]*net.UDPAddr` from an `EndpointRecord`. |
| `BuildEndpointPayload(ctx)` | Same candidate list as publish (includes UPnP attempt when enabled); does not sign or store. |
| `SymmetricNATReachabilityHint()` | Non-empty user-facing note when inferred NAT is symmetric (reachability not guaranteed without relay; see **Not yet implemented**). |
| `RegisterAgent(addr, priv)` | Add an extra agent identity on the same QUIC listener (self-signed TLS cert). |
| `RegisterDelegatedAgent(addr, opPriv, delegationCBOR)` | Register an agent published under a master-derived AID using an operational key and CBOR `DelegationProof`. |
| `UnregisterAgent(addr)` / `RegisteredAgents()` | Remove or list extra agents. |
| `Address`, `DHTLocalAddr`, `QUICLocalAddr` | Introspection. |
| `Node()`, `Sense()` | Access underlying DHT node or NAT/reflection state. |
| `ObserveFromPeers` | Triggers ping/bootstrap-style contact to collect `observed_addr` for `Sense`. |
| `SendMailbox` / `PollMailbox` | DHT mailbox (Phase 4): encrypt/decrypt for the **default** host identity. |
| `SendMailboxForAgent` / `PollMailboxForAgent` | Same for a **registered** agent address (self-sign or delegated). |
| `RegisterTopic` / `RegisterTopics` | Topic rendezvous (Phase 4 B): publish RecType `0x10` at `SHA-256("topic:"+string)` for the default identity. |
| `RegisterTopicForAgent` / `RegisterTopicsForAgent` | Same for a registered agent (delegation-aware). |
| `SearchTopic` / `SearchTopics` | `AggregateRecords` on topic key; `SearchTopics` returns AIDs present in **all** listed topics. |
| `StartDebugHTTP(addr)` / `DebugHTTPHandler()` | Read-only JSON (see Debug HTTP). |
| `Close()` | Shuts down QUIC, mux, and DHT. |

### `AgentConn`

Embeds `quic.Connection`. Fields:

- `Local` — agent `Address` selected for this connection (agent-route frame, else SNI, else default).  
- `Remote` — peer `Address` from the mutual TLS peer certificate (inbound).

### QUIC agent-route (interoperability)

After the TLS handshake, the **client** MUST open a stream and write **25 bytes**: prefix `a2r1` (ASCII) followed by the 21-byte binary `Address` of the intended server agent. The server uses this for routing when multiple agents share one listener; TLS SNI is a secondary hint.

---

## `dht` — `Node`

Use when you implement your own stack but need Kademlia-style RPCs and storage.

### Configuration (`dht.Config`)

| Field | Meaning |
|-------|---------|
| `Transport` | Required. DHT UDP (or mux) transport. |
| `Keystore` | Required. Exactly one identity. |
| `OnObservedAddr` | Optional callback when responses carry `observed_addr`. |
| `RecordAuth` | Optional. After `VerifySignedRecord` passes, called before accepting a `STORE`; enforce whether `Pubkey` may publish for the record `Address` (e.g. self-sign or delegation). If nil, no authority check. |

### Lifecycle

1. `dht.NewNode(dht.Config{Transport, Keystore, ...})`  
2. `Start()`  
3. `BootstrapAddrs` / `Bootstrap` / `StartWithBootstrap`  
4. `PublishEndpointRecord` or `NewQuery(n).Resolve` / `FindNode`  
5. `Close()`

### Common methods

| Method | Role |
|--------|------|
| `BootstrapAddrs(ctx, []net.Addr)` | Recommended bootstrap: only `ip:port` required; identity learned from PONG. |
| `PingIdentity(ctx, addr)` | Returns `PeerIdentity{Address, NodeID}`. |
| `PublishEndpointRecord(ctx, rec)` | STORE signed record to closest peers. |
| `PublishMailboxRecord(ctx, storeKey, rec)` | STORE mailbox `SignedRecord` at recipient `NodeID` to k-closest peers (Phase 4). |
| `PublishTopicRecord(ctx, storeKey, rec)` | STORE topic `SignedRecord` at `TopicNodeID` to k-closest peers (Phase 4 B). |
| `NewQuery(n).Resolve(ctx, NodeID)` | Iterative endpoint fetch. |
| `NewQuery(n).FindNode(ctx, NodeID)` | Iterative `FIND_NODE`. |
| `StartDebugHTTP` / `DebugHTTPHandler()` | DHT JSON (no `/debug/host`; that is `Host`-only). |

---

## Identity and signing

| Package | Items |
|---------|--------|
| `github.com/a2al/a2al` | `Address`, `NodeID`, `ParseAddress`, `NodeIDFromAddress` |
| `github.com/a2al/a2al/crypto` | `KeyStore`, `EncryptedKeyStore` (optional `Ed25519PrivateKey` for QUIC), `AddressFromPublicKey`, `GenerateEd25519`, sign/verify helpers |
| `github.com/a2al/a2al/identity` | `ScopeNetworkOps`, `SignDelegation`, `EncodeDelegationProof`, `ParseDelegationProof`, `VerifyDelegation`, `(DelegationProof).AgentAID()` |

---

## Endpoint records (`protocol`)

| Item | Role |
|------|------|
| `SignedRecord` | On-wire CBOR container; optional `Delegation` bytes (field 9) for operational-key publishes. |
| `EndpointPayload` | `Endpoints []string` (use `quic://host:port`), `NatType uint8` |
| `EndpointRecord` | Decoded view after verify (`Address`, `Endpoints`, `NatType`, `Seq`, `Timestamp`, `TTL`) |
| `SignEndpointRecord(priv, addr, payload, seq, timestamp, ttl)` | Build `SignedRecord` when the signing key is the AID's master key |
| `SignEndpointRecordDelegated(opPriv, delegationCBOR, addr, payload, seq, timestamp, ttl)` | Build `SignedRecord` when an operational key publishes for a master-derived `addr` |
| `ParseEndpointRecord(sr)` | Verify and decode to `EndpointRecord` |
| `VerifySignedRecord(sr, now)` | Cryptographic integrity + expiry + payload shape; does **not** enforce pubkey↔address authority (use `RecordAuth` at store/query) |
| NAT constants | `NATUnknown`, `NATFullCone`, `NATRestricted`, `NATPortRestricted`, `NATSymmetric` |

`timestamp` + `TTL` must cover "now" or verification/storage fails.

### Mailbox (Phase 4)

| Item | Role |
|------|------|
| `RecTypeMailbox` (0x80) | Stored at `NodeID(recipient)`; outer `SignedRecord.Address` = sender AID. |
| `EncodeMailboxPayload`, `OpenMailboxRecord` | X25519 + HKDF + AES-256-GCM wire helpers. |
| `MailboxMessage` | Decrypted view: `Sender`, `MsgType`, `Body`. |

### Topic rendezvous (Phase 4 B)

| Item | Role |
|------|------|
| `TopicNodeID(topic)` | `SHA-256("topic:" \|\| UTF-8 topic)` as DHT key. |
| `RecTypeTopic` (0x10) | `TopicPayload` CBOR in `SignedRecord.payload` (≤512 B); `Address` = registrant AID. |
| `TopicEntry` | Decoded listing: AID, `TopicPayload` fields, `Seq` / `Timestamp` / `TTL`. |
| `DiscoverFilter`, `FilterTopicEntries` | Optional `protocols` / `tags` AND-style client filter. |

---

## `a2ald` — HTTP API

Binds to `config.Config.APIAddr` (default `127.0.0.1:2121`). If `api_token` is set, requests must send `Authorization: Bearer <token>`. For mutating methods, use `Content-Type: application/json` (including `DELETE` with an empty JSON body `{}` where required).

| Method | Path | Role |
|--------|------|------|
| `GET` | `/` | Embedded Web UI (HTML). |
| `GET` | `/health` | `{"status":"ok"}`. |
| `GET` | `/status` | Node status: `auto_publish`, `node_aid`, `node_seq`, `last_publish`, `next_publish`. |
| `GET` | `/config` | Current config (`api_token` redacted as `***`). |
| `PATCH` | `/config` | Partial update; response includes `restart_required` field names. |
| `GET` | `/config/schema` | JSON Schema for config keys (UI / tooling). |
| `POST` | `/identity/generate` | Generate Ed25519 master + operational keys and delegation proof; daemon does not retain the master key. |
| `POST` | `/identity/generate-ethereum` | Generate Ethereum AID, secp256k1 owner key, Ed25519 op key, and EIP-191 delegation proof; keys are not stored. |
| `POST` | `/ethereum/delegation-message` | Build EIP-191 `personal_sign` text from `agent`, `issued_at`, `expires_at`, and one of `operational_public_key_hex` / `operational_private_key_seed_hex`. |
| `POST` | `/ethereum/register` | Register Ethereum-keyed agent after wallet `personal_sign`: `agent`, timestamps, `eth_signature_hex`, optional `service_tcp`, op key. |
| `POST` | `/ethereum/proof` | Autonomous Ethereum delegation: `ethereum_private_key_hex` signs; op keys generated if omitted. |
| `POST` | `/agents` | Register delegated agent (`operational_private_key_hex`, `delegation_proof_hex`, `service_tcp` optional). |
| `GET` | `/agents` | List registered agents with status (`service_tcp_ok`, `heartbeat_seconds_ago`, `last_publish`). |
| `GET` | `/agents/{aid}` | Single agent status (reachability, publish info). |
| `PATCH` | `/agents/{aid}` | Update `service_tcp` (requires operational key); triggers implicit heartbeat. |
| `DELETE` | `/agents/{aid}` | Unregister agent. |
| `POST` | `/agents/{aid}/publish` | Publish/refresh DHT endpoint record. |
| `POST` | `/agents/{aid}/heartbeat` | Explicit agent liveness signal for auto-republish. |
| `POST` | `/agents/{aid}/records` | Sovereign custom record (RecType `0x02`–`0x0f`): `rec_type`, `payload_base64`, `ttl`; signed with operational key + delegation. |
| `POST` | `/agents/{aid}/mailbox/send` | Encrypted mailbox: JSON `recipient`, `msg_type`, `body_base64` → `{"ok":true}`. |
| `POST` | `/agents/{aid}/mailbox/poll` | Returns `{"messages":[{"sender","msg_type","body_base64"},...]}`. |
| `POST` | `/agents/{aid}/services` | Register service(s): `services`, `name`, `protocols`, `tags`, `brief`, optional `meta` (incl. `url` for self-hosted agents), `ttl`. |
| `DELETE` | `/agents/{aid}/services/{service...}` | Drop service from daemon renewal list (body `{}`); DHT entry expires by TTL. |
| `POST` | `/discover` | `{"services":["..."],"filter":{"protocols":[],"tags":[]}}` → `{"entries":[{"service","aid","name",...},...]}`. |
| `GET` | `/resolve/{aid}/records?type={rec_type}` | List verified `SignedRecord`s for remote AID; omit `type` or `type=0` for all RecTypes. Response `records[]` with `payload_base64`, `pubkey_base64`, `signature_base64`, etc. |
| `POST` | `/resolve/{aid}` | Resolve remote AID to endpoint record JSON. |
| `POST` | `/connect/{aid}` | Outbound tunnel: returns `{"tunnel":"127.0.0.1:<port>"}`; optional JSON `{"local_aid":"..."}` if multiple local agents. |
| `GET` | `/debug/...` | Same as `Host.DebugHTTPHandler()` (includes `/debug/host`). |
| (MCP) | `/mcp/` | Streamable HTTP handler from `modelcontextprotocol/go-sdk` (see below). |

### MCP (`a2ald`)

- **Streamable HTTP**: mounted at `/mcp/` on the API server.  
- **Stdio**: run `a2ald -mcp-stdio` (no HTTP API in that mode).

All tools: `a2al_identity_generate`, `a2al_agents_generate_ethereum`, `a2al_ethereum_delegation_message`, `a2al_ethereum_register`, `a2al_ethereum_proof`, `a2al_agents_list`, `a2al_agent_register`, `a2al_agent_get`, `a2al_agent_patch`, `a2al_agent_publish`, `a2al_agent_heartbeat`, `a2al_agent_delete`, `a2al_agent_publish_record`, `a2al_status`, `a2al_resolve_records`, `a2al_resolve`, `a2al_connect`, `a2al_mailbox_send`, `a2al_mailbox_poll`, `a2al_service_register`, `a2al_service_unregister`, `a2al_discover`.

---

## `config` — daemon TOML (library)

Used by `a2ald` and embeddable loaders.

| Function / method | Role |
|-------------------|------|
| `Default()` | Spec default field values. |
| `(*Config) Validate()` | Required fields and enums. |
| `LoadFile(path)` / `Save(path, c)` | TOML read/write. |
| `ApplyEnv(c)` | Overlay `A2AL_*` environment variables. |
| `(*Config) KeyDirOrDefault(dataDir)` | Resolve key directory. |

---

## Debug HTTP

Constant `dht.DebugHTTPAddr` is a suggested default (`127.0.0.1:2634`) when using `StartDebugHTTP` on a library-only `Host` or `Node`.

| Path | Provided by |
|------|----------------|
| `/debug/identity`, `/debug/routing`, `/debug/store`, `/debug/stats` | `dht.Node` (and `Host` via combined handler) |
| `/debug/host` | `Host` only — QUIC bind, registered agents, NAT/reflection summary |

All responses are read-only JSON.

---

## `natsense` — optional reads

When using `Host`, `Sense()` exposes consensus over reflected UDP endpoints:

- `MinAgreeing` / `SetMinAgreeing` — lower to `1` for small test networks.  
- `TrustedUDP` / `TrustedWire` / `InferNATType` — read trusted reflection and coarse NAT classification used when building published payloads.

---

## Not yet implemented (library / network)

- **TURN relay** — no `pion/turn` integration or relay addresses in published records yet.  
- **IPv6 dual-stack `Host` listener** — wire format supports IPv6; `New()` currently uses `udp4` only.

---

## Tests

```bash
go test -vet=off -count=1 ./...
```

Example programs under `examples/` use separate `go.mod` files and import the parent module via `replace`.
