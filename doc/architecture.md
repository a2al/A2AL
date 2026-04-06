# A2AL Architecture

## Overview

A2AL is a decentralized address resolution protocol. Its sole function is to map a cryptographic identity (AID) to current network endpoints, so that any two agents can establish a direct encrypted connection without prior knowledge of each other's IP address, network location, or deployment environment.

What A2AL does not do: route application data, operate as a message relay, or manage application-level state. Once a connection is established, the protocol steps aside. All data flows directly between agents.

The three protocol operations that compose the full interaction:

```
Publish  — agent announces its endpoints to the DHT
Resolve  — caller retrieves live endpoints for a target AID
Connect  — direct QUIC connection with mutual identity verification
```

---

## Module Map

```
┌─────────────────────────────────────────────────────────────┐
│                          daemon                              │
│          REST API · MCP Server · Web UI · auto-publish       │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                           host                               │
│    DHT + QUIC + NAT sensing + UPnP + ICE fallback           │
└───┬──────────┬──────────────────────┬──────────────────┬────┘
    │          │                      │                  │
┌───▼───┐  ┌──▼──────┐  ┌────────────▼──────┐  ┌───────▼────┐
│  dht  │  │transport│  │    natsense        │  │  signaling │
│       │  │(UDPMux) │  │ natmap (UPnP)      │  │(ICE/WS)    │
└───┬───┘  └─────────┘  └───────────────────┘  └────────────┘
    │
┌───▼───────────────────────────────────────────────────────┐
│                        protocol                            │
│     wire format · CBOR records · mailbox · topic          │
└───┬───────────────────────────────────────────────────────┘
    │
┌───▼─────────────────────────────────────────┐
│              identity / crypto               │
│   AID derivation · signing · delegation      │
└─────────────────────────────────────────────┘
```

Dependencies flow downward. `daemon` depends on `host`; `host` depends on `dht`, `transport`, `natsense`, `natmap`, `signaling`, and `protocol`; all depend on `identity`/`crypto` at the bottom.

---

## Module Descriptions

### `identity` / `crypto`

The foundation layer. `crypto` provides key generation, address derivation from public keys, and sign/verify primitives. `identity` builds the delegation model on top: a master key issues a `DelegationProof` authorizing an operational key to act on its behalf. The daemon uses the operational key day-to-day; the master key can remain offline.

Public surface: `Address`, `NodeID`, `KeyStore`, `GenerateEd25519`, `AddressFromPublicKey`, `SignDelegation`, `VerifyDelegation`.

### `protocol`

Defines all on-wire data structures as CBOR-encoded types: endpoint records, mailbox messages, topic (service) records, and the `SignedRecord` container. Also provides signing and verification helpers for each record type.

This package is the schema layer — it defines what gets stored in the DHT and transmitted on the wire, independently of how it is routed or transported.

### `transport`

UDP socket management. The key type is `UDPMux`, which demultiplexes a single UDP socket between the DHT and QUIC subsystems. When `host.Config.QUICListenAddr` is empty, DHT and QUIC share one port via this mux.

### `dht`

Kademlia-style distributed hash table. Implements iterative `FIND_NODE` and `FIND_VALUE` queries, `STORE` RPCs, bootstrap, and K-Bucket routing. Record storage enforces `RecordAuth` — callers can plug in custom authority logic (the default in `host` requires records to be either self-signed or carry a valid delegation proof).

The DHT does not know about QUIC or connections. It only routes and stores `SignedRecord` blobs.

### `natsense` / `natmap`

`natsense` collects reflected UDP addresses reported by DHT peers and infers the local NAT type (full cone, restricted, port-restricted, symmetric). `natmap` handles UPnP IGD port mapping requests to open external ports on home routers. Both feed candidate endpoint data to `host` during endpoint publishing.

### `signaling`

WebSocket-based ICE trickle signaling. Provides the room rendezvous model: two agents independently connect to a signaling server with a deterministic room ID (derived from both AIDs), exchange ICE candidates, and establish a peer-to-peer connection. Used as a fallback when direct QUIC connection fails.

### `host`

The primary integration layer for Go applications. `Host` composes all lower layers into a single runtime: it owns a DHT node, a QUIC transport, NAT sensing, and UPnP mapping. It exposes the three protocol operations (`PublishEndpoint`, `Resolve`, `ConnectFromRecord` / `Accept`) plus multi-agent routing (multiple AIDs sharing one QUIC listener via TLS SNI and agent-route framing).

Most Go applications that embed A2AL depend only on this package.

### `daemon`

The `a2ald` binary. Wraps `host` with a persistent service layer: auto-publish on a schedule, agent registration and lifecycle management, REST API, MCP server, embedded Web UI, and a config/persistence layer. Non-Go integrations use `a2ald` exclusively and never call `host` directly.

---

## Key Data Structures

### `Address` (AID)

```
[ version_byte (1 byte) ] [ hash (20 bytes) ]   = 21 bytes total
```

The version byte encodes the cryptographic scheme:

| Version | Scheme | Derivation |
|---------|--------|-----------|
| `0xA0` | Ed25519 | `SHA-256(pubkey)[0:20]` |
| `0xA1` | P-256 | `SHA-256(pubkey)[0:20]` |
| `0xA2` | Paralism / secp256k1+HASH160 | `RIPEMD160(SHA-256(pubkey))` |
| `0xA3` | Ethereum / secp256k1+Keccak | `Keccak-256(pubkey)[12:32]` |

Displayed as a ~44-character base58-like string (Ed25519 native) or `0x`-prefixed hex (Ethereum/Paralism). Parsing is automatic based on format.

See [`doc/address-version-registry.md`](address-version-registry.md) for the full registry and assignment process.

### `NodeID`

The DHT routing key, derived deterministically from an `Address`:

```
NodeID = SHA-256(version_byte || hash_20bytes)   = 32 bytes
```

`NodeID` is used only inside the DHT for XOR-distance routing. It is never exposed at the application layer. The separation allows the routing scheme to evolve independently of the identity scheme.

### `SignedRecord`

The universal on-wire container stored in the DHT:

| Field | Type | Description |
|-------|------|-------------|
| `RecType` | `uint8` | Record type: `0x01` endpoint, `0x10` topic, `0x80` mailbox, `0x02–0x0f` custom |
| `Address` | 21 bytes | AID of the publishing agent |
| `Pubkey` | bytes | Signing public key (may be an operational key) |
| `Payload` | bytes | CBOR-encoded type-specific payload |
| `Seq` | `uint64` | Monotone sequence number |
| `Timestamp` | `uint64` | Unix seconds |
| `TTL` | `uint32` | Validity window in seconds |
| `Signature` | bytes | Ed25519 or secp256k1 signature over canonical fields |
| `Delegation` | bytes | Optional CBOR `DelegationProof` (present when an operational key signs for a master-derived AID) |

Records are verified before storage and on retrieval: signature integrity, timestamp + TTL coverage of "now", and (at storage time) authority — the signing key must either derive the record's `Address` directly, or carry a valid `Delegation` from the master key that does.

### `EndpointPayload`

The payload carried in a `RecType 0x01` record:

| Field | Type | Description |
|-------|------|-------------|
| `Endpoints` | `[]string` | Network endpoints as URLs, e.g. `quic://1.2.3.4:4122` |
| `NatType` | `uint8` | Coarse NAT classification (unknown / full cone / restricted / port-restricted / symmetric) |
| `Signal` | `string` | Optional WebSocket base URL for ICE trickle signaling |
| `Turns` | `[]string` | Optional credential-free `turn://` relay hints for remote peers |

Multiple endpoint candidates are published per record (direct bind, UPnP-mapped, externally reflected). The connecting peer dials all candidates concurrently (Happy Eyeballs) and uses whichever succeeds first.

### `DelegationProof`

An authorization statement binding an operational key to a master AID:

| Field | Description |
|-------|-------------|
| `MasterAID` | The permanent AID being delegated for |
| `OperationalPubkey` | The Ed25519 public key authorized to publish on behalf of `MasterAID` |
| `Scope` | Permission scope (currently: network operations) |
| `IssuedAt` / `ExpiresAt` | Validity window (Unix seconds) |
| `Signature` | Master private key signature over the canonical fields |

The master private key is only needed to produce a `DelegationProof`. After that, `a2ald` holds only the operational key and the CBOR-encoded proof. Rotating credentials means issuing a new proof; the AID is unchanged.

### `TopicPayload`

The payload carried in a `RecType 0x10` (topic / service) record:

| Field | Type | Description |
|-------|------|-------------|
| `Name` | `string` | Human-readable agent name |
| `Protocols` | `[]string` | Supported protocols (e.g. `"mcp"`, `"http"`, `"a2a"`) |
| `Tags` | `[]string` | Capability tags for filtering |
| `Brief` | `string` | Short description (≤ 256 bytes) |
| `Meta` | map | Optional extended metadata (e.g. `url` for self-hosted agents) |

Topic records are stored at `SHA-256("topic:" + service_name)` in the DHT, not at the agent's own `NodeID`. Multiple agents can publish the same service name; the DHT aggregates all current registrants, enabling capability-based discovery.

---

## Connection Establishment

Two paths exist for establishing a QUIC connection between agents:

**Direct path (primary):** `ConnectFromRecord` dials all `Endpoints` from the target's endpoint record concurrently. The first successful QUIC handshake wins. Both sides perform mutual TLS with certificates derived from their Ed25519 keys — identity is verified as part of the handshake.

**ICE path (fallback):** When all direct dials fail and the endpoint record carries a `Signal` URL, both peers connect to the signaling server using a deterministic room ID and exchange ICE candidates via WebSocket trickle. A peer-to-peer UDP path is established through ICE; QUIC then runs over that path.

After either path, the client sends a 25-byte **agent-route frame** (`a2r1` prefix + 21-byte target AID) on the first QUIC stream. This allows multiple agents sharing one QUIC listener to be addressed independently.

---

## Relationship to Other Protocols

| Protocol | Role | Relationship |
|----------|------|-------------|
| **MCP** | Agent tool-calling interface | A2AL runs as an MCP server, exposing networking as tools. MCP defines the calling convention; A2AL provides the network. |
| **A2A** | Agent collaboration semantics | A2AL provides the discovery and connectivity layer A2A assumes but does not define. A2A messages flow over A2AL connections. |
| **ANP** | Agent networking vision | A2AL implements the decentralized network layer ANP describes conceptually. |
| **QUIC** | Transport | A2AL uses QUIC for all agent-to-agent connections. QUIC provides TLS 1.3, stream multiplexing, and connection migration. |
| **ICE/STUN** | NAT traversal | Used in the ICE fallback path. A2AL does not define its own NAT traversal protocol. |
