# A2AL Go library

Public surfaces for embedding A2AL: `host`, `dht`, `protocol`, `identity`, `crypto`. Module: `github.com/a2al/a2al`.

Daemon REST, MCP, and Python: [API Reference](api-reference.md). Concepts: [Architecture](architecture.md).

| Level | Package | Use when |
|--------|---------|----------|
| Node runtime | `github.com/a2al/a2al/host` | DHT + QUIC, publish / resolve / connect |
| DHT only | `github.com/a2al/a2al/dht` | Routing and STORE/FIND with your own transport |
| Daemon | `a2ald` | REST, Web UI, MCP — do not import `host` unless you embed |

---

## `host.Host`

DHT node, UDP mux or split QUIC socket, NAT/reflection (`natsense`), ICE, optional TURN.

Wildcard `ListenAddr` / `QUICListenAddr` (`:4121`, `0.0.0.0:port`) bind **dual-stack**. Explicit IPv4 stays IPv4-only. `DisableIPv6` forces `udp4` (library only; not a daemon TOML key).

### `host.Config`

| Field | Meaning |
|-------|---------|
| `KeyStore` | Required. Exactly one `Address`. |
| `ListenAddr` | DHT UDP bind (default `":4121"`). Dual-stack unless a specific IPv4/IPv6 host is set. |
| `QUICListenAddr` | Empty: share the DHT socket (mux). Non-empty: separate QUIC bind. |
| `PrivateKey` | Ed25519 for QUIC/TLS. Else `EncryptedKeyStore.Ed25519PrivateKey`. |
| `MinObservedPeers` | Peers that must agree on a reflected address (default 3). |
| `FallbackHost` | Advertised host when bind/reflection is ambiguous. |
| `DisableUPnP` | Skip IGD mapping of the QUIC port (IPv4). |
| `DisableIPv6` | Force IPv4-only sockets. |
| `ICESignalURL` / `ICESignalURLs` | ICE WebSocket hubs. Non-empty `ICESignalURLs` wins; first URL is also `EndpointPayload.Signal`. |
| `ICESTUNURLs` | `stun:` URIs. Empty: public STUN if no TURN. |
| `ICETURNURLs` | Legacy `turn:` with embedded credentials. Prefer `TURNServers`. |
| `TURNServers` | External TURN: `URL`, `Username`, `Credential`, `CredentialType` (`static` / `hmac` / `rest_api`). Credentials are per ICE session, never published. |
| `ICEPublishTurns` | Deprecated. New nodes do not write `turns[]` on the DHT. |
| `DisableRelay` | If true, omit TURN relay candidates by default. Per-call: `DialOptions.DisableRelay`. Default false (relay allowed when TURN is configured). |
| `ICENetworkTypes` | ICE networks; default UDP4+UDP6. |
| `Logger` | `*slog.Logger`; default `slog.Default()`. |

`RecordAuth` on the inner DHT node requires self-sign or a valid delegation.

### Lifecycle

1. `host.New(cfg)`
2. `h.Node().BootstrapAddrs(ctx, []net.Addr{...})` — seeds are `ip:port`
3. Optional `ObserveFromPeers`
4. `PublishEndpoint` / `Resolve` / `ConnectFromRecord` / `Accept`
5. `h.Close()`

### Methods

| Method | Role |
|--------|------|
| `PublishEndpoint` / `PublishEndpointForAgent` | Sign and STORE a multi-candidate `quic://` payload (v4/v6, UPnP when enabled). |
| `Resolve` | Iterative lookup → `*protocol.EndpointRecord`. |
| `Connect` | QUIC to one UDP address + agent-route. |
| `ConnectFromRecord` / `ConnectFromRecordFor` | Happy Eyeballs over record endpoints; ICE if direct fails and a signal URL is present. Returns `(conn, isRelayed, err)`. `ErrRelayRequired` when relay is configured but disabled and direct failed. |
| `Accept` | Inbound QUIC → `*AgentConn`. |
| `QUICDialTargets` / `FirstQUICAddr` | Ordered UDP targets from a record. |
| `BuildEndpointPayload` | Candidates only; no STORE. |
| `SymmetricNATReachabilityHint` | Non-empty when NAT looks symmetric (relay may still be needed). |
| `RegisterAgent` / `RegisterDelegatedAgent` / `UnregisterAgent` / `RegisteredAgents` | Extra AIDs on one listener. |
| `SendMailbox` / `PollMailbox` (+ `ForAgent`) | Encrypted notes. |
| `RegisterTopic(s)` / `SearchTopic(s)` (+ `ForAgent`) | Capability rendezvous. |
| `StartDebugHTTP` / `DebugHTTPHandler` | Read-only JSON. |
| `Close` | QUIC, mux, DHT, UPnP cleanup. |

`AgentConn` embeds `quic.Connection` with `Local` / `Remote` AIDs.

### Agent-route

After TLS, the client writes **4-byte magic + 21-byte target AID** on stream 0.

- **`a2r2`** (current): length-prefixed control messages, then both sides FIN that stream; data uses later streams. `host` implements this.
- **`a2r1`**: still accepted inbound (frame only).

TLS SNI is a secondary hint when several agents share a listener.

---

## `dht.Node`

| Field | Meaning |
|-------|---------|
| `Transport` | Required. |
| `Keystore` | Required. One identity. |
| `OnObservedAddr` | Reflected addresses. |
| `RecordAuth` | After `VerifySignedRecord`; nil = no authority check. |

`BootstrapAddrs` takes `ip:port` only. `PublishMailboxRecord` / `PublishTopicRecord` STORE at recipient or topic NodeID.

---

## Identity

| Package | Items |
|---------|--------|
| `github.com/a2al/a2al` | `Address`, `NodeID`, `ParseAddress`, `NodeIDFromAddress` |
| `…/crypto` | `KeyStore`, `EncryptedKeyStore`, `AddressFromPublicKey`, `GenerateEd25519` |
| `…/identity` | `SignDelegation`, `VerifyDelegation`, Ethereum/Paralism helpers |

---

## `protocol`

| Item | Role |
|------|------|
| `SignedRecord` | On-wire CBOR; optional `Delegation`. |
| `EndpointPayload` | `Endpoints` (`quic://host:port` or `quic://[v6]:port`), `NatType`, `Signal`, `Signals`. `Turns` is decoded from old records; **new publishes omit it**. |
| `SignEndpointRecord` / `SignEndpointRecordDelegated` | Master vs operational key. |
| `ParseEndpointRecord` / `VerifySignedRecord` | Verify does not enforce pubkey↔AID (use `RecordAuth`). |
| Mailbox | `RecTypeMailbox` `0x80`; X25519 + AES-GCM helpers. |
| Topic | `RecTypeTopic` `0x10`; key `SHA-256("topic:" ‖ name)`; `DiscoverFilter`. |

`timestamp` + `TTL` must cover now.

---

## `config` (daemon TOML)

`Default()`, `Validate()`, `LoadFile` / `Save`, `ApplyEnv`. Example: [a2ald-config.example.toml](a2ald-config.example.toml).

---

## Debug HTTP

Suggested bind: `dht.DebugHTTPAddr` (`127.0.0.1:2634`) for a library `Host`/`Node`. Daemon exposes the same under `/debug/` on the API address.

| Path | Source |
|------|--------|
| `/debug/identity`, `/debug/routing`, `/debug/store`, `/debug/stats` | `dht.Node` |
| `/debug/host` | `Host` — QUIC bind, agents, NAT summary |

---

## `natsense`

`Sense()`: `TrustedUDP` / `TrustedUDPAll` (v4 and v6), `InferNATType`, `InferV6Reach`. Lower `MinAgreeing` for tiny test nets.

---

## Tests

```bash
go test -vet=off -count=1 ./...
```

`examples/` use their own `go.mod` with `replace`.
