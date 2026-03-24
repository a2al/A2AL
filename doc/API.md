# A2AL Go library — API reference

This document describes the **public surfaces** intended for application developers: discovery, signed endpoint records, and QUIC sessions. It reflects the current repository layout (`module github.com/a2al/a2al`).

## Integration levels

| Level | Package | Use when |
|--------|---------|----------|
| **Node runtime** | `github.com/a2al/a2al/host` | You want DHT + QUIC on one or two UDP ports, mutual TLS between agents, and helpers to publish/resolve endpoints. |
| **DHT only** | `github.com/a2al/a2al/dht` | You supply your own transport and only need routing, bootstrap, and iterative `FIND_VALUE` / `STORE`. |

Lower-level packages (`transport`, `routing`, internal mux details) are building blocks; most applications should depend on `host` or `dht` only.

---

## `host` — `Host`

A `Host` runs a DHT `Node`, optional UDP demux for DHT+QUIC on a single port, a QUIC listener, and NAT/reflection hints via `natsense.Sense`.

### Configuration (`host.Config`)

| Field | Meaning |
|-------|---------|
| `KeyStore` | Required. Must list **exactly one** `Address` (see `crypto.KeyStore`). |
| `ListenAddr` | DHT UDP bind, e.g. `":5001"`. |
| `QUICListenAddr` | If non-empty, QUIC binds here **separately** from DHT. If empty, QUIC shares the DHT UDP socket (mux). |
| `PrivateKey` | Ed25519 key for QUIC/TLS. If nil, `EncryptedKeyStore.Ed25519PrivateKey` is used when available; otherwise set explicitly. |
| `MinObservedPeers` | Minimum distinct peers that must report the same reflected address before `Sense` treats it as trusted (default 3 if ≤0). |
| `FallbackHost` | Optional advertised host when bind address and reflection data are ambiguous (e.g. `0.0.0.0`). |

### Lifecycle

1. `host.New(cfg)` — starts the DHT receive loop and QUIC listener.  
2. `h.Node().BootstrapAddrs(ctx, []net.Addr{...})` (or `StartWithBootstrap` on a bare `Node`).  
3. Optionally `h.ObserveFromPeers(ctx, seeds)` to seed observed-address sampling.  
4. `h.PublishEndpoint`, `h.Resolve`, `h.Connect`, `h.Accept` as needed.  
5. `h.Close()`

### Primary methods

| Method | Role |
|--------|------|
| `PublishEndpoint(ctx, seq, ttl)` | Builds `quic://` endpoint payload (NAT hint, optional reflection), signs, stores on the DHT. |
| `Resolve(ctx, target Address)` | Iterative lookup; returns `*protocol.EndpointRecord`. |
| `Connect(ctx, expectRemote Address, udpAddr)` | QUIC dial with mutual TLS; opens first stream and sends **agent-route** frame (see below). Returns `quic.Connection`. |
| `Accept(ctx)` | Blocks for inbound QUIC; returns `*AgentConn` with `Local` / `Remote` addresses. |
| `FirstQUICAddr(er)` | Parses first `quic://` or legacy `udp://` entry from an `EndpointRecord` to `*net.UDPAddr`. |
| `BuildEndpointPayload()` | Same addressing logic as publish, without signing or storing. |
| `RegisterAgent` / `UnregisterAgent` / `RegisteredAgents` | Extra agent identities on the same QUIC listener (TLS SNI + agent-route). |
| `Address`, `DHTLocalAddr`, `QUICLocalAddr` | Introspection. |
| `Node()`, `Sense()` | Access underlying DHT node or NAT/reflection state. |
| `ObserveFromPeers` | Triggers ping/bootstrap-style contact to collect `observed_addr` for `Sense`. |
| `StartDebugHTTP(addr)` / `DebugHTTPHandler()` | Read-only JSON (see Debug HTTP). |
| `Close()` | Shuts down QUIC, mux, and DHT. |

### `AgentConn`

Embeds `quic.Connection`. Fields:

- `Local` — agent `Address` selected for this connection (agent-route frame, else SNI, else default).  
- `Remote` — peer `Address` from the mutual TLS client certificate (inbound).

### QUIC agent-route (interoperability)

After the TLS handshake, the **client** MUST open a stream and write **25 bytes**: prefix `a2r1` (ASCII) followed by the 21-byte binary `Address` of the intended server agent. The server uses this for routing when multiple agents share one listener; TLS SNI is a secondary hint.

---

## `dht` — `Node`

Use when you implement your own stack but need Kademlia-style RPCs and storage.

### Lifecycle

1. `dht.NewNode(dht.Config{Transport, Keystore})` — keystore must list exactly one identity  
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
| `NewQuery(n).Resolve(ctx, NodeID)` | Iterative endpoint fetch. |
| `NewQuery(n).FindNode(ctx, NodeID)` | Iterative `FIND_NODE`. |
| `StartDebugHTTP` / `DebugHTTPHandler()` | Same DHT JSON as under `Host` (no `/debug/host`). |

`Config.OnObservedAddr` exists for custom wiring; `Host` sets it automatically when using the bundled node.

---

## Identity and signing

| Package | Items |
|---------|--------|
| `github.com/a2al/a2al` | `Address`, `NodeID`, `ParseAddress`, `NodeIDFromAddress` |
| `github.com/a2al/a2al/crypto` | `KeyStore`, `EncryptedKeyStore` (optional `Ed25519PrivateKey` for QUIC) |
| `github.com/a2al/a2al/crypto` | `AddressFromPublicKey`, `GenerateEd25519`, detached sign/verify helpers |

---

## Endpoint records (`protocol`)

| Item | Role |
|------|------|
| `EndpointPayload` | `Endpoints []string` (use `quic://host:port`), `NatType uint8` |
| `EndpointRecord` | Decoded view after verify (`Address`, `Endpoints`, `NatType`, `Seq`, `Timestamp`, `TTL`) |
| `SignEndpointRecord(priv, addr, payload, seq, timestamp, ttl)` | Build `SignedRecord` for DHT store |
| `ParseEndpointRecord(sr)` | Verify and decode to `EndpointRecord` |
| NAT constants | `NATUnknown`, `NATFullCone`, `NATRestricted`, `NATPortRestricted`, `NATSymmetric` |

`timestamp` + `TTL` must cover “now” or verification/storage fails.

---

## Debug HTTP

Constant `dht.DebugHTTPAddr` is a suggested default (`127.0.0.1:2634`).

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

## Tests

```bash
go test -vet=off -count=1 ./...
```

Example programs under `examples/` use separate `go.mod` files and import the parent module via `replace`.
