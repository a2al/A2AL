# A2AL Architecture

## Concepts (start here)

**The one-sentence model:** every participant has a permanent address (an AID), and any two
addresses can find and connect to each other directly.

**AID** — not an IP, not a username, not a domain. It is a cryptographic address derived from a
key you generate locally, tied to you by math. Your IP changes; your AID does not. Someone stores
your AID in their contacts; it works the next time you change networks.

**Three operations — that is the whole protocol:**

```
Publish  — announce that you exist and where to find you right now
Resolve  — look up where someone is right now, given their AID
Connect  — open a direct, encrypted, mutually authenticated channel to them
```

After `Connect`, application data flows directly between the two endpoints. It does not pass
through the Tangled Network. The network's job is only addressing — it does not see your payload.

**Why NAT is not a problem:** the daemon tries direct connection first. When both sides are behind
NAT, it negotiates a path using ICE (the same mechanism browsers use for WebRTC calls). The
protocol figures out the route; your application code sees a plain connection.

**a2ald** is the local daemon that implements all of this, plus applications on top: 1:1 chat,
rooms, notes (offline-tolerant messages), file objects, and access control. REST, MCP, CLI, and
the Web UI are all interfaces to the same daemon.

---

## Protocol internals

A2AL is a peer-to-peer addressing and connectivity layer. An **AID** (cryptographic identity) maps to live endpoints on a DHT; two agents then open a mutual-TLS QUIC session. Application payloads travel on that session, not through the directory.

The **protocol** does not sit in the data path after connect and does not host application state. The **daemon** (`a2ald`) additionally offers local applications: notes, 1:1 chat, rooms, file objects, access control, MCP, REST, and the Web UI.

---

## Runtime

```
┌──────────────────────────────────────────────────────────────┐
│  a2ald — REST · MCP · Web UI · chat · rooms · notes · ACL    │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│  host — DHT + QUIC + NAT sense + UPnP + ICE + TURN (optional)│
└───┬──────────┬──────────────────────┬──────────────────┬─────┘
    │          │                      │                  │
  dht      transport              natsense           signaling
           (UDP mux,               natmap             (ICE hub)
            dual-stack)            (UPnP IPv4)
    │
 protocol — records, mailbox, topics, streams
 identity / crypto — AID, sign, delegation
```

Go programs that only need publish/resolve/connect depend on `host`. Everyone else talks to `a2ald`.

---

## Identity

An AID is 21 bytes: `[version 1][hash 20]`.

| Version | Scheme | Hash |
|---------|--------|------|
| `0xA0` | Ed25519 | `SHA-256(pubkey)[0:20]` |
| `0xA1` | P-256 | `SHA-256(pubkey)[0:20]` (byte assigned; no generate path in `a2ald`) |
| `0xA2` | Paralism / HASH160 | `RIPEMD160(SHA-256(pubkey))` |
| `0xA3` | Ethereum | `Keccak-256(pubkey)[12:32]` |

Display: native base58-like string, or `0x` hex for Ethereum/Paralism. Registry: [address-version-registry.md](address-version-registry.md).

**NodeID** = `SHA-256(version ‖ hash)` — DHT routing key only, not an application identity.

**Delegation.** Master key derives the AID and stays offline. Operational key publishes with a `DelegationProof`. Newer `delegation.IssuedAt` wins if keys rotate.

---

## Records (DHT)

Universal container: `SignedRecord` (CBOR). Verified on store and fetch: signature, TTL window, authority (self-sign or valid delegation).

| RecType | Role |
|---------|------|
| `0x01` | Endpoint record (`quic://` candidates, NAT hint, ICE signal URLs) |
| `0x02`–`0x0f` | Profile / custom signed records |
| `0x10` | Topic (Capability) at `SHA-256("topic:" ‖ name)` |
| `0x80` | Encrypted note (mailbox) at recipient NodeID |

Endpoint payloads may list **IPv4 and IPv6** `quic://` URLs. New nodes do **not** publish TURN URLs in the record; relay credentials stay local. Multi-hub ICE URLs use `Signals` (key 5); `Signal` (key 3) remains the primary URL for older peers.

---

## Connect

Wildcard listen (`:4121`) is **dual-stack** by default (`udp` on `[::]`; Windows: paired sockets). Explicit `1.2.3.4:port` stays IPv4-only. Go `host.Config.DisableIPv6` forces IPv4 (not a TOML key).

Dialers race candidates (Happy Eyeballs, IPv6 first when present). If direct QUIC fails and a signal URL is in the record, both sides use the **embedded ICE hub** (WebSocket trickle). Optional **external TURN** (static / HMAC / REST credentials) supplies relay candidates. UPnP IGD mapping is IPv4.

After TLS, stream 0 carries an **agent-route** frame so several AIDs can share one QUIC listener:

- Current: `a2r2` + 21-byte target AID, then a short control exchange, then data streams.
- Inbound still accepts legacy `a2r1` (25-byte frame only).

Service HTTP uses a dedicated stream type; file objects use a content-addressed stream. Unknown `a2*` magics are closed, not bridged to TCP.

**Access control** (daemon) applies to inbound HTTP and object fetch for that AID. Notes, DHT, and chat envelopes are not gated by the same allow/deny lists.

---

## Daemon applications (not the DHT)

| Feature | Behavior |
|------------|----------|
| Notes | Encrypted store-and-forward on the DHT mailbox |
| Chat | 1:1 after mutual invite; live path when connected, else local pending |
| Rooms | Per-AID signed replica; members sync over QUIC; objects by hash |
| ACL | Allow/deny + optional join password for that AID’s HTTP / objects |
| Profile | Signed name/brief/skills record (RecType 0x02) |
| Address book | Local aliases + favorites (`/node/address-book`) |
| Remote admin | Another AID may administer this node |
| AID URL | `http://127.0.0.1:2121/aid/{AID}/path` — local gateway, no extra port |

---

## Management API

Default `127.0.0.1:2121`. If `api_token` is set: loopback skips the token unless `require_local_token = true`; non-loopback always needs `Authorization: Bearer`. Empty token is open access (intentional). Credential export is loopback-only. Host header on loopback is checked against DNS rebinding.

---

## Related protocols

| | Role vs A2AL |
|--|----------------|
| **MCP** | Tool calling. `a2ald` is an MCP server. |
| **A2A / ANP** | Collaboration / networking vision. A2AL supplies addressing and connect. |
| **QUIC** | Agent-to-agent transport. |
| **ICE / STUN / TURN** | NAT traversal; TURN is an optional *external* server. |
