# Changelog

All notable changes to A2AL are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/).
Versions are `v0.x.y`. In 0.x, behavior may change between minors;
**Breaking:** is always marked, and names the surface that moved
(CLI, MCP, REST, protocol, or config).

GitHub Release notes are derived from each version section below.

## [Unreleased]

## [0.3.4] - 2026-10-07

v0.3.4 focuses on usability and transfer efficiency. The Web UI can now create and join rooms directly with links and interact with quotes and mentions. Files transfer peer-to-peer with encryption and background prefetch, without any cloud relay. Offline chat messages queue locally and drain automatically once peers reconnect. Notes now support read-only preview.

### Added

- **[Web UI]** Room creation, `a2al://` link join, room leave, `@mentions`, and quotes in the session bubble; local snapshot instant rendering and recent activity sorting.
- **[Notes]** Read-only inspection interfaces (REST `GET /agents/{aid}/mailbox`, CLI `a2al note list`, MCP `a2al_mailbox_list`).
- **[Files]** P2P file transfers, background prefetch, and remote fetch status flags (`fetched`).
- **[Rooms]** Public REST endpoints for room `append` and `leave`.
- **[CLI]** `--force` flag for `a2al group object get`; version alignment checks in `doctor` and `status`.

### Changed

- **[Chat]** Automatic draining of locally queued messages when peers reconnect; preserved file names across transfer boundaries.
- **[MCP]** Recommended inspect-then-poll flow for `pending.mailbox`; `chat.invites` returns peer inviter list.
- **[Docs]** Removed internal jargon and streamlined guides around concrete user jobs.

### Fixed

- **[Daemon]** Registry lock re-entry stall during concurrent operations.
- **[Tunnels]** Clearer connection refusal errors to avoid false 502s; fixed 415 error on empty request payloads.
- **[Rooms]** Suppressed sync error noise for unjoined rooms.

## [0.3.3] - 2026-10-01

A2AL evolves from point-to-point addressing into a multi-party collaboration environment. This release introduces serverless, fully end-to-end encrypted Rooms and 1:1 Chat, alongside Inbound Bind to expose local HTTP services behind an AID. Across the Web UI, CLI, and MCP, traffic never touches a third-party relay or central custodian.

### Added

- **[Rooms]** Distributed group protocol based on content-addressed storage (CAS) and vector clocks (`group store`, envelope types, and proof-of-work anti-abuse). CLI `a2al group create --aid <aid> [--title <title>]`; MCP `group_create`.
- **[Chat]** Mutual friend authentication and live 1:1 message transport. CLI `a2al chat request` / `a2al chat accept`; MCP `chat_request` / `chat_accept`.
- **[Tunnels]** `a2al inbound bind --addr <host:port> [--aid <local-aid>]` with a live-connection guard that revokes the bind when the conn drops.
- **[Web UI]** Collaboration bubble: identity **Room** button; in-bubble tabs **Room** / **Chat**.
- **[MCP]** `a2ald mcp add` host manager (Claude Code, VS Code, Cursor, Claude Desktop, Windsurf, OpenClaw, Hermes, DeepSeek Harness); `group_*` and `chat_*` tool families; `a2al_events_poll`.
- **[CLI]** Command families `a2al group`, `a2al chat`, and `a2al inbound`.
- **[Notes]** Hardened mailbox architecture with higher storage limits and event-log-driven delivery.

### Changed

- **[Network]** Learned-path outbound selection and Global Unicast Address (GUA) advertising.
- **[DHT]** Stronger DHT store and anti-flapping for faster convergence on multi-interface changes.

## [0.3.2] - 2026-08-23

After “can connect,” this release makes passage a configurable door. Per-identity ACL decides who may fetch your HTTP / file objects; the node can enable remote admin; a local address book remembers frequent AIDs. NAT detection and outbound path selection tighten further, so you stay findable after a network change.

### Added

- **[Install]** Identity ACL: allow/deny lists and IP-restricted service access.
- **[CLI]** `a2al agents acl*`, `a2al admin *`; `connect` / `tunnel open` gain `--access-token`.
- **[Web UI]** Access Control dialog, Remote admin, address book.
- **[Network]** Published service-address streams, GUA advertising, bootstrap fallback.

### Changed

- **[DHT]** Address authority, filter unverified self-advertised addresses, query/replication updates.
- **[Network]** Candidate selection and NAT type-detection accuracy.

## [0.3.1] - 2026-08-16

Outbound takes IPv6 seriously: candidates, Happy Eyeballs, and replica holders are selected by address family. UPnP mappings get lease renewal and backoff; the service stops before the package is removed. Resolve and connect paths are more observable to applications.

### Added

- **[Network]** Network-resolve API and user-facing connect helpers.
- **[Install]** deb/rpm: stop the service before removal.

### Changed

- **[Network]** v6-aware candidates, Happy Eyeballs.
- **[DHT]** Dual-stack replicas, TTL classes, query/replication probes, address-family-aware store writes.
- **[Daemon]** Helper resolve thresholds, connection-pool and dial-path improvements.

## [0.3.0] - 2026-07-13

Failed traversal has a definite end: ICE session exhaustion is detectable, tunnels can be reset. The gateway falls back when DHT is unhealthy. The Web UI moves publish and profile into dialogs; Discover / Agents interactions are reshuffled.

### Added

- **[Network]** ICE session exhaustion detection, address cache, ICE connect-path improvements.
- **[CLI]** `a2al tunnel reset`; advanced commands and auto-update status.
- **[Web UI]** Publish / profile dialogs; Discover / Agents rework and localization.

### Changed

- **[Daemon]** Gateway DHT fallback, tunnel reset, follow-on re-evaluation after network change.
- **[Tunnels]** Tunnel TLS, connection pooling, profile, routing and service updates.

### Fixed

- **[Network]** NAT detection and passive observation look up peers by address family (IPv4/IPv6).

## [0.2.9] - 2026-06-28

Symmetric NAT is classified per path; STUN probes are filtered more cleanly. After ICE disconnect, a released local address is no longer dereferenced. Replica-set renewal and inbound health evidence reduce “looks online, cannot connect.”

### Changed

- **[Network]** Per-path symmetric NAT, STUN-filtered mapping probes, Windows UDP retry.
- **[DHT]** Replica-set renewal, verified records vs unverified advertisements, store-API signature updates; publicly reachable nodes skip cold-start UDP; self-sovereign path cache.
- **[DHT]** Active replica tracking, inbound-evidence health gate.

### Fixed

- **[Network]** After ICE disconnect, do not read a released local address.
- **[DHT]** QUIC idle eviction.

## [0.2.8] - 2026-06-04

IPv6 routing, path quality, anchor fallback, stale-path invalidation, and network-change handling are tightened together.

### Changed

- **[Network]** IPv6 routing, path quality, anchor fallback, stale-path invalidation, network-change handling.
- **[Web UI]** Discover loads profile/service in parallel; localization.

## [0.2.7] - 2026-05-30

A node-level transport pool reuses ICE connections. Cold start bootstraps in parallel, ICE listens earlier, NAT detection is async. Symmetric NAT is detected per IP. MCP Registry `server.json` and a publish flow are added.

### Added

- **[Network]** Node transport pool, shared ICE.
- **[MCP]** MCP Registry publish flow, `server.json`.
- **[DHT]** Prefetch NAT endpoints before replication, recovery notifications, health-aware dial feedback.

### Changed

- **[Daemon]** Parallel bootstrap, early ICE listen, async NAT detection; signaling bootstrap falls back via the hub proxy.
- **[DHT]** FIND_NODE / FIND_VALUE routing fixes; replies faithfully reflect the sender.
- **[Network]** Per-IP symmetric NAT, cold-start consensus, same-socket STUN.

## [0.2.6] - 2026-05-24

Transport goes dual-stack: STUN/candidates, signaling hubs, and ICE/hole punch select IPv4 and IPv6 separately. Anchor vs live-endpoint addressing and inbound path learning land. ICE-aware send scheduling and gap-fill replication.

### Added

- **[Network]** Dual-stack IPv6 transport, STUN/candidates, hub discovery, ICE/hole punch.
- **[DHT]** Anchor vs live-endpoint addressing, inbound path learning, reachability-profile gating.
- **[DHT]** ICE-aware send scheduling, multipath routing, gap-fill replication.

## [0.2.5] - 2026-05-18

`a2ald` can stay resident as a system service: Windows install scripts and Service Control Manager integration, plus macOS launch-item improvements. Identities remain resolvable after the terminal closes.

### Added

- **[Install]** Windows service rewrite and install scripts; macOS service improvements; daemon–service integration.
- **[DHT]** Diagnostics.

## [0.2.4] - 2026-05-17

Notes get an on-disk mailbox: QUIC push, storage, subscriptions. The daemon can run as a system service, locks its data directory, and can auto-update. `--mcp-stdio` becomes a transparent proxy when a daemon is already running. The Web UI adds an update panel.

### Added

- **[Notes]** Persistent mailbox: QUIC push, store, subscription.
- **[Install]** System service, data-directory lock, event notifications, deploy config, auto-update.
- **[MCP]** Transparent stdio proxy.
- **[Web UI]** Update panel; published service-address improvements.

### Fixed

- **[Network]** Signaling registration-ack race.

## [0.2.3] - 2026-05-16

Identities export/import in a password envelope; the Web UI vault flow matches. Records become self-sovereign signed records. MCP tool descriptions are clearer. Delegation/record expiry tolerates clock skew.

### Added

- **[Install]** Encrypted export/import envelopes; Web UI vault.
- **[Protocol]** Self-sovereign record signatures.
- **[MCP]** Clearer tool descriptions; node info UI.

### Changed

- **[Web UI]** Identity import dialog; local/remote connection toggle.

### Fixed

- **[Protocol]** Clock-skew tolerance on delegation/record expiry.
- **[DHT]** Closer routing-table neighbors prefer ICE.

## [0.2.2] - 2026-05-12

When both sides sit behind symmetric NAT and direct hole punch fails, traffic can take TURN/relay (explicit config; third-party or self-hosted). ICE and the connection pool are relay-aware; the Web UI gains relay controls. Direct remains the default; relay is the fallback.

### Added

- **[Network]** TURN relay: dial options, explicit relay-required errors, relay-aware ICE and connection pooling.
- **[Daemon]** Relay-aware routing API, TURN configuration API, Web UI relay controls.

## [0.2.1] - 2026-05-10

DCUtR-style hole punching, parallel ICE racing, IPv6, and ICE endpoint caching. The daemon adds HTTPS tunnel listen, published service-address handling, and connection-pool improvements. Component-scoped logging, liveness probes, and Web UI polish.

### Added

- **[Network]** DCUtR-style hole punching, parallel ICE, IPv6, ICE endpoint cache.
- **[Tunnels]** HTTPS tunnel listen, published service address, connection pooling.
- **[Daemon]** Component-scoped logging, liveness-probe endpoint.
- **[Web UI]** Matching UI updates.

## [0.2.0] - 2026-05-10

The Web UI can add/import identities (including Ethereum), Discover is rebuilt, and favorites land. Self-sovereign record types are introduced. An AID resource gateway lets you fetch paths on a peer AID over local HTTP. QUIC/ICE dial in parallel.

### Added

- **[Web UI]** Identity export/generate APIs; add/import dialogs; Discover rebuild; favorites.
- **[Protocol]** Self-sovereign record types.
- **[Daemon]** AID resource gateway.
- **[Network]** Parallel QUIC/ICE dial (staggered by about 2s).
- **[Demo]** Multi-protocol demos keyed by caller AID.

### Fixed

- **[Network]** STUN candidates derived from the signaling hub, with Cloudflare fallback.

## [0.1.9] - 2026-05-03

CLI `a2al get` already existed. This release exposes the same capability on MCP (`a2al_fetch`) and in the Discover UI. Multiplexed tunnels arrive: `a2al tunnel open|close|status` and `a2al_tunnel_*`.

### Added

- **[CLI]** `a2al tunnel open|close|status` (`a2al get` has existed since v0.1.2).
- **[MCP]** `a2al_fetch`, `a2al_tunnel_open` / `close` / `list`.
- **[Web UI]** Discover integrates fetch and tunnel; agent-list sorting and version display.
- **[Daemon]** Multiplexed tunnel API, HTTP fetch, QUIC connection pool.

### Changed

- **[DHT]** STORE response policy fields; expired-record handling.

## [0.1.8] - 2026-05-02

A DHT-side NAT hole-punch pool joins query and replication. STORE policy fields and expired-record behavior are corrected. A transparent TCP forwarding gateway can report caller identity on a local port session.

### Added

- **[DHT]** NAT hole-punch pool, STORE replica backfill, observed-address piggyback, dual replica sets (XOR-distance + direct).
- **[Daemon]** Demo mode, transparent TCP gateway, Agents UI rewrite.
- **[Network]** Multi-signal ICE pool.

### Fixed

- **[DHT]** Replication reliability; expired STORE reports stored when the replica already holds the record.
- **[Web UI]** Protocol probe, publish-button copy, sorting.

## [0.1.7] - 2026-04-23

ICE signaling can use multiple hubs: the callee subscribes on each, the caller falls back in order. Bootstrap paths are hardened; the routing table is quality-managed. Linux packages restart the service after install so the new binary is actually running.

### Added

- **[Network]** Multi-hub ICE: per-hub subscribe, sequential fallback.
- **[DHT]** Hardened bootstrap, routing-table quality management.
- **[Examples]** Binary-first docs, multi-provider automatic fallback.

### Fixed

- **[Install]** Post-install script restarts the service.

## [0.1.6] - 2026-04-19

DHT queries move to a slotted engine; QUIC adds a peer control channel. When an endpoint expires or the published local service address changes, discovery records update automatically — so a live record is less likely to point at a dead address. Mailbox adds a public-key cache.

### Added

- **[DHT]** Slotted query engine, local store API, replica health repair.
- **[Network]** QUIC peer control channel, peer-info exchange.
- **[Notes]** Mailbox public-key cache (one fewer DHT lookup on reply).

### Fixed

- **[Daemon]** Automatic republish of discovery records on expired endpoints and local service-address changes.

## [0.1.5] - 2026-04-18

Failed bootstrap can recover: DNS routing, then automatic republish after recovery.

### Added

- **[Daemon]** Bootstrap recovery, DNS routing, automatic republish after recovery.
- **[Install]** Binaries carry version and build metadata.

## [0.1.4] - 2026-04-17

ICE gets a dedicated signaling hub, protocol signals, and a TURN credential model, wired into the local transport. Network changes are debounced before follow-on work; ICE listeners keep alive. Outbound QUIC uses identity certificates for mutual TLS (mTLS); inbound ICE is accepted through a shared gateway.

### Added

- **[Network]** ICE signaling hub, protocol signals, TURN credentials, local transport integration.
- **[Daemon]** Debounced network-change handling and follow-on re-evaluation, ICE listener keepalive, QUIC diagnostics.

### Fixed

- **[Network]** Identity-certificate mTLS; inbound ICE accepted through a shared gateway.

## [0.1.3] - 2026-04-15

First documentation set: Quick Start, User Guide, API, Architecture. Identities republish automatically when endpoints change. Discover / Agents UI improvements, with per-identity publish.

### Added

- **[Docs]** Quick Start, User Guide, API reference, architecture.
- **[Daemon]** Republish discovery records on endpoint change; per-identity publish API.
- **[Web UI]** Discover / Agents improvements.

### Changed

- **[DHT]** Asynchronous replication, trusted-source routing, NAT classification TTL, endpoint port fixes.

### Fixed

- **[Daemon]** Startup logging; QUIC multiplexer receive buffer.

## [0.1.2] - 2026-04-06

First installable A2AL release: local daemon `a2ald` (REST, embedded Web UI, MCP), CLI `a2al`, and npm / PyPI packages. Identity is an **AID** derived from a key you hold. After you publish it to the decentralized network, others resolve by AID and open mutually authenticated encrypted connections. NAT traversal (QUIC, ICE, UPnP, Happy Eyeballs) runs inside the daemon. Notes (mailbox) can be delivered while a peer is offline. Optional Ethereum / secp256k1 identities and delegation.

### Added

- **[Protocol]** DHT, endpoint publishing, QUIC transport, NAT type detection, UPnP, Happy Eyeballs.
- **[Daemon]** REST, MCP (`--mcp-stdio` or HTTP), Web UI, auto-publish and heartbeat.
- **[CLI]** `status` `register` `publish` `unpublish` `search` `get`, `resolve` `connect`, `note send|poll`, `agents *`, `identity new|new-eth`.
- **[MCP]** `a2al_identity_generate`, `a2al_resolve`, `a2al_connect`, `a2al_mailbox_*`, `a2al_discover`, Ethereum delegation tools.
- **[Install]** npm `a2ald` platform packages, PyPI `a2al` sidecar.
- **[Identity]** Ed25519 AID; Ethereum/secp256k1 and delegation; Paralism address support.

### Security

- **[Daemon]** Hardened key and DHT data paths.

[Unreleased]: https://github.com/a2al/a2al/compare/v0.3.4...HEAD
[0.3.4]: https://github.com/a2al/a2al/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/a2al/a2al/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/a2al/a2al/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/a2al/a2al/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/a2al/a2al/compare/v0.2.9...v0.3.0
[0.2.9]: https://github.com/a2al/a2al/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/a2al/a2al/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/a2al/a2al/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/a2al/a2al/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/a2al/a2al/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/a2al/a2al/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/a2al/a2al/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/a2al/a2al/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/a2al/a2al/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/a2al/a2al/compare/v0.1.9...v0.2.0
[0.1.9]: https://github.com/a2al/a2al/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/a2al/a2al/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/a2al/a2al/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/a2al/a2al/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/a2al/a2al/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/a2al/a2al/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/a2al/a2al/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/a2al/a2al/releases/tag/v0.1.2
