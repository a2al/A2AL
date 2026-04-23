# Examples

The `examples/` directory contains runnable demos that verify A2AL's core capabilities end to end.

---

## Quick start — pre-built binaries (recommended)

No Go installation required. Download the two releases and you're ready:

- **Demo binaries** (demo1 … demo6): [**Demo binaries (latest)**](https://github.com/a2al/a2al/releases/tag/demos-latest)
- **`a2ald` daemon**: [Main Releases page](https://github.com/a2al/a2al/releases)

Extract and place the binaries somewhere on your PATH, then follow the per-demo instructions below.

### Windows — unsigned binary warning

The demo and daemon binaries are currently **unsigned**. Windows SmartScreen will show a warning on first run — this is expected for open-source binaries that have not yet gone through the Microsoft code-signing process and does not indicate a security risk.

**To run anyway:**

1. Double-click (or run from PowerShell/Command Prompt) — a blue SmartScreen dialog appears.
2. Click **"More info"**.
3. Click **"Run anyway"**.

If Windows Defender flags the file, choose **"Allow on device"** or add an exclusion for the binary's folder.

> For developers who prefer to build from source, see the *Build from source* note at the end of each demo section.

---

## Overview

| Demo | What it verifies | Requires `a2ald` |
|------|-----------------|:---:|
| `demo6-swarm` | Dynamic multi-agent discovery and parallel QUIC sessions | Yes |
| `demo5-marketplace` | QUIC tunnel, direct HTTP service invocation | Yes |
| `demo4-marketplace` | Named service, encrypted notes, Sovereign Record | Yes |
| `demo3-chat` | Encrypted chat via daemon REST API | Yes |
| `demo2-chat` | QUIC, mutual TLS, NAT traversal; multi-candidate dial (Go library) | No |
| `demo1-node` | DHT node bootstrap, AID publishing, iterative resolution | No |

Demos 3–6 use `a2ald` as the network layer and focus on application-level behaviour. Demos 1–2 embed a DHT/QUIC node directly in the process and require no daemon.

---

## Prerequisites

- **Demos 1 and 2**: pre-built binary from [**Demo binaries (latest)**](https://github.com/a2al/a2al/releases/tag/demos-latest), or Go 1.22+ to build from source.
- **Demos 3–6**: `a2ald` running on each participating machine, plus a pre-built demo binary or Go 1.22+.

Start `a2ald` with no arguments on any internet-connected machine; it joins the public Tangled Network automatically.

Testing without an internet connection (offline or isolated network) requires a few extra parameters for `a2ald`. Refer to the comments at the top of each demo's source file for a full explanation.

---

## demo6-swarm — dynamic multi-agent swarm

**Verifies:** dynamic service discovery, parallel QUIC sessions, graceful handling of agents that go offline mid-session.

Planner searches the Tangled Network for available specialist agents (compliance, logistics, tariffs, localization), opens parallel QUIC tunnels to all found workers, collects their responses, and produces a consolidated report — without knowing in advance how many workers are online.

**Two machines (recommended):**
```
# Machine A — worker
a2ald
demo6-swarm --role worker

# Machine B — planner
a2ald
demo6-swarm --role planner
```

Start Worker first. Verify registered services in the Web UI (`http://localhost:2121`) → **Discover** tab: search `reason.evaluate`, `data.search`, `reason.analyze`, or `reason.recommend`.

**Single machine** (four terminals):
```
Worker  a2ald:   a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
Planner a2ald:   a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
                 --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
Worker  demo:    demo6-swarm --role worker
Planner demo:    demo6-swarm --role planner --api 127.0.0.1:2122
```

> **Build from source:** replace `demo6-swarm` with `go run .` inside `examples/demo6-swarm/`.

---

## demo5-marketplace — QUIC tunnel, direct HTTP invocation

**Verifies:** service discovery, `POST /connect/{aid}` QUIC tunnel, synchronous HTTP call through the tunnel without knowing the server's IP.

Seller exposes an HTTP question-answering service (`reason.qa`). Buyer discovers Seller, requests a QUIC tunnel from the daemon, and calls the HTTP endpoint directly through it.

**Two machines (recommended):**
```
# Machine A — seller
a2ald
demo5-marketplace --role seller

# Machine B — buyer
a2ald
demo5-marketplace --role buyer
```

Start Seller first. This demo requires two separate daemons even on a single machine (the QUIC tunnel is a cross-node operation).

**Single machine** (four terminals):
```
Seller a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
Buyer  a2ald:  a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
               --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
Seller demo:   demo5-marketplace --role seller
Buyer  demo:   demo5-marketplace --role buyer --api 127.0.0.1:2122
```

> **Build from source:** replace `demo5-marketplace` with `go run .` inside `examples/demo5-marketplace/`.

---

## demo4-marketplace — named service, encrypted notes, Sovereign Record

**Verifies:** named service registration and discovery, encrypted notes send and poll, Sovereign Record metadata.

Alice publishes a translation service as the named service `lang.translate`. Bob discovers it, sends a translation request via encrypted notes, and waits for the reply — without either party knowing the other's IP address.

**Two machines (recommended):**
```
# Machine A — alice
a2ald
demo4-marketplace --role alice

# Machine B — bob
a2ald
demo4-marketplace --role bob
```

Start Alice first; Bob discovers her automatically once both daemons have synced.

**Single machine, shared daemon** (demo4 uses only DHT — no QUIC cross-node dial required):
```
a2ald --fallback-host 127.0.0.1
demo4-marketplace --role alice   # terminal 2
demo4-marketplace --role bob     # terminal 3
```

**Single machine, two daemons** (full P2P isolation):
```
Alice a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
Bob   a2ald:  a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
              --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
Alice demo:   demo4-marketplace --role alice
Bob   demo:   demo4-marketplace --role bob --api 127.0.0.1:2122
```

> **Build from source:** replace `demo4-marketplace` with `go run .` inside `examples/demo4-marketplace/`.

---

## demo3-chat — encrypted chat via daemon

**Verifies:** agent registration, endpoint publish/resolve, QUIC tunnel establishment, bidirectional TCP gateway — all through the daemon REST API with no Go library dependency in the application.

On each of two machines, open two terminals:

```
a2ald        # network layer
demo3-chat   # chat app
```

Bob types Alice's AID → the daemon resolves and connects → bidirectional encrypted chat.

**Single machine** (four terminals):
```
Alice a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
Alice chat:   demo3-chat
Bob a2ald:    a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
              --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
Bob chat:     demo3-chat --api 127.0.0.1:2122
```

> **Build from source:** replace `demo3-chat` with `go run .` inside `examples/demo3-chat/`.

---

## demo2-chat — encrypted chat (Go library)

**Verifies:** `Publish`, `Resolve`, `ConnectFromRecord`, mutual TLS, agent-route, NAT sensing, UPnP, multi-candidate QUIC dial (try multiple paths).

Two nodes connect directly — no daemon involved. Bob types Alice's AID and a QUIC-encrypted session opens.

**Two machines (recommended):**
```
demo2-chat                             # Alice
demo2-chat -bootstrap <Alice-IP>:4121  # Bob
```

**Single machine:**
```
demo2-chat -listen :4121                            # Alice
demo2-chat -listen :4123 -bootstrap 127.0.0.1:4121  # Bob
```

Add `-debug :2634` to either side to inspect DHT and NAT state at `http://127.0.0.1:2634/debug/host`.

> **Build from source:** replace `demo2-chat` with `go run .` inside `examples/demo2-chat/`.

---

## demo1-node — DHT node basics

**Verifies:** identity generation, UDP bootstrap, AID publishing, iterative `FIND_VALUE` resolution.

A minimal DHT node. After startup it publishes its own endpoint record and accepts AID lookups typed on stdin.

```
demo1-node -listen :4121 -debug :2634                          # Node A
demo1-node -listen :4122 -bootstrap <A-IP>:4121 -debug :2635   # Node B
```

Inspect live state at `http://127.0.0.1:2634/debug/routing`.

> **Build from source:** replace `demo1-node` with `go run .` inside `examples/demo1-node/`.

---

## Single-machine notes

When running two `a2ald` instances on the same machine:

- Both need separate `--data-dir` paths to avoid key conflicts.
- The second daemon must use `--listen :4122` and `--api-addr 127.0.0.1:2122` to avoid port collisions (defaults: `:4121` and `127.0.0.1:2121`).
- Both need `--fallback-host 127.0.0.1` because loopback and private IPs are excluded from the automatic endpoint candidate list.
- The second daemon needs `--bootstrap 127.0.0.1:4121` to find the first.

On a LAN or offline network, replace `127.0.0.1` with the machine's LAN IP and point `--bootstrap` at the peer machine's `ip:4121`.
