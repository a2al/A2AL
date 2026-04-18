# Examples

The `examples/` directory contains runnable demos that verify A2AL's core capabilities end to end.

---

## Running without a Go environment

You don't need to install Go. Download the pre-built demo binaries from the [**Demo binaries (latest)**](https://github.com/a2al/a2al/releases/tag/demos-latest) release and `a2ald` from the [main Releases page](https://github.com/a2al/a2al/releases), then follow the instructions below — just replace every `go run .` with the binary name.

| Instead of | Use |
|------------|-----|
| `go run .` in `demo3-chat/` | `demo3-chat` |
| `go run .` in `demo4-marketplace/` | `demo4-marketplace` |
| `go run .` in `demo5-marketplace/` | `demo5-marketplace` |
| `go run .` in `demo6-swarm/` | `demo6-swarm` |

---

## Overview

| Demo | What it verifies | Requires `a2ald` |
|------|-----------------|:---:|
| `demo6-swarm` | Dynamic multi-agent discovery and parallel QUIC sessions | Yes |
| `demo5-marketplace` | QUIC tunnel, direct HTTP service invocation | Yes |
| `demo4-marketplace` | Named service, encrypted notes, Sovereign Record | Yes |
| `demo3-chat` | Encrypted chat via daemon REST API | Yes |
| `demo2-chat` | QUIC, mutual TLS, NAT traversal; multi-candidate dial (try multiple paths) (Go library) | No |
| `demo1-node` | DHT node bootstrap, AID publishing, iterative resolution | No |

Demos 3–6 use `a2ald` as the network layer and focus on application-level behaviour. Demos 1–2 embed a DHT/QUIC node directly in the process and require no daemon.

---

## Prerequisites

- **Demos 1 and 2**: Go 1.22+ or a pre-built binary from [**Demo binaries (latest)**](https://github.com/a2al/a2al/releases/tag/demos-latest).
- **Demos 3–6**: `a2ald` running on each participating machine, plus Go 1.22+ or a pre-built demo binary from [**Demo binaries (latest)**](https://github.com/a2al/a2al/releases/tag/demos-latest).

Start `a2ald` with no arguments on any internet-connected machine; it joins the public Tangled Network automatically.

Testing without an internet connection (offline or isolated network) requires a few extra parameters for `a2ald`. The commands are longer but straightforward — refer to the comments at the top of each demo's source file for a full explanation of every parameter.

---

## demo6-swarm — dynamic multi-agent swarm

**Verifies:** dynamic service discovery, parallel QUIC sessions, graceful handling of agents that go offline mid-session.

Planner searches the Tangled Network for available specialist agents (market analysis, legal, logistics, localization), opens parallel QUIC tunnels to all found workers, collects their responses, and produces a consolidated report — without knowing in advance how many workers are online.

**Two machines (recommended):**
```bash
# Machine A — worker
a2ald
go run . --role worker      # or: demo6-swarm --role worker

# Machine B — planner
a2ald
go run . --role planner     # or: demo6-swarm --role planner
```

Start Worker first. You can verify registered services in the Web UI (`http://localhost:2121`) under the **Discover** tab: search for `reason.evaluate`, `data.search`, `reason.analyze`, or `reason.recommend`.

**Single machine** (four terminals):
```bash
Worker  a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
Planner a2ald:  a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
                --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
Worker  demo:   go run . --role worker
Planner demo:   go run . --role planner --api 127.0.0.1:2122
```

---

## demo5-marketplace — QUIC tunnel, direct HTTP invocation

**Verifies:** service discovery, `POST /connect/{aid}` QUIC tunnel, synchronous HTTP call through the tunnel without knowing the server's IP.

Seller exposes an HTTP question-answering service (`reason.qa`). Buyer discovers Seller, requests a QUIC tunnel from the daemon, and calls the HTTP endpoint directly through it.

**Two machines (recommended):**
```bash
# Machine A — seller
a2ald
go run . --role seller      # or: demo5-marketplace --role seller

# Machine B — buyer
a2ald
go run . --role buyer       # or: demo5-marketplace --role buyer
```

Start Seller first. This demo requires two separate daemons even on a single machine (the QUIC tunnel is a cross-node operation).

**Single machine** (four terminals):
```bash
Seller a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
Buyer  a2ald:  a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
               --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
Seller demo:   go run . --role seller
Buyer  demo:   go run . --role buyer --api 127.0.0.1:2122
```

---

## demo4-marketplace — named service, encrypted notes, Sovereign Record

**Verifies:** named service registration and discovery, encrypted notes send and poll, Sovereign Record metadata.

Alice publishes a translation service as the named service `lang.translate`. Bob discovers it, sends a translation request via encrypted notes, and waits for the reply — without either party knowing the other's IP address.

**Two machines (recommended):**
```bash
# Machine A — alice
a2ald
go run . --role alice       # or: demo4-marketplace --role alice

# Machine B — bob
a2ald
go run . --role bob         # or: demo4-marketplace --role bob
```

Start Alice first; Bob discovers her automatically once both daemons have synced.

**Single machine, shared daemon** (demo4 uses only DHT — no QUIC cross-node dial required):
```bash
a2ald --fallback-host 127.0.0.1
go run . --role alice   # terminal 2
go run . --role bob     # terminal 3
```

**Single machine, two daemons** (full P2P isolation):
```bash
Alice a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
Bob   a2ald:  a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
              --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
Alice demo:   go run . --role alice
Bob   demo:   go run . --role bob --api 127.0.0.1:2122
```

---

## demo3-chat — encrypted chat via daemon

**Verifies:** agent registration, endpoint publish/resolve, QUIC tunnel establishment, bidirectional TCP gateway — all through the daemon REST API with no Go library dependency in the application.

On each of two machines, open two terminals:

```bash
a2ald          # network layer
go run .       # chat app  (or: demo3-chat)
```

Bob types Alice's AID → the daemon resolves and connects → bidirectional encrypted chat.

**Single machine** (four terminals):
```bash
Alice a2ald:  a2ald --data-dir ./tmp/a --fallback-host 127.0.0.1
Alice chat:   go run .
Bob a2ald:    a2ald --data-dir ./tmp/b --listen :4122 --api-addr 127.0.0.1:2122 \
              --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121
Bob chat:     go run . --api 127.0.0.1:2122
```

---

## demo2-chat — encrypted chat (Go library)

**Verifies:** `Publish`, `Resolve`, `ConnectFromRecord`, mutual TLS, agent-route, NAT sensing, UPnP, multi-candidate QUIC dial (try multiple paths).

Two nodes connect directly — no daemon involved. Bob types Alice's AID and a QUIC-encrypted session opens.

**Two machines (recommended):**
```bash
go run .                             # Alice
go run . -bootstrap <Alice-IP>:4121  # Bob
```

**Single machine:**
```bash
go run . -listen :4121                            # Alice
go run . -listen :4123 -bootstrap 127.0.0.1:4121  # Bob
```

Add `-debug :2634` to either side to inspect DHT and NAT state at `http://127.0.0.1:2634/debug/host`.

---

## demo1-node — DHT node basics

**Verifies:** identity generation, UDP bootstrap, AID publishing, iterative `FIND_VALUE` resolution.

A minimal DHT node. After startup it publishes its own endpoint record and accepts AID lookups typed on stdin.

```bash
go run . -listen :4121 -debug :2634                          # Node A
go run . -listen :4122 -bootstrap <A-IP>:4121 -debug :2635   # Node B
```

Inspect live state at `http://127.0.0.1:2634/debug/routing`.

---

## Single-machine notes

When running two `a2ald` instances on the same machine:

- Both need separate `--data-dir` paths to avoid key conflicts.
- The second daemon must use `--listen :4122` and `--api-addr 127.0.0.1:2122` to avoid port collisions (defaults: `:4121` and `127.0.0.1:2121`).
- Both need `--fallback-host 127.0.0.1` because loopback and private IPs are excluded from the automatic endpoint candidate list.
- The second daemon needs `--bootstrap 127.0.0.1:4121` to find the first.

On a LAN or offline network, replace `127.0.0.1` with the machine's LAN IP and point `--bootstrap` at the peer machine's `ip:4121`.
