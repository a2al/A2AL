# Developer Guide

For people who want to build on A2AL at the code level: embed the Go library, extend the
daemon, run the test suite, or contribute.

---

## Build from source

Requirements: Go 1.24+

```bash
git clone https://github.com/a2al/a2al
cd a2al

go build ./cmd/a2ald   # the daemon
go build ./cmd/a2al    # the CLI
```

Place the binaries in your PATH or run them directly from the build output.

---

## Tests

```bash
go test -vet=off -count=1 ./...
```

The test suite covers the DHT, protocol, identity, host, and daemon layers.
`-vet=off` is needed because some generated code triggers vet; `-count=1` disables caching.
Tests that spin up a real DHT require network access (loopback is fine).

```bash
go test -vet=off -count=1 -run TestConnPool ./daemon/...   # one package, one test
```

The `examples/` directory has its own `go.mod` with a `replace` directive pointing at the
local module root. Run them with `go run .` inside each sub-directory.

---

## Codebase map

| Directory | Contents |
|-----------|----------|
| `cmd/a2ald/` | Daemon entry point, service install, MCP add |
| `cmd/a2al/` | CLI entry point and subcommands (`commands_*.go`) |
| `daemon/` | REST routes, MCP server, tunnel, fetch, ACL, group, chat, CAS |
| `dht/` | Kademlia DHT node — STORE / FIND_VALUE / routing table |
| `host/` | Public embedding surface: publishes, resolves, connects, accepts |
| `protocol/` | On-wire CBOR types, signed records, mailbox, topic |
| `identity/` | Delegation proofs, Ethereum / Paralism helpers |
| `crypto/` | KeyStore, Ed25519, AES-GCM, address derivation |
| `chat/` | 1:1 chat store and delivery |
| `group/` | Room store, append, sync, CAS objects |
| `natsense/` | NAT type sensing, UPnP IGD |
| `signaling/` | ICE WebSocket signal hub (embedded in a2ald) |
| `transport/` | UDP mux, dual-stack binding |
| `examples/` | Standalone demos, each with their own `go.mod` |

The daemon imports `host` but the reverse is not true. Code that only needs
publish/resolve/connect should import `host` and not reference `daemon`.

---

## Hello World — embed the Go library

The compiling example is `examples/demo2-chat` (identity, `host.New`, optional seed, publish, accept/connect). Copy that; do not paste a shortened sketch.

Sequence:

1. Implement `crypto.KeyStore` — see `examples/demo2-chat/keystore.go`.
2. `host.New(host.Config{KeyStore, ListenAddr, PrivateKey})`.
3. Optional seed: `h.Node().BootstrapAddrs(ctx, []net.Addr{udp})` where `udp` is `ip:port`. Empty bootstrap does **not** join the public DNS list; that path lives in `a2ald`, not in `host`.
4. `h.PublishEndpoint(ctx, seq, ttl)`.
5. `h.Accept(ctx)` inbound, or `h.Resolve` then `h.ConnectFromRecord` outbound.

Do not treat `_a2al-bootstrap.a2al.org` or `_a2al-bootstrap.tngld.net` as UDP hostnames. Those names are TXT records `a2ald` looks up; `host` takes numeric `ip:port` seeds.

---

## Using the daemon REST API from any language

If you do not want to embed the Go library, spawn `a2ald` as a subprocess and call its REST
API. This is what the Python sidecar (`pip install a2al`) and the npm wrapper do.

```go
// Start the daemon (or assume it is already running)
cmd := exec.Command("a2ald", "--data-dir", "./mydata")
cmd.Start()

// Call its REST API
resp, _ := http.Post("http://127.0.0.1:2121/agents", "application/json",
    strings.NewReader(`{"operational_private_key_hex":"…","delegation_proof_hex":"…"}`))
```

Full REST reference: [API Reference](api-reference.md). The Go SDK that manages the sidecar
lifecycle is in `examples/` and the Python package (`python/`).

---

## Architecture decisions

Key design constraints that affect where to put new code:

- **Host ≠ daemon**: `host` is the public embed API; `daemon` is a2ald application layer.
  Put network-layer logic in `host`; put management / REST / MCP in `daemon`.
- **Protocol layer boundary**: only add something to `protocol/` if nodes that do not
  implement it would behave in a way that cannot be reconciled. See
  `協議層與應用層分工准則.md` (internal) for the three-question test.
- **No application coupling in `host`**: chat, rooms, ACL, MCP are `daemon` concerns.
  `host` does not know about them.

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for:
- PR guidelines (one concern per PR, tests required)
- CLA (signed automatically by bot on first PR)
- Commit message format

Open an issue before significant work to avoid duplicate effort.
