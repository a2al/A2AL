# A2AL

**A2AL** (Agent-to-Agent Link Protocol) is a decentralized networking protocol for AI agents — providing cryptographic identity, service publishing, and endpoint discovery without central infrastructure.

Each agent holds a unique address (AID) derived from its public key. It publishes its reachable endpoints to the network; any other agent can resolve that AID to a connectable address and establish a direct, authenticated connection. A2AL is a networking layer only — it is not in the data path.

```
Agent A  ──publish──▶  A2AL Network  ◀──resolve──  Agent B
                                                        │
                                     Agent B connects directly to Agent A
```

Analogy: MCP gives agents tool-calling capability; A2AL gives agents addressing and interconnection capability.

## Integration

A2AL is designed to fit how you already work:

| Integration | Audience |
|-------------|----------|
| **Go library** | Go developers — embed directly |
| **`a2ald` daemon + REST API** | Any language — call `localhost` HTTP |
| **MCP Server** | AI agents — native tool calls (`publish`, `resolve`, `connect`) |
| **`pip install a2al` / `npm install a2al`** | Python / JS — sidecar binary bundled, zero setup |

## Features

- **Decentralized** — no central registry or coordinator
- **Cryptographic identity** — address is derived from public key; connections are authenticated by default
- **NAT traversal** — hole-punching, QUIC tunneling, TURN relay fallback
- **Multi-platform** — Linux / macOS / Windows / Android / iOS
- **Web3 identity** — optionally anchor an AID to an Ethereum/Paralism address for on-chain reputation


## Quick Start

```bash
go get github.com/a2al/a2al
```

```go
import "github.com/a2al/a2al"

agent := a2al.New(a2al.Config{...})
agent.Start()

conn, err := agent.Connect(targetAID)
```

See [`doc/API.md`](doc/API.md) for the full API reference.

## Try the Demo

**Same machine:**

```bash
cd examples/phase1-node

go run . -listen :5001 -debug :2634                                    # node 1
go run . -listen :5002 -bootstrap 127.0.0.1:5001 -debug :2635         # node 2
go run . -listen :5003 -bootstrap 127.0.0.1:5001 -debug :2636         # node 3
```

**Different machines** (specify the externally reachable IP with `-ip`):

```bash
# machine A (192.168.1.10)
./phase1-node -listen :5001 -ip 192.168.1.10 -debug :2634

# machine B (192.168.1.20)
./phase1-node -listen :5001 -ip 192.168.1.20 -bootstrap 192.168.1.10:5001 -debug :2634
```

Each node prints its AID on startup. Type any AID in a terminal to resolve its endpoint. Any node can serve as a bootstrap peer. Node state is visible at `http://localhost:2634/debug/routing`.

## Contributing

Contributions are welcome. Before your pull request can be merged, you must sign the [Contributor License Agreement](CLA.md). A bot will prompt you automatically when you open a PR.

Please open an issue before starting significant work.

## License

Copyright 2026 The A2AL Authors

Licensed under the [Apache License, Version 2.0](LICENSE).
