# a2al (Python)

Python client for [A2AL](https://github.com/a2al/a2al) — decentralized agent networking. Spawns a local `a2ald` daemon as a sidecar and exposes a typed REST helper covering the full API surface: identity, publish, discover, resolve, fetch, and multiplexed persistent tunnels.

Full API: [doc/api-reference.md](https://github.com/a2al/a2al/blob/main/doc/api-reference.md)

## Installation

```sh
pip install a2al
```

Pre-built `a2ald` binaries are bundled inside platform wheels:

| Platform | Architecture  |
|----------|---------------|
| Linux    | x86_64, arm64 |
| macOS    | x86_64, arm64 |
| Windows  | x86_64        |

On unsupported platforms, install `a2ald` manually and set `A2ALD_PATH` to the executable path.

## Quick Start

```python
from a2al import Daemon, Client

with Daemon() as d:
    c = Client(d.api_base, token=d.api_token)

    # 1 — Check daemon health
    print(c.health())

    # 2 — Send an HTTP request to a remote agent (encrypted QUIC, no local port needed)
    result = c.fetch(
        remote_aid,
        method="GET",
        path="/.well-known/agent.json",
    )
    # result = {"status": 200, "headers": {...}, "body": "<base64>", "truncated": False}

    # 3 — Open a persistent tunnel (multiple concurrent TCP connections)
    tunnel = c.tunnel_open(remote_aid)
    local_addr = tunnel["listen"]   # e.g. "127.0.0.1:58320"
    tunnel_id  = tunnel["id"]       # e.g. "tun_abc123"

    # ... connect your application to local_addr ...

    c.tunnel_close(tunnel_id)
```

## Client API

| Method | REST endpoint | Description |
|--------|---------------|-------------|
| `health()` | `GET /health` | Daemon liveness check |
| `resolve(aid)` | `POST /resolve/{aid}` | Look up a remote agent's endpoints |
| `connect(aid, *, local_aid)` | `POST /connect/{aid}` | One-shot tunnel — single TCP session, closes automatically |
| `fetch(aid, *, method, path, headers, body_base64, local_aid)` | `POST /fetch/{aid}` | HTTP request over QUIC; returns `{status, headers, body(base64), truncated}` |
| `tunnel_open(aid, *, local_aid, idle_timeout_sec)` | `POST /tunnel/{aid}` | Persistent tunnel — accepts many concurrent connections; returns `{id, listen}` |
| `tunnel_close(id)` | `DELETE /tunnel/{id}` | Close a persistent tunnel |
| `tunnel_list()` | `GET /tunnel` | List active persistent tunnels |
| `tunnel_status(id)` | `GET /tunnel/{id}` | Status of one tunnel |
| `agents_list()` | `GET /agents` | List locally registered agents |
| `identity_generate()` | `POST /identity/generate` | Create a new Ed25519 AID |
| `agent_register(payload)` | `POST /agents` | Register a generated identity |
| `agent_publish(aid)` | `POST /agents/{aid}/publish` | Announce agent to the Tangled Network |

## Daemon Context Manager

`Daemon()` starts `a2ald` as a subprocess and stops it when the `with` block exits.

```python
from a2al import Daemon, Client

# Default: auto-locate a2ald binary, random API port, temp data dir
with Daemon() as d:
    c = Client(d.api_base, token=d.api_token)
    ...

# Custom binary path and extra daemon flags
with Daemon(
    a2ald_exe="/usr/local/bin/a2ald",
    extra_args=["--data-dir", "/var/lib/a2al", "--fallback-host", "1.2.3.4"],
) as d:
    c = Client(d.api_base, token=d.api_token)
    ...
```

## Environment Variables

| Variable      | Description                                              |
|---------------|----------------------------------------------------------|
| `A2ALD_PATH`  | Override path to the `a2ald` executable                  |
| `A2AL_API_TOKEN` | Bearer token when the daemon enforces authentication  |

## Requirements

- Python 3.10+
- No third-party dependencies (standard library only)

## Links

- [a2al.org](https://a2al.org) — project site
- [API reference](https://github.com/a2al/a2al/blob/main/doc/api-reference.md)
- [tanglednet.org](https://tanglednet.org) / [tngld.net](https://tngld.net) — Tangled Network
- [GitHub](https://github.com/a2al/a2al)

## License

[MPL-2.0](https://www.mozilla.org/MPL/2.0/)
