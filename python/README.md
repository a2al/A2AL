# a2al (Python)

Direct, peer-to-peer networking for AI agents across NAT, machines, and sleep cycles — no cloud, no open ports, no relay server.

[![PyPI](https://img.shields.io/pypi/v/a2al)](https://pypi.org/project/a2al/)
[![Python versions](https://img.shields.io/pypi/pyversions/a2al)](https://pypi.org/project/a2al/)
[![license](https://img.shields.io/pypi/l/a2al)](https://github.com/a2al/a2al/blob/main/LICENSE)

**Connect Python AI agents across different machines in 3 lines of code — direct end-to-end encrypted communication without server setup.**

`pip install a2al` bundles the `a2ald` daemon and runs it as a sidecar: zero-config networking, your own self-sovereign identity (AID), and no cloud account to sign up for. **An AID is self-sovereign: it comes from a key you
control, and no registry issues, revokes, or reassigns it.**

![a2al in ten seconds: create an AID in the Web UI, then call your own agent and someone else's by address from a terminal](https://a2al.org/img/a2ald/quickstart-2.gif)

## Installation

```sh
pip install a2al
```

Install once — the wheel bundles the right `a2ald` binary for your platform:

| Platform | Architecture  |
|----------|---------------|
| Linux    | x86_64, arm64 |
| macOS    | x86_64, arm64 |
| Windows  | x86_64        |

On an unsupported platform, install `a2ald` yourself and point `A2ALD_PATH` at it.
Python 3.10+, with no third-party dependencies.

## Quick start

Three actions — resolve an address, call a service, keep a connection open.

```python
from a2al import Daemon, Client

with Daemon() as d:                          # bundles + starts a2ald; stops it on exit
    c = Client(d.api_base, token=d.api_token)

    endpoints = c.resolve(remote_aid)         # AID -> current endpoints

    r = c.fetch(remote_aid, method="GET", path="/.well-known/agent.json")
    # -> 200 · the other agent's own answer, over the encrypted link

    t = c.tunnel_open(remote_aid)
    print(t["listen"])                        # point your app at this local address
    c.tunnel_close(t["id"])
```

Call the client directly — there is no readiness gate. Peer discovery continues in the
background: if your first call happens before the daemon has discovered any peers, the same call a
few seconds later goes through.

Prefer your own build? `Daemon(a2ald_exe="/usr/local/bin/a2ald", extra_args=["--data-dir", "/var/lib/a2al"])`.

## Why not a URL or a VPN?

- **No domain, no port-forwarding.** Peers keep an AID — an address that persists when the
  machine moves or changes networks.
- **No account, no gateway in the data path.** The network stores *where to find you now*;
  application bytes go directly between peers, end-to-end encrypted.
- **Built for the hard cases.** The same code runs on a cloud VM and on a laptop behind NAT —
  neither needs a special case.

## What you can do

**Today from Python**

- **Create and publish an identity** — generate an AID, register it, announce it so other machines find you.
- **Resolve an address** — get a known AID's current endpoints.
- **Call a remote agent** — HTTP to any AID over an encrypted link, with no local port.
- **Keep a connection open** — one encrypted link carrying many concurrent TCP connections (SSH, databases, gRPC).

**Also available today — through the `a2al` CLI, local REST, MCP, or the Web UI:**

- **Discover by service name** — search for agents by what they do (e.g. `lang.translate`).
- **Be callable, on your terms** — expose a service on your machine to peers: both sides authenticate, and per-AID access control decides who gets in.
- **Leave an encrypted note** — store-and-forward to an AID that is offline right now.
- **Chat and rooms** — 1:1 messages, or a shared signed log with offline catch-up and file objects.
- **Get told** — an event stream notifies an agent when a note, a room update, or a chat arrives.
- **See it** — the Web UI at `http://localhost:2121`, and the same MCP tools.

These are available today through the CLI, the local REST API, and MCP; native Python methods are
coming.

![Agents collaborating over AIDs: a chat by address, a file sent by hash, and a shared room log](https://a2al.org/img/a2ald/collab-1.gif)

*Real output from agents on separate machines — an address each, no account, and nothing routed
through a server in between.*

## Client API

| Method | What it does |
|--------|--------------|
| `identity_generate()` / `agent_register()` / `agent_publish()` | Create, register, and announce an identity |
| `resolve(aid)` | AID → current endpoints |
| `fetch(aid, method=, path=)` | HTTP to a remote AID over an encrypted link |
| `tunnel_open()` / `tunnel_close()` / `tunnel_list()` | Persistent multiplexed tunnels |
| `agents_list()` / `health()` | Local daemon and agent status |

Full method list: [API reference](https://github.com/a2al/a2al/blob/main/doc/api-reference.md).

## What you get — and what it asks of you

**What you get**

| You get | Why it matters |
|---|---|
| Nobody in the middle | Your traffic stays between the two peers and crosses no third party |
| An address you own outright | Switch machines, cloud environments, or networks: the AID in your config does not change, and no platform can revoke it or transfer it |

**What it asks of you**

- **Keep the daemon running** — the sidecar stays up for as long as your `with` block runs; run
  `a2ald` as a service when your app needs to be reachable around the clock.

## Links

- [a2al.org](https://a2al.org) — project site, quick start, and docs
- **Machine-readable:** [`llms.txt`](https://a2al.org/llms.txt) / [`llms-full.txt`](https://a2al.org/llms-full.txt) · MCP tools over
  `http://127.0.0.1:2121/mcp/` · any agent's card at `/aid/<AID>/.well-known/agent.json`
- [API reference](https://github.com/a2al/a2al/blob/main/doc/api-reference.md)
- [a2ald on npm](https://www.npmjs.com/package/a2ald)
- [tanglednet.org](https://tanglednet.org) / [tngld.net](https://tngld.net) — **Tangled Network**:
  the public peer-to-peer network that A2AL agents form (an outcome of the protocol, not a
  dependency), plus its public AID gateway. Unrelated projects use similar names —
  **tanglednet.org is the only official domain.**
- [GitHub](https://github.com/a2al/a2al)

## License

[MPL-2.0](https://www.mozilla.org/MPL/2.0/)
