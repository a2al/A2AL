# A2AL — Agent-to-Agent Link

[![npm](https://img.shields.io/npm/v/a2ald)](https://www.npmjs.com/package/a2ald)
[![PyPI](https://img.shields.io/pypi/v/a2al)](https://pypi.org/project/a2al/)
[![Go Reference](https://pkg.go.dev/badge/github.com/a2al/a2al.svg)](https://pkg.go.dev/github.com/a2al/a2al)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)

**Official sites:** [a2al.org](https://a2al.org) · [Tangled Network](https://tanglednet.org) · [tngld.net](http://tngld.net)

Give a **person, agent, device, or service** a permanent address — then find others and talk to them directly. No domain. No cloud account. No central registry.

That address is an **AID**: it comes from a key you hold. Nobody issues it, revokes it, or reassigns it. You hand it over once. They still reach you when the laptop changes Wi-Fi, the box moves, or the machine was asleep when they first tried. After connect, application bytes go peer-to-peer; A2AL is not in the data path.

MCP, A2A, and the rest already know how agents *talk* once they have a URL. They do not say how a laptop, a home server, and a worker in a vendor-less world share one address that survives the next NAT, the next cloud, the next company. That layer is missing. A2AL is that layer, and it has to live in the open — an address you own is only real if no one vendor has to stay up for you to exist.

`a2ald` is the local runtime: identities, connections, Web UI, REST, and an MCP server. It joins the public Tangled Network by default. Prefer a network only your machines belong to? `--bootstrap` your own seeds; the same addressing, notes, and rooms.

![Create an AID in the Web UI, then call agents by address](https://a2al.org/img/a2ald/quickstart-2.gif)

## Start

**Person** — run the daemon, open the UI:

```bash
npx -y a2ald
```

→ [http://localhost:2121](http://localhost:2121). Create an identity. Keep `a2ald` running across logins if they must still find you after you close the terminal (Windows/macOS: `a2ald service install`; Linux: [deploy/linux](deploy/linux/README.md)).

**Agent (MCP)** — one command:

```bash
npx -y a2ald mcp add
```

Known hosts: Claude Code, VS Code, Cursor, Claude Desktop, Windsurf, OpenClaw, Hermes, DeepSeek Harness. If add does not know this host, it writes nothing — `npx -y a2ald mcp print` and paste the entry yourself. Then reload and act on the goal. Do not wait for a peer count.

**Already have their AID** — any HTTP client:

```text
http://127.0.0.1:2121/aid/{AID}/…
```

There is no warm-up gate. The daemon answers locally as soon as it is up. Call others right away.

Install for real: `npm install -g a2ald`, [GitHub Releases](https://github.com/a2al/a2al/releases) (`a2ald` + `a2al`), or `pip install a2al` (Python sidecar). Full path: [Quick Start](doc/quickstart.md).

## When it's worth it

| Job | Otherwise | With A2AL |
|-----|-----------|-----------|
| Reach something on someone else's laptop | VPN, public IP, rotating tunnel URL | They send an AID once; you fetch |
| Let others call *your* local HTTP | Domain+TLS, or a hostname you must redistribute | `a2al inbound bind --addr 127.0.0.1:8080` |
| Leave work for a machine that is asleep | Slack the human, or a webhook 404 | Encrypted **note** to their AID |
| Agents (and people) coordinating, sharing files | Vendor workspace; everyone online | A **room** — history stays after someone was offline |
| Ongoing 1:1 | IM product, or notes-as-chat | **Chat** (invite first) |
| Stay off the public directory | Tailscale / homemade VPN | `--bootstrap` your seeds |

## MCP

HTTP (recommended — REST and the Web UI come with it):

```json
{
  "mcpServers": {
    "a2al": {
      "url": "http://127.0.0.1:2121/mcp/"
    }
  }
}
```

Hosts that only spawn a process: `"command": "a2ald", "args": ["--mcp-stdio"]` (proxies to a running daemon). Setup: [MCP Setup](doc/mcp-setup.md). Agent entry: [llms.txt](https://a2al.org/llms.txt).

## Everyday CLI

```bash
a2al get <AID> /.well-known/agent.json
a2al note send <your-aid> <their-aid> "$(echo -n 'job payload' | base64)"
a2al group append --aid <your-aid> --group-id <gid> --kind msg --body '…'
a2al inbound bind --addr 127.0.0.1:8080
```

`a2al help` for the rest. Numbers (timing, note size, rooms): [User Guide](doc/user-guide.md).

![Agents collaborating over AIDs](https://a2al.org/img/a2ald/collab-1.gif)

## Docs

| If you want to… | Read |
|-----------------|------|
| How visible, which channel | [Only turn on what you need](doc/choose.md) |
| Find the right page | [doc/](doc/README.md) |
| Wire an MCP host | [MCP Setup](doc/mcp-setup.md) · [MCP entry](doc/mcp-entry.md) |
| Identities, notes, chat, rooms, ACL, tunnels | [User Guide](doc/user-guide.md) |
| REST, MCP tools, Python | [API Reference](doc/api-reference.md) |
| Embed in Go | [Go SDK](doc/API.md) |
| Build from source | [Developer Guide](doc/developer-guide.md) |
| Protocol internals | [Architecture](doc/architecture.md) |
| Example binaries | [Examples](doc/examples.md) |

Windows binaries are unsigned: SmartScreen **More info → Run anyway** is expected.

## Protocol design

**Self-sovereign identity.** An AID is derived from a key you generate. No registry issues, revokes, or reassigns it — identity is end-to-end verifiable.

**Decentralized discovery.** The Tangled Network stores endpoint records, not payloads. Any node can resolve an AID without a central authority; the network operates at any scale.

**Mutual authentication.** Every connection cryptographically verifies both ends. You always know the agent on the other side is who it claims to be.

**Direct communication.** A2AL resolves addresses and brokers the initial connection, then steps aside. Application data flows peer-to-peer, not through the protocol.

**Web3 compatible.** Ethereum wallet addresses work as AIDs. Cross-key attestation lets an agent prove ownership of both a native AID and a blockchain identity — Web3 is supported, not required.

A2AL is complementary to existing agent communication standards:

| Protocol | Role | How A2AL fits |
|----------|------|---------------|
| **MCP** | Tool-calling interface | A2AL is an MCP-installable server; agents get addressing and networking as tools |
| **A2A** | Agent collaboration semantics | A2AL provides the discovery and connectivity layer A2A assumes |
| **ANP** | Agent networking vision | A2AL implements the decentralized network layer ANP envisions |

## Contributing

If the missing layer is worth having, it is worth building together. Open an issue before significant work. A PR needs a signed [Contributor License Agreement](CLA.md); a bot will prompt you.

## Disclaimer

A2AL is a networking protocol project. It is not associated with any cryptocurrency token, ICO, or financial product. Any use of the A2AL name or codebase in token offerings or financial promotions is unauthorized and not endorsed by the authors.

## Author

XG.Shi — This project is not affiliated with or endorsed by any employer or organization.

## License

Copyright (c) 2026 The A2AL Authors. [Mozilla Public License 2.0](LICENSE).
