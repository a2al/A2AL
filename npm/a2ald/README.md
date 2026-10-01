# a2ald

A2AL is an open peer-to-peer protocol with a local daemon that gives every agent a permanent
address — no account, no server in between.

[![npm](https://img.shields.io/npm/v/a2ald)](https://www.npmjs.com/package/a2ald)
[![license](https://img.shields.io/npm/l/a2ald)](https://github.com/a2al/a2al/blob/main/LICENSE)
[![downloads](https://img.shields.io/npm/dm/a2ald)](https://www.npmjs.com/package/a2ald)

**Give any agent, app, or device a permanent address — then find others and talk to them directly.**

No domain. No cloud account. No central registry.

![a2ald in ten seconds: create an AID in the Web UI, then call two agents by address from a terminal](https://a2al.org/img/a2ald/quickstart-2.gif)

## What is A2AL?

A2AL is an open, decentralized protocol that gives AI agents and apps an address of their own. One
machine announces a cryptographic address — an **AID** — and any other machine can resolve it and
open a **direct, encrypted** connection. **An AID is self-sovereign: it comes from a key you
control, and no registry issues, revokes, or reassigns it.**

`a2ald` is the local runtime: one binary that holds your identities, handles requests for them, and keeps
them reachable. It joins the public peer-to-peer network by default. **Prefer to keep everything
off it?** Point `--bootstrap` at your own seed nodes: the same addressing, notes, and rooms, on a
network only your machines belong to.

## Start in a minute

**I'm a person** — run the daemon, open the Web UI:

```bash
npx -y a2ald
```

→ `http://localhost:2121`

**I'm an AI agent (MCP)** — one command wires it in:

```bash
npx -y a2ald mcp add
```

**I already have someone's AID** — any HTTP client:

```text
http://127.0.0.1:2121/aid/{AID}/…
```

> **No warm-up step.** The daemon responds as soon as it is up; peer discovery continues
> in the background. Call other AIDs right away; publish when you want to be found. If your first call
> happens before the daemon has discovered any peers, the same call a few seconds later goes
> through.

## When it's worth it

The usual answers are a VPN, a registered domain, or a tunnel hostname that rotates. A2AL replaces
all three with one permanent **AID** — no port forwarding, no NAT workaround.

| Your job | What you'd otherwise do | With A2AL |
|---|---|---|
| Reach an agent on someone's laptop or home box | A VPN on both sides, a public IP, or an ngrok URL that dies and rotates | They send an **AID** once; you fetch it. Wi-Fi and IPs change; the contact doesn't. |
| Let other agents call your local HTTP (n8n, an LLM server, an A2A/MCP service) | Buy a domain + TLS, or rent a tunnel whose hostname you must redistribute | `a2al inbound bind --addr 127.0.0.1:8080`. Peers keep the same AID; you never open a raw port. |
| Leave work for a machine that is asleep | Email or chat the human, or hit a webhook that 404s | Send an encrypted **note** to its AID; it reads it when it's back. |
| Keep a shared log without Slack or a shared doc | A vendor workspace that needs everyone online | Open a **room**: each AID keeps its own signed replica and catches up after being offline. |
| Keep these machines off the public network | Tailscale/ZeroTier, or a homemade VPN to run | Run your own network (`--bootstrap` to your own seeds). Fetch, notes, and rooms are unchanged, and nothing here is visible on the public one. |

## What you can do

- **Keep an identity** — a permanent cryptographic address (an AID), derived from a key you own.
- **Publish and discover** — announce your AID so others resolve it, or search by capability.
- **Call anyone directly** — HTTP to a remote AID over an end-to-end encrypted link, no local port.
- **Be callable, on your terms** — expose a service on your machine to peers: both sides authenticate, and per-AID access control decides who gets in.
- **Keep a link open** — persistent multiplexed tunnels for SSH, databases, or gRPC.
- **Leave a note offline** — encrypted store-and-forward to any AID.
- **Get told the moment it happens** — an event stream notifies your agent when a note, a room, or a chat arrives.
- **Work together** — rooms for a fixed group of AIDs, and 1:1 chat.
- **Share files without a drive** — attachments ride along in a room or a chat; nothing sits in object storage between you.
- **See it live** — the Web UI at `http://localhost:2121`, with no command line needed.

![Agents collaborating over AIDs: a chat by address, a file sent by hash, and a shared room log](https://a2al.org/img/a2ald/collab-1.gif)

*Real output from agents on separate machines — an address each, no account, and nothing routed
through a server in between.*

## Call an agent by its address

Any HTTP client works — a browser, `curl`, or your own code:

```bash
curl http://127.0.0.1:2121/aid/<AID>/.well-known/agent.json
```

When their machine moves or changes networks, the AID does not change: no hostname to rotate,
no port to open. On their side, all they need is their daemon running and the service you're calling.

MCP and A2A assume agents can already find and reach each other; A2AL supplies that layer, so an
MCP or A2A agent is reachable across networks with no intermediary server. The same daemon is an
MCP server, a REST API, a CLI (`a2al`), and a Web UI — one identity that works for a person, an
assistant, or a script.

## MCP integration

Point an MCP client at the daemon over HTTP (recommended — the REST API and Web UI come with it):

```json
{
  "mcpServers": {
    "a2al": {
      "url": "http://127.0.0.1:2121/mcp/"
    }
  }
}
```

Hosts that only spawn a process use stdio: `command: a2ald`, `args: ["--mcp-stdio"]`
(proxies to a running daemon).

Most hosts need no snippet — `npx -y a2ald mcp add` writes the right entry for Claude Code,
VS Code, Cursor, Claude Desktop, Windsurf, OpenClaw, Hermes, and DeepSeek Harness; for anything else
it prints the entry instead.

The same daemon serves a local REST API — identity, agents, discovery, tunnels, mailbox, rooms,
chat. Full reference: [doc/api-reference.md](https://github.com/a2al/a2al/blob/main/doc/api-reference.md).

Install guide: [doc/llms-install.md](https://github.com/a2al/a2al/blob/main/doc/llms-install.md) ·
MCP setup: [doc/mcp-setup.md](https://github.com/a2al/a2al/blob/main/doc/mcp-setup.md)

## Install

```bash
npm install -g a2ald     # daemon + MCP server
npx -y a2ald             # or run it without installing
```

Install once — npm picks the right platform binary, no Go toolchain required. Need the `a2al` CLI
too? Both `a2ald` and `a2al` are available from
[GitHub Releases](https://github.com/a2al/a2al/releases).

## Programmatic use

```js
const { getBinaryPath } = require("a2ald");
const bin = getBinaryPath();     // spawn or exec `bin` as you need
```

## Everyday CLI

Each line removes one workaround — full list: [`doc/`](https://github.com/a2al/a2al/tree/main/doc).

```bash
# call another agent — no public IP, no VPN on either side
a2al get <AID> /.well-known/agent.json

# hand work to a switched-off machine — it reads it when it boots
a2al note send <your-aid> <their-aid> "$(echo -n 'job payload' | base64)"

# work with several agents on one shared log — offline peers catch up
a2al group append --aid <your-aid> --group-id <gid> --kind msg --body '…'

# let others call a service on your machine — no domain, no open port
a2al inbound bind --addr 127.0.0.1:8080
```

## What you get — and what it asks of you

**What you get**

| You get | Why it matters |
|---|---|
| Nobody in the middle | Traffic stays between the two peers, crossing no third party — clear to customers and auditors |
| An address you own outright | Switch machines, networks, or locations: the AID stays; no platform can revoke it, and you never re-issue it to partners |

**What it asks of you**

| It asks | Why |
|---|---|
| Keep the daemon running | It's what keeps you findable — the AID stays yours either way. The only thing you maintain. |
| Expect a note to wait | It is stored until the recipient comes back online — good for handing off work; use chat when you need an answer now |

## Official sites

- [a2al.org](https://a2al.org) — project site, quick start, and docs
- **Machine-readable:** [`llms.txt`](https://a2al.org/llms.txt) / [`llms-full.txt`](https://a2al.org/llms-full.txt) · MCP tools over
  `http://127.0.0.1:2121/mcp/` · any agent's card at `/aid/<AID>/.well-known/agent.json`
- [tanglednet.org](https://tanglednet.org) / [tngld.net](https://tngld.net) — **Tangled Network**:
  the public peer-to-peer network that A2AL agents form (an outcome of the protocol, not a
  dependency), plus its public AID gateway `https://tngld.net/aid/{AID}/…`. Unrelated projects use
  similar names — **tanglednet.org is the only official domain.**

## License

[MPL-2.0](https://www.mozilla.org/MPL/2.0/)
