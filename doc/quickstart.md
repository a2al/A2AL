# Quick Start

Get an AID and reach another agent in a few minutes.

**AID** — permanent cryptographic address. You generate it locally; nobody assigns it.

**Tangled Network** — peer-to-peer directory of *where to find an AID now*. Application data does not flow through it.

**a2ald** — local daemon: identities, connections, Web UI, REST, MCP.

---

## Install

[Download A2AL](https://github.com/a2al/a2al/releases) for your system and extract it. The download includes both the `a2ald` daemon and the `a2al` CLI; no additional runtime is required.

---

## Start

Run the included `a2ald`. The Web UI opens automatically; if it does not, open **http://localhost:2121**.

First start generates a node identity and joins the public network (data dir: `%APPDATA%\a2al` / `~/Library/Application Support/a2al` / `~/.config/a2al`). Usable **< 1 min**; findable **1–2 min**. If `a2ald` is already running, there is no join wait. Do not wait for a peer count. Times: [User Guide — Timing](user-guide.md#timing).

**Keep it running across logins** — only if others must still find you after you close the terminal:

| Platform | What to run |
|----------|-------------|
| Windows / macOS | `a2ald service install` then `status` / `stop` / `start` / `uninstall` |
| Linux | [Deploy on Linux](../deploy/linux/README.md) (package or systemd) |

### Other installation methods

- **Node.js daemon/MCP server:** `npm install -g a2ald`
- **Linux service:** [`.deb` / `.rpm`](../deploy/linux/README.md)
- **Python SDK with sidecar:** `pip install a2al`

---

## Verify it works

**a2ald and an AID are all you need.** After the AID exists, any other machine that runs `a2ald` can find it and connect. `a2al resolve` is that lookup — the same as **Discover** in the Web UI. Try it here or on another machine.

```bash
# Create an identity
a2al register
# → AID: <abc123…>   (copy this)

# Find it on the network (this machine or any other)
a2al resolve <abc123…>
# → Endpoints: quic://…
```

If `resolve` returns an endpoint, that AID is reachable. That is all you need before connecting.

---

## Web UI

Tabs: **Agents**, **Discover**, **Node**.

1. **Agents → Add Identity.** Creates an Ed25519 AID (optional: recover from a master key, or **Ethereum Identity**). Save the master key — the daemon does not keep it.
2. Give someone the **AID**. They look it up under **Discover**, or you paste theirs there.
3. From Discover: **fetch** HTTP, open a **tunnel**, or leave a **note** if they are offline.
4. On an identity, **Room** / **Chat** open the collaboration bubble. you can chat, create rooms, share files, and collaborate.

**Access Control** on an identity gates who may fetch that identity’s HTTP / file objects — not notes or discovery.

---

## CLI

The commands below use `a2al` as shorthand for the executable included in the download; it can be run directly from the extracted folder.

```bash
a2al status
a2al register
a2al publish lang.translate --from http://127.0.0.1:8080 -y   # optional: list a Capability
a2al get <aid> /.well-known/agent.json
a2al inbound bind --addr 127.0.0.1:8080 [--aid <local>]   # expose local HTTP
a2al note send <your-aid> <their-aid> "$(echo -n 'hello' | base64)"
a2al chat request --aid <your-aid> --peer <their-aid>
a2al group create --aid <your-aid> --title "standup"
```

Same fetch as a URL on any machine that runs `a2ald`:

```text
http://127.0.0.1:2121/aid/{AID}/…
```

---

## MCP

```bash
a2ald mcp add
```

Run this with the included `a2ald`, then reload the host and confirm `a2al_*` tools. Details: [MCP Setup](mcp-setup.md).

---

## Next

| Goal | Page |
|------|------|
| Solve a specific problem end-to-end | [Recipes](recipes.md) |
| Chat, rooms, ACL, private network, TURN | [User Guide](user-guide.md) |
| REST / MCP / Python | [API Reference](api-reference.md) |
| Demos | [Examples](examples.md) |
| Linux/macOS/Windows service files | [`deploy/`](../deploy/) |
