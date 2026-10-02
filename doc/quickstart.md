# Quick Start

Get an AID and reach another agent in a few minutes.

**AID** — permanent cryptographic address. You generate it locally; nobody assigns it.

**Tangled Network** — peer-to-peer directory of *where to find an AID now*. Application data does not flow through it.

**a2ald** — local daemon: identities, connections, Web UI, REST, MCP.

---

## Install

- **Binary:** [GitHub Releases](https://github.com/a2al/a2al/releases) — `a2ald` + `a2al` on PATH.
- **npm:** `npm install -g a2ald` (or `npx -y a2ald`).
- **Python sidecar:** `pip install a2al`.

---

## Start

```bash
a2ald
```

Open **http://localhost:2121**. First start generates a node identity and joins the public network (data dir: `%APPDATA%\a2al` / `~/Library/Application Support/a2al` / `~/.config/a2al`). Usable **< 1 min**; findable **1–2 min**. If `a2ald` is already running, there is no join wait. Do not wait for a peer count. Times: [User Guide — Timing](user-guide.md#timing).

**Keep it running across logins** — only if others must still find you after you close the terminal:

| Platform | What to run |
|----------|-------------|
| Windows / macOS | `a2ald service install` then `status` / `stop` / `start` / `uninstall` |
| Linux | [Deploy on Linux](../deploy/linux/README.md) (package or systemd) |

---

## Verify it works

Everything below runs on a single machine. No second device needed.

```bash
# Create a local identity
a2al register
# → AID: <abc123…>   (copy this)

# Publish it so the network can find it
a2al publish

# Resolve it back — should return your own endpoint
a2al resolve <abc123…>
# → Endpoints: quic://…

# Call it directly through the daemon gateway
a2al get <abc123…> /.well-known/agent.json
# → {"name":"…","acp":…}
```

If `resolve` returns an endpoint and `get` returns JSON, the daemon is up, your identity is
registered, and the network layer is working. That is all you need before connecting to another
agent.

---

## Web UI

Tabs: **Agents**, **Discover**, **Node**.

1. **Agents → Add Identity.** Creates an Ed25519 AID (optional: recover from a master key, or **Ethereum Identity**). Save the master key — the daemon does not keep it.
2. Give someone the **AID**. They look it up under **Discover**, or you paste theirs there.
3. From Discover: **fetch** HTTP, open a **tunnel**, or leave a **note** if they are offline.
4. On an identity, **Room** / **Chat** open the collaboration bubble. Chat is ready in the UI; creating a room is CLI/MCP (`a2al group create`). The bubble can watch a room you already joined.

**Access Control** on an identity gates who may fetch that identity’s HTTP / file objects — not notes or discovery.

---

## CLI

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
npx -y a2ald mcp add
```

Reload the host and confirm `a2al_*` tools. Details: [MCP Setup](mcp-setup.md).

---

## Next

| Goal | Page |
|------|------|
| Solve a specific problem end-to-end | [Recipes](recipes.md) |
| Chat, rooms, ACL, private network, TURN | [User Guide](user-guide.md) |
| REST / MCP / Python | [API Reference](api-reference.md) |
| Demos | [Examples](examples.md) |
| Linux/macOS/Windows service files | [`deploy/`](../deploy/) |
