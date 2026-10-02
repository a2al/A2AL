# MCP Setup

A2AL daemon (`a2ald`) runs as an MCP server: identity, discovery, fetch, tunnels, notes, events, 1:1 chat, and rooms.

---

## Fastest path

`npx -y a2ald mcp add` starts a daemon if none is running and registers the server with the hosts it finds.

```bash
npx -y a2ald mcp add       # or: a2ald mcp add
```

Reload the host and confirm `a2al_*` tools appear (chat and rooms are `chat_*` / `group_*`); then act on the goal. `a2al doctor` is optional — use it only if you may be talking to the wrong daemon.

If `mcp add` does not know your host, it writes nothing and prints the entry for you to place — see [Configuration Snippets](#configuration-snippets) and `a2ald mcp print`.

---

## Choose your operating mode

| Mode | How the MCP client connects | Best for |
|------|-----------------------------|----------|
| **Persistent daemon** (default) | `"url": "http://127.0.0.1:2121/mcp/"` | Collaborative work, CLI, Web UI, several hosts sharing one daemon |
| **Stdio** | `"command": "a2ald", "args": ["--mcp-stdio"]` | Hosts that only spawn a process; CI; a running daemon is proxied |

A daemon started in the background is enough for the current session. Staying findable after logout is a separate choice (next section).

**What stdio costs, if no daemon is already running:** a fresh DHT join, **no REST API** — so no CLI and no Web UI — only one process per data directory, and published records expire when the session ends. Use it when those are acceptable.

**Stdio smart proxy:** if `a2ald` is already running, `a2ald --mcp-stdio` proxies MCP to it — no cold-start, no lock conflict. If none is running, this process is the node: usable **< 1 min**; findable **1–2 min**. Do not wait for a peer count. Times: [User Guide — Timing](user-guide.md#timing).

> **Data directory lock:** One data directory can only be used by one `a2ald` process at a time. Accidental double-start on the default directory fails with a lock error. A second **node** is a different intent: new `-data-dir`, new `-api-addr` / `-listen`, then CLI `--api` / MCP URL for that port. Empty `bootstrap` still joins the public network.

---

## Install `a2ald`

### Option A — npm (recommended)

```bash
npm install -g a2ald
```

No Go toolchain required. The correct binary for your platform is installed automatically.

### Option B — npx (zero install)

Use `npx` directly in your MCP config — npm downloads `a2ald` on first use. This is stdio; if a daemon is already running, it proxies.

```json
{
  "mcpServers": {
    "a2al": {
      "command": "npx",
      "args": ["a2ald", "--mcp-stdio"]
    }
  }
}
```

### Option C — binary download

Download from [Releases](https://github.com/a2al/a2al/releases) and place `a2ald` in your PATH.

macOS/Linux:
```bash
curl -fsSL https://github.com/a2al/a2al/releases/latest/download/a2ald_linux_amd64.tar.gz | tar xz
sudo mv a2ald /usr/local/bin/
```

---

## Configuration Snippets

Only needed if `a2ald mcp add` did not cover your host. Run `a2ald mcp print` for the entry to paste — it reads the daemon's actual address instead of assuming the default, and reports whether the daemon is reachable.

Prefer HTTP (`"url": "http://127.0.0.1:2121/mcp/"`) when the host supports it. Stdio is a valid joint: if a daemon is already running, `--mcp-stdio` proxies to it.

The snippets below are examples of common shapes, not a specification. If your host documents something different, follow your host: what must hold is the endpoint, the transport, and a running daemon.

`mcp add` knows: Claude Code, VS Code, Cursor, Claude Desktop, Windsurf, OpenClaw, Hermes, DeepSeek Harness.

### Claude Code

Prefer Claude Code's own command:

```bash
claude mcp add --scope user --transport http a2al http://127.0.0.1:2121/mcp/
```

### VS Code

```bash
code --add-mcp "{\"name\":\"a2al\",\"type\":\"http\",\"url\":\"http://127.0.0.1:2121/mcp/\"}"
```

### Cursor

Edit `.cursor/mcp.json` in project root, or global `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "a2al": {
      "url": "http://127.0.0.1:2121/mcp/"
    }
  }
}
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "a2al": {
      "command": "a2ald",
      "args": ["--mcp-stdio"]
    }
  }
}
```

### Windsurf

Edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "a2al": {
      "serverUrl": "http://127.0.0.1:2121/mcp/"
    }
  }
}
```

### Hermes (NousResearch)

Prefer Hermes' own command (it writes `~/.hermes/config.yaml`). The CLI then prompts for which tools to enable:

```bash
hermes mcp add --url http://127.0.0.1:2121/mcp/ a2al
```

`a2ald mcp add` does not run that picker; it writes the HTTP shape Hermes documents, under `mcp_servers`. `command` and `url` must not both be set:

```yaml
mcp_servers:
  a2al:
    url: "http://127.0.0.1:2121/mcp/"
```

Stdio is the other legal shape: `command: "a2ald"` / `args: ["--mcp-stdio"]` (proxies a running daemon). Restart or wait for Hermes to reload MCP.

### OpenClaw

Copy the skill file to your workspace and restart OpenClaw:

```bash
mkdir -p ~/.openclaw/workspace/skills/a2al
cp skills/a2al/SKILL.md ~/.openclaw/workspace/skills/a2al/SKILL.md
```

Then register with OpenClaw's own command:

```bash
openclaw mcp add a2al --url http://127.0.0.1:2121/mcp/ --transport streamable-http
```

### DeepSeek Harness

No MCP-add CLI. Merge an insert into the user patch layer — `$DSH_HOME/cordis.patch.yml` (default `~/.dsh/cordis.patch.yml`) for every profile, or `$DSH_HOME/profiles/<profile>/cordis.patch.yml` for one profile. Do not replace a file that already has other patches. Restart `dsh web`.

```yaml
- insert:
    - id: mcp-a2al
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: a2al
        transport: streamable-http
        url: http://127.0.0.1:2121/mcp/
```

---

## Keep the daemon across logins

`a2ald mcp add` starts a daemon for the current session. HTTP MCP and stdio (proxying that daemon) already work. Installing a **service** is a separate choice: published records expire when the process stops (TTL; default 1 hour). Do it when this machine’s agents should stay findable after logout or reboot — not as a required upgrade from stdio to HTTP.

**Windows / macOS:**

```bash
a2ald service install
```

This registers `a2ald` as a background service and starts it immediately. On subsequent logins it starts automatically.

> **Windows:** if you are not already an administrator, an interactive menu appears: **[1] System Service** (UAC prompt; survives reboot, recommended) or **[2] Task Scheduler** (no elevation; stops at logout). Pass `-user` to skip the menu and install via Task Scheduler directly. If you already have admin rights, the command installs the Windows Service with no menu.

```bash
a2ald service status
a2ald service stop
a2ald service start
a2ald service uninstall
```

**Linux:** [deploy/linux](../deploy/linux/README.md) (package or a systemd unit).

If you prefer to write the unit/plist/task XML yourself:

| Platform | Guide |
|----------|-------|
| Linux (systemd) | [`deploy/linux/README.md`](../deploy/linux/README.md) |
| macOS (launchd) | [`deploy/macos/README.md`](../deploy/macos/README.md) |
| Windows (Task Scheduler) | [`deploy/windows/README.md`](../deploy/windows/README.md) |

Leave a working HTTP MCP entry alone. Hosts that only spawn a process keep stdio — `--mcp-stdio` proxies to the service on the same data directory.

Try the call you came to make. `a2al doctor` (or `a2al_status`) is optional: local observations on this daemon, not a verdict. Neighbor counts and `network_ready` are signals. To see whether lookup works, try resolve/fetch of a known AID.

---

## Full Path (if `a2ald` is not in PATH)

Replace `"command": "a2ald"` with the absolute path:

- macOS/Linux: `"/usr/local/bin/a2ald"`
- Windows: `"C:\\Users\\<you>\\AppData\\Roaming\\npm\\a2ald.cmd"` (npm global) or full path to binary

---

## FAQ

**Q: My AI agent calls a2al_resolve right away and it fails. Why?**

If a2ald just started, it is usable **< 1 min**; looking someone up or being found takes **1–2 min**. If it has been running, there is no join wait — first connect **< 10 sec**, later connects **~10–100 ms**. Neighbor count (`dht_peers`) only tells you who is in view — do not wait for a number, and do not treat `network_ready` as proof others can find you. If stdio is proxying to a daemon that is already running, there is no cold start. Times: [User Guide — Timing](user-guide.md#timing).

**Q: I published my agent — is it now permanently reachable?**

No. Published endpoint records have a TTL (default 1 hour). `a2ald` renews them automatically **while it is running**. If `a2ald` stops, the records expire and your agent becomes unreachable. Publishing is not a one-time setup — the agent is online only as long as `a2ald` is online. Keep the process running across logins (Windows/macOS: `a2ald service install`; Linux: [deploy/linux](../deploy/linux/README.md)).

**Q: When should I use stdio, HTTP, or a service?**

The **joint** and **whether the daemon survives logout** are independent:

- Prefer HTTP (`"url": "http://127.0.0.1:2121/mcp/"`) when the host supports it. Stdio is a valid joint: if a daemon is already running, `--mcp-stdio` proxies to it.
- Use stdio without a pre-existing daemon for CI, a sandbox, or a session-only node (accept: no REST/UI, publish dies with the process).
- Install a service when this machine should stay findable across logins. Do not install a service just to “switch transport.”

**Q: Can I run two daemons at the same time?**

Not on the same data directory — each process takes an exclusive lock. That is accidental collision. A **second node** is allowed and is the right move when you want isolation: new `-data-dir`, new `-api-addr` and `-listen`, then point CLI/MCP at that API (`a2al --api http://127.0.0.1:<port>`). Same AID keys can be registered on the new node; a throwaway identity is a new generate. Empty `bootstrap` still joins the public network.

**Q: How do I join only my own nodes, or only this machine?**

Set `bootstrap` (flag or `config.toml`) to your seeds. A non-empty list **skips public DNS and beacon**. Loopback seeds (`127.0.0.1:<listen>`) keep coordination on this machine. Use a fresh data directory for a private cluster — an old `peers.cache` may still dial public neighbours. Isolated/air-gapped networks use the same pattern: first node can run standalone, others `-bootstrap` it.

**Q: How do I keep the same identity when I install a service?**

Your identity lives in the data directory (default: `%APPDATA%\a2al` on Windows, `~/Library/Application Support/a2al` on macOS, `~/.config/a2al` on Linux). Install the service pointing at that directory. HTTP MCP entries stay as they are. Stdio entries stay stdio; they will proxy to the service.

**Q: The default API port 2121 is already in use. How do I change it?**

Edit `config.toml` in the data directory and set `api_addr = "127.0.0.1:<port>"`, then update the MCP client URL accordingly. CLI: `a2al --api http://127.0.0.1:<port>`. A second node must change `-listen` as well, not only the API port.

---

## Available tools

Identity and networking: `a2al_identity_generate`, `a2al_agents_list`, `a2al_agents_generate_ethereum`, `a2al_ethereum_delegation_message`, `a2al_ethereum_register`, `a2al_ethereum_proof`, `a2al_agent_register`, `a2al_agent_get`, `a2al_agent_probe`, `a2al_agent_patch`, `a2al_agent_publish`, `a2al_agent_heartbeat`, `a2al_agent_delete`, `a2al_status`, `a2al_agent_publish_record`, `a2al_resolve`, `a2al_resolve_records`, `a2al_discover`, `a2al_service_register`, `a2al_service_unregister`, `a2al_fetch`, `a2al_connect`, `a2al_tunnel_open`, `a2al_tunnel_close`, `a2al_tunnel_list`, `a2al_mailbox_send`, `a2al_mailbox_poll`, `a2al_events_poll`.

Chat: `chat_request`, `chat_accept`, `chat_refuse`, `chat_remove`, `chat_block`, `chat_send`, `chat_read`, `chat_mark_read`, `chat_contacts`.

Rooms: `group_create`, `group_list`, `group_invite`, `group_join`, `group_append`, `group_read`, `group_head`, `group_sync`, `group_members`, `group_mark_read`, `group_object_put`, `group_object_locate`, `group_object_get`, `group_get_link`, `group_retract`.

Do not use `a2al_mailbox_send` as chat. Arguments: [API Reference](api-reference.md#mcp-tools).
