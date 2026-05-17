# MCP Setup

A2AL daemon (`a2ald`) runs as an MCP server, giving any MCP-compatible AI agent 20+ networking tools: publish identity, discover agents, resolve addresses, send encrypted messages, and more.

---

## Choose your operating mode

| Mode | How the MCP client connects | Best for |
|------|-----------------------------|----------|
| **Service mode** (recommended) | `"url": "http://127.0.0.1:2121/mcp/"` | Daily AI assistant work; `network_ready` is already `true` when the session starts — network ops are **near-instant** from the moment a session starts |
| **Stdio mode** | `"command": "a2ald", "args": ["--mcp-stdio"]` | CI/scripts, isolated test sessions, privacy-sensitive use, no background process |

**Stdio mode smart proxy:** if `a2ald` is already running as a service, `a2ald --mcp-stdio` automatically detects it and proxies MCP traffic to the running daemon — no cold-start, no lock conflict, near-instant `network_ready`. If no service is running, `a2ald` starts normally: DHT bootstrap takes **60–120 seconds** before `network_ready: true`. Always call `a2al_status` first and poll until ready before any network operation.

> **Important — data directory exclusivity:** One data directory can only be used by one `a2ald` process at a time. Never run a service-mode instance and a stdio-mode instance pointing to the same data directory simultaneously; the second process will fail to start or corrupt state.

---

## Install `a2ald`

### Option A — npm (recommended)

```bash
npm install -g a2ald
```

No Go toolchain required. The correct binary for your platform is installed automatically.

### Option B — npx (zero install)

Use `npx` directly in your MCP config — npm downloads `a2ald` on first use:

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

Once `a2ald` is installed, add it to your MCP client config.

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

### Cursor

Edit `.cursor/mcp.json` in project root, or global `~/.cursor/mcp.json`:

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
      "command": "a2ald",
      "args": ["--mcp-stdio"]
    }
  }
}
```

### Cline (VS Code extension)

Open Cline settings → MCP Servers → Add Server → paste:

```json
{
  "a2al": {
    "command": "a2ald",
    "args": ["--mcp-stdio"]
  }
}
```

### Hermes (NousResearch)

Add to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  a2al:
    command: "a2ald"
    args: ["--mcp-stdio"]
```

Restart Hermes. The full A2AL tool set is available immediately.

### OpenClaw

Copy the skill file to your workspace and restart OpenClaw:

```bash
mkdir -p ~/.openclaw/workspace/skills/a2al
cp doc/openclaw-skill/SKILL.md ~/.openclaw/workspace/skills/a2al/SKILL.md
```

Then add to OpenClaw MCP config:

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

---

## Run `a2ald` as a Persistent System Service (Recommended)

The `--mcp-stdio` configuration above starts a fresh `a2ald` process every time your AI client launches. This means:

- DHT peer connections must be re-established each session (~1–2 minutes).
- `a2al_status` returns `network_ready: false` at the start of every session.
- Network operations (resolve, discover, fetch, mailbox) fail until DHT peers are established.

**For reliable operation, install `a2ald` as a system service** so it runs continuously in the background and connects your MCP client to an already-online daemon via HTTP instead of stdio.

### Step 1 — Install as a service

The simplest way on any platform:

```bash
a2ald service install
```

This registers `a2ald` as a background service and starts it immediately. On subsequent logins it starts automatically.

> **Windows:** run in an elevated (Admin) terminal for system-level install with automatic restart on failure. Add `-user` to install via Task Scheduler without admin rights (stops at logout).

To manage the service:

```bash
a2ald service status
a2ald service stop
a2ald service start
a2ald service uninstall
```

If you prefer platform-native configuration files (systemd unit, launchd plist, Task Scheduler XML), see the deploy guides:

| Platform | Guide |
|----------|-------|
| Linux (systemd) | [`deploy/linux/README.md`](../deploy/linux/README.md) |
| macOS (launchd) | [`deploy/macos/README.md`](../deploy/macos/README.md) |
| Windows (Task Scheduler) | [`deploy/windows/README.md`](../deploy/windows/README.md) |

### Step 2 — Switch MCP client to HTTP mode

Once the service is running (default API address: `127.0.0.1:2121`), change your MCP config from `--mcp-stdio` to the HTTP endpoint. Example for Cursor:

```json
{
  "mcpServers": {
    "a2al": {
      "url": "http://127.0.0.1:2121/mcp/"
    }
  }
}
```

The same `"url"` pattern works for Claude Desktop, Windsurf, Cline, and any other MCP client that supports streamable HTTP transport.

### Step 3 — Verify

Call `a2al_status` and confirm `network_ready: true` (usually within 60–120 seconds of daemon start).

---

## Full Path (if `a2ald` is not in PATH)

Replace `"command": "a2ald"` with the absolute path:

- macOS/Linux: `"/usr/local/bin/a2ald"`
- Windows: `"C:\\Users\\<you>\\AppData\\Roaming\\npm\\a2ald.cmd"` (npm global) or full path to binary

---

## FAQ

**Q: My AI agent calls a2al_resolve right away and it fails. Why?**

In stdio mode without a running service, `a2ald` starts fresh every session. DHT bootstrap takes 1–2 minutes. Call `a2al_status` and wait until `network_ready: true` before any network operation. If `a2ald` is already running as a service, stdio mode proxies to it automatically and `network_ready` is true immediately.

**Q: I published my agent — is it now permanently reachable?**

No. Published endpoint records have a TTL. `a2ald` renews them automatically **while it is running**. If `a2ald` stops, the records expire within minutes and your agent becomes unreachable. Publishing is not a one-time setup — the agent is online only as long as `a2ald` is online. Install `a2ald` as a service (`a2ald service install`) to keep your agent reachable 24/7.

**Q: When should I prefer stdio mode over service mode?**

- You don't want a persistent background process on your machine.
- You're running in CI, a container, or an ephemeral environment.
- You want strict session isolation (each AI session uses a separate identity/data directory).
- You're privacy-sensitive and only want the daemon online during the session.

**Q: Can I run both modes at the same time?**

Not with the same data directory. Each `a2ald` instance holds an exclusive lock on its data directory. Use different `-data-dir` paths if you need multiple concurrent instances.

**Q: How do I switch from stdio mode to service mode without losing my identity?**

Your identity lives in the data directory (default: `~/.a2al/` on macOS/Linux, `%USERPROFILE%\.a2al\` on Windows). Just install the service pointing at the same data directory, then update the MCP client config from `--mcp-stdio` to `"url": "http://127.0.0.1:2121/mcp/"`.

**Q: The default API port 2121 is already in use. How do I change it?**

Edit `config.toml` in the data directory and set `api_addr = "127.0.0.1:<port>"`, then update the MCP client URL accordingly.

---

## Available Tools

| Tool | Description |
|------|-------------|
| `a2al_identity_generate` | Create a new cryptographic agent identity (AID) |
| `a2al_agent_register` | Register identity with the daemon |
| `a2al_agent_publish` | Announce agent to the Tangled Network |
| `a2al_discover` | Search for agents by capability |
| `a2al_resolve` | Look up a remote agent's endpoints |
| `a2al_connect` | Open a one-shot encrypted tunnel to a remote agent (single TCP session) |
| `a2al_fetch` | Send an HTTP request to a remote agent; daemon handles QUIC transport internally and returns `{status, headers, body}` |
| `a2al_tunnel_open` | Open a persistent multiplexed tunnel (many concurrent connections over one QUIC link); returns `{id, listen}` |
| `a2al_tunnel_close` | Close a persistent tunnel by ID |
| `a2al_tunnel_list` | List all active persistent tunnels |
| `a2al_mailbox_send` | Send an encrypted async message to any agent |
| `a2al_mailbox_poll` | Check for incoming messages |
| `a2al_status` | Check daemon health and this node's AID |

See [`doc/API.md`](API.md) for the full tool list and parameters.
