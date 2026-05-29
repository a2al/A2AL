# A2AL MCP — Install Guide

Lets AI agents find and connect to other agents directly—no central server, registry, or pre-configured endpoint required.

`a2ald` is a local daemon with a built-in MCP server (25+ networking tools). Install the binary once, add it to your MCP client config, and your AI can discover peers, resolve addresses, and open encrypted agent-to-agent connections.

Full documentation: [doc/mcp-setup.md](https://github.com/a2al/a2al/blob/main/doc/mcp-setup.md)

---

## 1. Install `a2ald`

Pick one:

**GitHub Release (recommended if you prefer a standalone binary)**

Download from [Releases](https://github.com/a2al/a2al/releases) and put `a2ald` on your PATH.

**npm (downloads the correct platform binary automatically)**

```bash
npm install -g a2ald
```

**npx (no global install — downloads on first MCP session)**

No manual install; use the npx config in step 2 below.

---

## 2. MCP client config

### Stdio — binary on PATH (default)

Use this when `a2ald` is already installed (Release or `npm install -g`):

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

### Stdio — npx fallback (binary not on PATH)

```json
{
  "mcpServers": {
    "a2al": {
      "command": "npx",
      "args": ["-y", "a2ald", "--mcp-stdio"]
    }
  }
}
```

### HTTP — service mode (recommended for daily use)

Install and start the background service first:

```bash
a2ald service install
```

Then point your MCP client at the running daemon:

```json
{
  "mcpServers": {
    "a2al": {
      "url": "http://127.0.0.1:2121/mcp/"
    }
  }
}
```

Service mode avoids a 60–120 s DHT cold-start on every AI session.

---

## 3. Before any network operation

Always call **`a2al_status`** first:

- `network_ready: true` → safe to resolve, discover, fetch, connect, mailbox.
- `network_ready: false` → wait 60–120 s (stdio cold-start) or install as a service.

If a service is already running, `a2ald --mcp-stdio` auto-proxies to it — no cold-start.

---

## 4. Client-specific config paths

| Client | Config file |
|--------|-------------|
| Cursor | `.cursor/mcp.json` or `~/.cursor/mcp.json` |
| Claude Desktop | `claude_desktop_config.json` in Claude app data |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Cline | Cline settings → MCP Servers |

---

## 5. Key tools

| Tool | Purpose |
|------|---------|
| `a2al_status` | Check daemon health and `network_ready` |
| `a2al_discover` | Search agents by capability |
| `a2al_resolve` | Look up a remote agent's endpoints |
| `a2al_fetch` | HTTP request to a remote agent over encrypted transport |
| `a2al_agent_publish` | Announce this agent to the network |
| `a2al_mailbox_send` | Send encrypted async message to any agent |

See [doc/API.md](https://github.com/a2al/a2al/blob/main/doc/API.md) for the full tool list.

---

## Links

- Repository: https://github.com/a2al/a2al
- npm: https://www.npmjs.com/package/a2ald
- Project site: https://a2al.org
