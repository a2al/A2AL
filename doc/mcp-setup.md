# MCP Setup

A2AL daemon (`a2ald`) runs as an MCP server, giving any MCP-compatible AI agent 20+ networking tools: publish identity, discover agents, resolve addresses, send encrypted messages, and more.

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

## Full Path (if `a2ald` is not in PATH)

Replace `"command": "a2ald"` with the absolute path:

- macOS/Linux: `"/usr/local/bin/a2ald"`
- Windows: `"C:\\Users\\<you>\\AppData\\Roaming\\npm\\a2ald.cmd"` (npm global) or full path to binary

---

## Available Tools

| Tool | Description |
|------|-------------|
| `a2al_identity_generate` | Create a new cryptographic agent identity (AID) |
| `a2al_agent_register` | Register identity with the daemon |
| `a2al_agent_publish` | Announce agent to the Tangled Network |
| `a2al_discover` | Search for agents by capability |
| `a2al_resolve` | Look up a remote agent's endpoints |
| `a2al_connect` | Open a direct encrypted tunnel to a remote agent |
| `a2al_mailbox_send` | Send an encrypted async message to any agent |
| `a2al_mailbox_poll` | Check for incoming messages |
| `a2al_status` | Check daemon health and this node's AID |

See [`doc/API.md`](API.md) for the full tool list and parameters.
