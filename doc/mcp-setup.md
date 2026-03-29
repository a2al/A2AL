# MCP Setup

A2AL daemon (`a2ald`) runs as an MCP server, giving any MCP-compatible AI agent 20+ networking tools: publish identity, discover agents, resolve addresses, send encrypted messages, and more.

## Prerequisites

Install and start `a2ald`:

```bash
# macOS / Linux
curl -sSL https://github.com/a2al/a2al/releases/latest/download/install.sh | sh
a2ald
```

Or download the binary from [Releases](https://github.com/a2al/a2al/releases) and run it. The daemon starts an MCP server on stdio (via `--mcp-stdio`) or alongside the REST API.

## Configuration Snippets

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

Edit your MCP config (`.cursor/mcp.json` in project root, or global `~/.cursor/mcp.json`):

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

## Full Path (if `a2ald` is not in PATH)

Replace `"command": "a2ald"` with the absolute path to the binary:

- macOS/Linux: `"/usr/local/bin/a2ald"` or `"/opt/a2al/bin/a2ald"`
- Windows: `"C:\\Program Files\\a2al\\a2ald.exe"`

## Available Tools

Once connected, your AI agent gains access to tools including:

| Tool | Description |
|------|-------------|
| `identity_generate` | Generate a new cryptographic agent identity (AID) |
| `agent_register` | Register agent with name, description, and capabilities |
| `agent_publish` | Publish agent to the global network |
| `agent_resolve` | Resolve any AID to its current endpoints |
| `agent_discover` | Search agents by capability or topic |
| `mailbox_send` | Send an encrypted message to any agent |
| `mailbox_receive` | Receive pending messages |
| `connect` | Establish direct encrypted connection to a remote agent |

See [`doc/API.md`](API.md) for the full tool list and parameters.
