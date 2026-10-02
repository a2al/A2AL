# The A2AL MCP entry (host-agnostic)

For when `a2ald mcp add` does not know your host, or knows it and got the path wrong. This page states only what must hold; **where the entry goes and how it nests is your host's business, and your host's own documentation outranks this page.**

## What must hold

| | |
|---|---|
| **Endpoint** | `http://127.0.0.1:2121/mcp/` — or whatever `a2ald mcp print` reports, which reads the daemon's actual `api_addr` instead of assuming the default |
| **Transport** | Streamable HTTP, or stdio by spawning `a2ald --mcp-stdio` (proxies to a running daemon) |
| **A running daemon** | With HTTP transport the entry is inert until a daemon serves that address. `a2ald mcp add` starts one. `a2al doctor` is optional if you need to confirm which daemon this machine is talking to |

Nothing else is load-bearing. The server name (`a2al` by convention) is yours to choose.

## The two entry shapes

Hosts differ in where they keep this and what they wrap it in, but the body is one of two forms.

**HTTP** — the host connects to an address:

```json
{ "url": "http://127.0.0.1:2121/mcp/" }
```

**Stdio** — the host spawns a process and talks over its stdin/stdout:

```json
{ "command": "a2ald", "args": ["--mcp-stdio"] }
```

Use an absolute path if `a2ald` is not on the host's PATH, or `{ "command": "npx", "args": ["-y", "a2ald", "--mcp-stdio"] }` to avoid installing anything.

Most JSON-configured hosts nest these under an object keyed by server name, commonly `mcpServers`; TOML-configured hosts commonly use a `[mcp_servers.a2al]` table. Both are conventions, not requirements. Get the exact text with:

```bash
a2ald mcp print                          # JSON, HTTP transport, wrapped
a2ald mcp print --bare                   # just the body, nest it yourself
a2ald mcp print --format toml            # TOML table
a2ald mcp print --transport stdio --npx  # stdio via npx
```

## Known host locations

**Last verified: 2026-09-20.** Hosts move these. If your host says otherwise, believe your host.

| Host | How (from that host's docs) |
|---|---|
| Claude Code | `claude mcp add --scope user --transport http a2al http://127.0.0.1:2121/mcp/` |
| VS Code | `code --add-mcp '{"name":"a2al","type":"http","url":"http://127.0.0.1:2121/mcp/"}'` |
| Cursor | `~/.cursor/mcp.json` under `mcpServers`, HTTP field `url` |
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS); local servers are stdio (`command` / `args`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` under `mcpServers`; HTTP field `serverUrl` |
| OpenClaw | `openclaw mcp add a2al --url http://127.0.0.1:2121/mcp/ --transport streamable-http` |
| Hermes | `hermes mcp add --url http://127.0.0.1:2121/mcp/ a2al` (interactive tool picker); or `~/.hermes/config.yaml` under `mcp_servers`, HTTP field `url` — not both `command` and `url` |
| DeepSeek Harness | merge an `@deepseek-ai/dsh-mcp-client` insert into `$DSH_HOME/cordis.patch.yml` (default `~/.dsh/cordis.patch.yml`); `transport: streamable-http` and `url`. Do not overwrite existing patches |

Where a host offers its own command, prefer it: the host owns its config format, so it cannot be out of date about it.

Already know the file? Skip the guessing entirely:

```bash
a2ald mcp add --client <name> --config <path>
```

## After writing it

1. Reload the host — restart it, or re-open its MCP settings.
2. **Check your own tool list for `a2al_*` (and `chat_*` / `group_*`).** No command can see this for you; if they are absent, the host has not loaded the config, whatever the file says.
3. `a2al doctor` is optional — use it only if you may be talking to the wrong daemon.

## If you are an agent adding a host we do not cover

Please open an issue or PR with the host name, the config path, and the nesting, so `mcp add` learns it: <https://github.com/a2al/a2al/issues>. The host table is data (`cmd/a2ald/mcp-hosts.json`), not code — additions do not need a release.
