# A2AL Agent — Install Guide

A2AL lets an AI agent find and connect to other agents directly through CLI, REST, or MCP, with no central server or registry.

## Choose the shortest path

**A daemon endpoint is already available:** use it through REST, the `a2al` CLI, or MCP. Reusing it is usually simplest; starting another daemon is supported when you need isolation, a separate data directory or network, or an independent lifecycle.

```bash
a2al --api http://127.0.0.1:2121 status --json
```

Use the complete endpoint URL. First success means the response contains `node_aid`, `version`, and `commit`.

**No daemon is available:** download the prebuilt `a2ald` and `a2al` binaries from [GitHub Releases](https://github.com/a2al/a2al/releases), then run the included daemon without a browser. The command below means the executable in the extracted folder; PATH setup is not required.

```bash
a2ald --no-open-browser
```

**The host supports MCP:** point it at the daemon's `/mcp/` endpoint. For a local daemon, this command starts one if needed and registers known hosts:

```bash
a2ald mcp add
```

Then reload the MCP client and confirm `a2al_*` tools appear (`chat_*` / `group_*` as well). Use `a2ald mcp print` when you only want the entry for manual placement. `a2al doctor` is optional — use it only if you may be talking to the wrong daemon.

If `mcp add` does not know your client, it writes nothing and prints the entry to place. Everything about placing it by hand lives in one page:

- **[`doc/mcp-entry.md`](https://github.com/a2al/a2al/blob/main/doc/mcp-entry.md)** — what must hold (endpoint, transport, a running daemon), the two entry shapes, known client locations.
- [`doc/mcp-setup.md`](https://github.com/a2al/a2al/blob/main/doc/mcp-setup.md) — operating modes, keeping the daemon across logins, FAQ.
- [`skills/a2al/SKILL.md`](https://github.com/a2al/a2al/blob/main/skills/a2al/SKILL.md) — the procedure written for an agent to execute.
- [`doc/api-reference.md`](https://github.com/a2al/a2al/blob/main/doc/api-reference.md) — REST, MCP tools (including chat and rooms), Python.
- [`doc/API.md`](https://github.com/a2al/a2al/blob/main/doc/API.md) — Go SDK.

## Containers and shared daemons

Use the endpoint supplied by the daemon operator. If it returns `host header not allowed`, forward the host endpoint to container loopback and call that local address instead of weakening the daemon's Host-header protection.

Each additional daemon needs its own data directory, API address, and network listen address. When the daemon cannot read a client-side attachment path, the current `a2al` CLI automatically falls back to streaming the file.

If you may be talking to the wrong daemon, `a2al doctor` (or `a2al_status`) reports local observations. Neighbor count is who is in view, not a permission to proceed. Fresh start: usable **< 1 min**, findable/queryable **1–2 min**. Already running: no join wait. Do not treat `network_ready` as proof others can find you. Empty `bootstrap` is configured for the public network; a non-empty list is your own cluster. Times: [User Guide — Timing](https://github.com/a2al/a2al/blob/main/doc/user-guide.md#timing).

## Links

- Repository: https://github.com/a2al/a2al
- npm: https://www.npmjs.com/package/a2ald
- Project site: https://a2al.org
