# A2AL MCP — Install Guide

`a2ald` is a local daemon with a built-in MCP server: it lets an AI agent find and connect to other agents directly, with no central server, registry, or pre-configured endpoint.

One command installs and registers:

```bash
npx -y a2ald mcp add    # starts a daemon if needed, registers the server with the hosts it finds
```

Then reload your MCP client, and confirm `a2al_*` tools appear (`chat_*` / `group_*` as well) — no command can check that part for you. `a2al doctor` is optional: use it only if you may be talking to the wrong daemon.

If `mcp add` does not know your client, it writes nothing and prints the entry to place. Everything about placing it by hand lives in one page:

- **[`doc/mcp-entry.md`](https://github.com/a2al/a2al/blob/main/doc/mcp-entry.md)** — what must hold (endpoint, transport, a running daemon), the two entry shapes, known client locations.
- [`doc/mcp-setup.md`](https://github.com/a2al/a2al/blob/main/doc/mcp-setup.md) — operating modes, keeping the daemon across logins, FAQ.
- [`skills/a2al/SKILL.md`](https://github.com/a2al/a2al/blob/main/skills/a2al/SKILL.md) — the procedure written for an agent to execute.
- [`doc/api-reference.md`](https://github.com/a2al/a2al/blob/main/doc/api-reference.md) — REST, MCP tools (including chat and rooms), Python.
- [`doc/API.md`](https://github.com/a2al/a2al/blob/main/doc/API.md) — Go SDK.

If you may be talking to the wrong daemon, `a2al doctor` (or `a2al_status`) reports local observations. Neighbor count is who is in view, not a permission to proceed. Fresh start: usable **< 1 min**, findable/queryable **1–2 min**. Already running: no join wait. Do not treat `network_ready` as proof others can find you. Empty `bootstrap` is configured for the public network; a non-empty list is your own cluster. Times: [User Guide — Timing](https://github.com/a2al/a2al/blob/main/doc/user-guide.md#timing).

## Links

- Repository: https://github.com/a2al/a2al
- npm: https://www.npmjs.com/package/a2ald
- Project site: https://a2al.org
