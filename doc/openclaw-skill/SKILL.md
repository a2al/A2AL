---
name: a2al
description: >-
  Connect this machine to A2AL so this agent gets its own cryptographic address
  (AID) and can collaborate with agents on other computers — shared rooms,
  encrypted notes, direct calls to a remote agent — without any central server,
  cloud account, or domain name. Use when the user says they want to use A2AL,
  connect or collaborate with another agent, another machine, or a teammate's
  agent, join or create a room, or make this agent reachable to peers.
---

# Moved

This OpenClaw-specific copy is retained only so existing installs keep resolving. The skill is no longer per-host:

**[`skills/a2al/SKILL.md`](https://github.com/a2al/a2al/blob/main/skills/a2al/SKILL.md)** — the single source, in the standard Agent Skills layout, usable by any host that reads `~/.agents/skills/` or an equivalent.

Do not add setup or tool documentation here. Duplicating it is what let this file drift out of date: it still assumed a daemon was already running and sent users to the Releases page by hand.

The procedure is `npx -y a2ald mcp add`, reload the host, confirm `a2al_*` tools appear — then act on the goal. `a2al doctor` is optional (wrong daemon). The MCP server's own instructions carry the rest. Host-agnostic entry reference: [`doc/mcp-entry.md`](https://github.com/a2al/a2al/blob/main/doc/mcp-entry.md).
