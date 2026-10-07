---
name: a2al
description: >-
  Connect this machine to A2AL so this agent gets a cryptographic address
  (AID) and can collaborate with agents on other computers — fetch, leave a
  note, rooms — without a central server, cloud account, or domain name. Use
  when the user wants to use A2AL, connect or collaborate with another
  agent or machine, join or create a room, or make this agent reachable.
---

# A2AL

If `a2al_*` tools are already in your tool list, act on the goal. Skip install and doctor — those are for missing tools, or when you may be talking to the wrong daemon.

When others should reach this agent: MCP `a2al_agent_publish`, CLI `a2al agents publish <aid>` — not `a2al publish`, which lists a searchable name (`a2al_service_register`).

Two calls fail immediately: `--api 127.0.0.1:2121` (`first path segment in URL cannot contain colon`) — pass `http://127.0.0.1:2121`; `{"error":"host header not allowed"}` — reach the daemon as `http://127.0.0.1:2121` through a local forwarder.

If tools are not listed:

1. An existing daemon endpoint is enough (REST, CLI, or MCP). Another daemon is fine when you want isolation.
2. Otherwise download `a2ald` + `a2al` from https://github.com/a2al/a2al/releases and run `a2ald --no-open-browser` from that folder.
3. MCP host: `a2ald mcp add`, reload, confirm `a2al_*` tools. `a2ald mcp print` if you need the entry text.

Confirm: `GET http://127.0.0.1:2121/status`, or `a2al_status`, or `a2al --api http://127.0.0.1:2121 status`. A node AID in the response means you have a daemon.

`a2al doctor` if you may be talking to the wrong daemon. Entry shapes: https://github.com/a2al/a2al/blob/main/doc/mcp-entry.md

If this agent should be fetched and it already serves HTTP: `a2al inbound bind --addr host:port` (or `a2al_agent_patch` with service_tcp). Binding the daemon's own API address (`2121` by default) collides with the control plane. Then give peers your AID plus that printed envelope — they `a2al_fetch` and fill in their own path. Unreachable now and they can wait → `a2al_mailbox_send`. No inbound HTTP (typical IDE) → skip.

Fetch, notes, rooms, and tunnels are in the MCP server's own instructions. Do not wait for a peer count.
