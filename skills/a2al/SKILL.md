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

If `a2al_*` tools are already in your tool list, act on the goal. Do not run doctor first.

If they are not:

1. `npx -y a2ald mcp add` (or `a2ald mcp add`) — starts a daemon if none is running and registers this host.
2. Reload the host. Confirm `a2al_*` tools appear. Then act on the goal.

If add does not know this host, it wrote nothing: run `npx -y a2ald mcp print` and place that entry yourself. What must hold is the endpoint, the transport, and a running daemon: https://github.com/a2al/a2al/blob/main/doc/mcp-entry.md

`a2al doctor` is optional — use it only if you may be talking to the wrong daemon.

If this agent should be fetched or woken by others and it already serves HTTP: `a2al inbound bind --addr host:port` (or `a2al_agent_patch` with service_tcp). Never bind the daemon api_addr. Then give peers your AID plus that printed envelope — they a2al_fetch and fill in their own path. Unreachable now and they can wait → `a2al_mailbox_send`. No inbound HTTP (typical IDE) → skip.

Fetch, leave a note, rooms, and tunnels are in the MCP server's own instructions. Do not wait for a peer count.
