# A2AL

You built something — an AI agent, a local service, a home server. Now you want another agent,
another machine, or a teammate to reach it, without you having to touch ports, IPs, or tunnels
every time. Or you want to reach *them*, and they're behind NAT on someone else's network.

The usual answers — a domain, a cloud VM, an ngrok URL — all solve it temporarily, then break
the next time something changes. And they put something between you and the other end.

A2AL takes a different approach: every agent gets a permanent cryptographic address — an **AID**.
You hand it to someone once. From then on, they reach you regardless of your IP, your network,
or whether your machine was asleep when they tried. Because an AID comes from a key you hold,
no registry can revoke it, and no server needs to stay up for you to exist.

## When it's worth it

| Your situation | Without A2AL | With A2AL |
|---|---|---|
| You want another agent to call something on your machine | Set up ngrok or open a port; share a URL that breaks and rotates | Share your AID once. It works across IPs and networks; nothing expires |
| Your agent is behind NAT and needs to be reachable | VPN both sides, or rent a reverse tunnel | Your agent publishes to the network; peers connect directly with no port forwarding |
| You need to leave work for a machine that's offline | Email it, hit a webhook that 404s, wait until it's back | Send an encrypted note to its AID; it reads it when it's back |
| Several agents (and people) need to talk, coordinate, and share files | A vendor workspace, or a home-rolled relay | Open a **room**: group chat + files; history stays after someone was offline |
| You want to keep traffic between machines only | VPN or Tailscale on every node | Run your own network (`--bootstrap` to your own seeds); same protocol, nothing on the public one |

## What you're looking for

| If you want to… | Read |
|---|---|
| Get a2ald running in the next 30 minutes | [Quick Start](quickstart.md) |
| Wire Claude, Cursor, or any MCP host | [MCP Setup](mcp-setup.md) · [MCP Entry Spec](mcp-entry.md) |
| Solve a specific problem end-to-end | [Recipes](recipes.md) |
| Understand identities, notes, chat, rooms, ACL, tunnels | [User Guide](user-guide.md) |
| Call REST, use MCP tools, or the Python client | [API Reference](api-reference.md) |
| Embed A2AL in a Go program | [Go SDK](API.md) |
| Build from source, run tests, contribute | [Developer Guide](developer-guide.md) |
| Understand how addressing and connections work inside | [Architecture](architecture.md) |
| Name a published Capability | [Service categories](service-categories.md) |
| Run the demo binaries | [Examples](examples.md) |
| Configure `a2ald` | [Config example](a2ald-config.example.toml) |
| AID version bytes | [Address Version Registry](address-version-registry.md) |
| What changed in each release | [Changelog](CHANGELOG.md) |

CLI: `a2al help`. Daemon starts a Web UI at `http://localhost:2121`.
