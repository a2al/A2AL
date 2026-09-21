# User Guide

A2AL is the ready-to-use layer that lets **people, AI assistants, and agents** find each other, talk, coordinate, and leave work for later — without a vendor account, a domain, or a shared chat product.

If `a2ald` is not running yet, start with the [Quick Start](quickstart.md). Agents in an MCP host: [MCP Setup](mcp-setup.md).

---

## What you actually get

The increment is not “another API.” It is that the same identity works for a human in a browser, an AI in an editor, and a worker on a server — and that this keeps working when machines move, sleep, or sit on a private network.

**Open and use.** One local daemon is the whole runtime. People open `http://localhost:2121`. An AI assistant gets MCP tools (`npx -y a2ald mcp add`). Scripts use the CLI or REST. No cloud signup, no DNS, no certificate authority, no reverse-proxy tenant.

**Connect, coordinate, interact.** With someone’s **AID** (their contact card) you can fetch their HTTP, open a tunnel, leave a note they will see when they are back, or join a room. Humans use the UI; agents use the same daemon’s tools. You do not need a third-party IM to introduce two machines.

**Permanent identity.** An AID is yours for as long as you hold the key. IP, hostname, laptop, and cloud VM can all change; contacts keep using the same string. Reachability still needs a live daemon while others should find you now (records expire on TTL). The identity does not.

**Strong privacy, no third party in the data path.** After connect, application bytes go peer-to-peer. The network stores *where to find me now*, not your payloads. Notes are encrypted to the recipient’s key. There is no tenant that can read the session. Isolation is first-class: point `bootstrap` at your own seeds and the same fetch / notes / rooms work with nobody else on the net.

**No extra stack.** You do not rent ngrok, run a directory, or put agents behind a company VPN just so they can address each other. Empty config joins the public Tangled Network. The same commands apply on a rack server and on a home machine.

---

## When it is worth it

AID is a contact, not the product. Use A2AL when the job below is yours and the usual tools are the wrong shape.

| Job | You’d otherwise | Why A2AL |
|-----|-----------------|----------|
| Reach an agent on someone else’s laptop or home box | VPN both sides, ask for a public IP, or an ngrok URL that dies | They send an AID once. You fetch. Wi-Fi and IP can change; the contact does not |
| Let another agent call *your* local HTTP (OpenClaw, n8n, LLM API, A2A) | Domain+TLS, or a tunnel tenant whose hostname you must redistribute | `inbound bind` + AID. Peers keep the same address; no tenant in the data path |
| Your editor’s AI must talk to an agent that isn’t a public SaaS URL | Paste `localhost` (only this PC) or put the specialist on the internet with API keys | `mcp add` here; fetch their AID from any machine that has a daemon |
| Leave work for a machine that is asleep, offline, or powered off | Slack/email the human, or hit a webhook that 404s | Encrypted note to their AID; only their key opens it; they see it when back |
| Keep a shared log without a company chat or a Google doc | Slack (vendor, must be online), a git repo (humans), a shared folder (no identity) | A room: each AID has a signed replica; people watch in the UI; late joiners catch up |
| These machines must not show up on a public network | Tailscale/ZeroTier (still a coordinator), a VPN concentrator, a private MQTT | Your own `bootstrap`. Same fetch / notes / rooms; public DHT never sees you |
| A worker moved (home GPU → cloud, or the reverse) | Edit every client’s base URL, DNS, ngrok dashboard | Same AID; it republishes. Callers do not change |
| Two local AIs coordinating without a shared folder | One JSON file / pipe they both clobber | Each AID has its own notes and rooms; that AID can later leave this machine |

Skip rooms for 1:1 fetch. Skip publish if you only call others. Skip inbound bind if this process has no HTTP to serve (typical IDE assistant).

NAT, sleep, and changing IPs are where this is *most visible*. They are not the product boundary. A well-connected VM uses the same addressing — and still skips the account and the round of URL edits when it moves.

---

## Scenarios

Each story is a job you already have. AID is how you point at the other side — getting one is [Start here](#start-here), not the payoff.

### Call the agent on their machine — no VPN, no tunnel account

A teammate (or your other computer) runs an agent at home. You need to fetch it from the office tonight, and again next month after they’ve changed Wi-Fi.

Slack does not open a socket to their process. A public IP needs their router. ngrok gives a hostname you must rediscover when it rotates, and the tenant sits on the path.

They send you an **AID** once (UI or chat, like a phone number). You `a2al_fetch` / `a2al get` / open `http://127.0.0.1:2121/aid/{AID}/…`. Identity is checked on both sides. After they move, they republish; you still use the same string.

### Your local HTTP should be callable — without buying a domain or renting ngrok

OpenClaw, n8n, a local LLM `/v1`, an A2A or MCP HTTP server — it already listens on this machine. Another agent should POST to it, including from outside this LAN.

```bash
a2al inbound bind --addr 127.0.0.1:8080
```

Publish, keep `a2ald` running, hand them the printed envelope (AID + fetch; they fill in **their** path). Never bind the daemon’s API address.

Unlike a tunnel URL, the address they keep is the AID. Unlike “just listen on 0.0.0.0”, you are not opening a raw port to the world — peers connect through A2AL and prove who they are. Skip this if the process is only an IDE assistant with nothing to serve.

### The AI in your editor should use a specialist that is not a SaaS URL

Cursor / Claude / … is on your laptop. The code-review or research agent is on a lab box (or a colleague’s). `localhost` only works on one PC. Putting that specialist on the public internet means API keys and a hostname you will edit later.

`npx -y a2ald mcp add` on the laptop. The assistant fetches the specialist’s AID (or discovers a capability name). No networking code in the project. The specialist can live on a GPU box at home; the assistant does not care.

### They’re asleep — still leave the work (and not in Slack)

The other daemon is down, the laptop lid is closed, the VM is stopped. A webhook 404s. Asking a human in Slack puts the body on a vendor’s disk, and it is still not a message *to the agent*.

Leave a **note** to their AID (UI, `a2al_mailbox_send`, or `a2al note send`). Encrypted to their key; they see it when the daemon is back. That is store-and-forward, not a live reply. In MCP, a waiting note is attached to a successful tool result when there is one — do not poll the mailbox every turn.

### A shared board that is not Slack and not a Google doc

Three agents (and maybe a human watching) need one history: who wrote what, in order, with no operator. Slack needs a workspace and everyone online. A shared folder has no identity. Git is for people.

A **room**: invite by AID; a join link only if you don’t have everyone’s AID. Each AID holds its own signed replica and catches up after being offline. People open the UI to watch (watching ≠ that AID is “in session”). 1:1 fetch does not need a room.

### These machines must not appear on any public directory

A privacy cluster, an air-gapped lab, or “only the agents on this PC.” Tailscale still has a coordination plane. A homemade VPN is another product to run.

Non-empty `-bootstrap` **skips public DNS**. Loopback keeps it on this host. Same fetch, notes, and rooms.

```bash
a2ald --bootstrap 192.168.1.10:4121          # your seeds
a2ald --bootstrap 127.0.0.1:4121             # this machine only
```

Use a **new** data directory so an old `peers.cache` does not still dial the public net.

### The box moved. Nobody edits a URL

Last week the researcher ran on a home GPU; this week it is a cloud VM (or the reverse). Every ngrok/DNS/base-URL setup is a round of “update the clients.”

The AID does not change. Republish from the new machine (register the same keys). Planners that already have the AID keep calling it. Optional: publish a capability name (`reason.analyze`) so *new* callers discover whoever is up, without a spreadsheet.

---

## Start here

**A person.** Install `a2ald` (or `npx -y a2ald`), open `http://localhost:2121`, create an identity. Publish only if others on this network must resolve you. Give them the **AID**. Persistent service is optional (`a2ald service install -user`) — use it when this machine should stay findable after logout.

**An AI assistant.** If `a2al_*` tools are already in the session, act on the goal. If not: `npx -y a2ald mcp add`, reload, confirm the tools, then fetch / leave a note / use rooms. `a2al doctor` is optional — only if you may be talking to the wrong daemon.

**Be reachable as HTTP.** If this agent already listens locally: `a2al inbound bind --addr host:port` (never the daemon’s API address). Share the printed envelope: AID + how to fetch, and let the peer fill in *their* path. Unreachable now and they can wait → leave a note.

A known AID is also `http://127.0.0.1:2121/aid/{AID}/…` on a machine that has a daemon (or `https://tngld.net/aid/{AID}/…` with no local daemon).

---

## Core concepts

### AID — identity and address unified

An **AID** (Agent Identifier) is a cryptographic address derived from a key pair you generate locally:

```
a2alEKFspDoevpFxLHiagvdBFqMVFq3sZ1JDsFdJKP    ← Ed25519 (native)
0x3a7fc8f294b4e53e91a5b7a4f2c9d0e1b3c8a2f9    ← Ethereum wallet address
```

- **Self-sovereign.** No one assigns it. The private key is the proof of ownership.
- **Permanent.** The AID does not change when IP, host, or cloud vendor does.
- **Verifiable.** Anyone can confirm the peer holds the matching key — no CA.
- **Portable.** The same AID on a laptop, a VM, a home network, or a private cluster.

Share an AID the way you would share a contact. Whoever has it can reach you (while your daemon is published and alive). Rooms and invite links are for *groups*, not the default way to introduce two identities.

### The Tangled Network

Publishing writes a signed record — AID → current endpoints — onto a peer-to-peer network.

- **No central server** to operate, depend on, or get blocked by.
- **Not in the data path.** It stores “where to find me now.” Your application data does not flow through it.
- **Self-healing.** New endpoints are published; old records expire by TTL.
- **Open participation.** Any `a2ald` is a node. Empty `bootstrap` joins the public net; a non-empty list is *your* net.

### a2ald — local runtime, not a proxy

`a2ald` is the process on this machine: identities, DHT, connections, MCP, REST, and the Web UI. It resolves and connects, then steps aside. After the link is up, bytes go directly between peers.

People, agents, and scripts all talk to **this** daemon. A second copy on the default data directory is an accident (lock). A second *node* is intentional: new `-data-dir`, new `-api-addr` / `-listen`, and point CLI/MCP at that API.

### Running as a persistent service

Install a service when this machine should stay findable across logins. Published records expire after the process stops (TTL; default 1 hour). You can work immediately after a cold start; if a call fails, wait 10–30 seconds and retry the same call — do not wait for a peer count.

```bash
a2ald service install          # register + start
a2ald service status           # check running state
a2ald service stop             # stop
a2ald service start            # start
a2ald service uninstall        # remove service registration
```

**Flags for `install`:**

| Flag | Description |
|------|-------------|
| `-data-dir <path>` | Data directory (default: platform config dir). Baked in at install time. |
| `-user` | No-admin install (Windows): Task Scheduler instead of SCM. Stops at logout. |

> **Windows:** `a2ald service install` from any terminal. If admin rights are needed, an interactive menu appears: **[1] System Service** (UAC; survives reboot) or **[2] Task Scheduler** (no elevation; stops at logout). Pass `-user` to skip the menu.

Platform unit files: [`deploy/`](../deploy/).

### Delegated identity — the master key stays offline

Registering an agent creates two keys:

- **Master key**: derives the AID. Keep it offline or in a hardware wallet. Needed to prove ownership or issue new credentials.
- **Operational key**: what `a2ald` uses day-to-day. It carries a delegation proof from the master key.

If an operational key is compromised, revoke it and issue a new one — the AID and existing contacts stay. `a2al register` does this automatically for most users.

---

## The three operations

### Publish — announcing your agent

A signed record contains:

- AID and current endpoints (whatever paths the daemon can observe)
- Optional service declaration (capability name, description, tags)
- A TTL

`a2ald` signs, refreshes endpoints, and republishes before expiry. Publishing is not a promise to be online forever: go offline and the record expires; come back, republish, contacts still have the same AID.

**Service publishing** is how others find you by *what you do* (`lang.translate`, `reason.plan`, …) when they do not already have your AID.

### Discover — finding agents

**Resolve by AID** — you already have the contact. Deterministic.

**Search by service** — you know the capability, not the AID. Filter with tags: `a2al search reason.analyze --filter-tag finance`. Taxonomy: [Service Categories](service-categories.md).

| Service | Capability |
|---------|-----------|
| `lang.translate` | Language translation |
| `lang.chat` | Conversational AI |
| `reason.plan` | Task planning and orchestration |
| `reason.analyze` | Data analysis and research |
| `code.review` | Code review |
| `code.gen` | Code generation |
| `data.search` | Web or knowledge base search |
| `gen.image` | Image generation |
| `tool.browser` | Browser automation |

### Connect — direct encrypted link

Once you have an AID, `a2ald` opens a direct QUIC connection. Both sides verify identity. No trusted third party.

**Fetch** (HTTP) — the daemon sends the request and returns `{status, headers, body}`. No local port. `a2al get` / `a2al post` / `a2al_fetch`.

**One-shot tunnel** — `127.0.0.1:<port>` for one TCP session (SSH, etc.). Released when that TCP connection closes.

**Persistent tunnel** — a long-lived local listener, many connections over one QUIC link (`a2al tunnel`).

Encryption and identity checks are always on. Extra paths (UPnP, ICE, relay) race in parallel where the network needs them; they are not a separate product mode.

---

## Runtime behavior

### How a connection finds a path

`a2ald` gathers candidates and dials them in parallel (not “try NAT first, then something else”):

- **Peer reflection** — what address others see
- **UPnP** — on routers that support it
- **ICE / hole-punching** — when a direct candidate is not enough

Most home, office, and cloud paths succeed this way. Symmetric NAT on *both* sides may need a relay; the UI warns if that condition is detected.

If direct paths fail, a configured TURN relay is last resort. The application API is the same. Example:

```toml
# Static credentials
[[turn_servers]]
url = "turn:turn.example.com:3478?transport=udp"
username = "alice"
credential = "s3cr3t"

# Time-limited HMAC credentials (coturn use-auth-secret)
[[turn_servers]]
url = "turn:coturn.example.com:3478"
credential_type = "hmac"
username = "a2ald"
credential = "<shared_secret>"

# REST API credentials (Twilio, Metered.ca, etc.)
[[turn_servers]]
url = "turn:global.turn.twilio.com:3478?transport=udp"
credential_type = "rest_api"
credential_url = "https://api.twilio.com/.../Tokens.json"
credential = "Basic <base64(AccountSID:AuthToken)>"
```

Disable relay with `disable_relay = true`, or per request. If relay exists but was disabled and the direct path failed, the API returns HTTP 412 `"relay_required"`.

### Endpoint refresh

IP change (new Wi-Fi, container restart, VM migrate): `a2ald` republishes before the old record expires. Callers keep using the AID.

### Bootstrap

Default: public bootstrap, no config. Isolated / private: non-empty `--bootstrap`. After join, the node builds its own table and does not keep depending on the seed.

---

## Glossary

| Term | Definition |
|------|-----------|
| **AID** | Agent Identifier. Cryptographic address from a key pair. Permanent, self-issued. The contact card. |
| **Tangled Network** | Peer-to-peer DHT that stores and resolves AID endpoint records. |
| **a2ald** | Local daemon: DHT, connections, identity, UI, MCP, REST. |
| **Publish** | Write a signed, TTL-bound endpoint record for an AID. |
| **Resolve** | Look up current endpoints for an AID. |
| **Discover** | Search by service capability name. |
| **Connect** | Direct encrypted QUIC to a remote agent, with mutual identity check. |
| **Fetch** | HTTP to a remote agent through the daemon; response returned locally. |
| **Inbound bind** | Attach a local HTTP listen to an AID (`service_tcp`) so others can fetch it. |
| **AID URL** | `http://127.0.0.1:2121/aid/{AID}/…` — same fetch, as a normal HTTP URL. |
| **One-shot tunnel** | Local TCP for a single session to a remote agent. |
| **Persistent tunnel** | Long-lived local listener; many TCP sessions over one QUIC link. |
| **Service** | Capability published with an endpoint record (e.g. `lang.translate`). |
| **Note** | Encrypted store-and-forward for an AID that is not reachable now. Not a live reply. |
| **Room** | Shared signed log; each AID has its own replica. Invite by AID; link when needed. |
| **Master key** | Derives the AID. Keep offline. |
| **Operational key** | Day-to-day key with a delegation proof. Rotatable without changing the AID. |
| **Delegation proof** | Master-key statement authorizing an operational key to publish. |
| **Endpoint record** | Signed, TTL-bound DHT record: AID → current endpoints. |
| **DHT** | Distributed hash table under the Tangled Network. |
| **Bootstrap** | Seeds used to join. Empty = public net. Non-empty = your net (skips public DNS). |
| **TTL** | How long a published record stays valid. Renewed only while `a2ald` runs. |
| **MCP** | Model Context Protocol. A2AL exposes networking as tools for AI hosts. |
