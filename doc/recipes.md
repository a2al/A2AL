# Recipes

Concrete paths for the most common situations. Each recipe starts from the problem and ends
with a working result. For flags and parameters, see [API Reference](api-reference.md).

---

## 1. Make your local service reachable from anywhere

**The situation:** You have something running locally — an LLM server, an n8n workflow, an
A2A/MCP endpoint, a private API. You want another agent, another machine, or a collaborator
to call it without you opening ports or setting up a domain.

**What you do once:**

```bash
# 1. Register an identity for this service (if you haven't yet)
a2al register

# 2. Bind your local service to that identity
a2al inbound bind --addr 127.0.0.1:8080 --aid <your-aid>
#   Replace 8080 with the port your service actually listens on.
#   Never use the daemon's own API address (2121).

# 3. Publish a service name so others can find you
a2al publish lang.translate --aid <your-aid>   # or skip if you share the AID directly
```

**What the other side does:**

```bash
# If they know your AID:
a2al get <your-aid> /your/api/path

# If they search by service name:
a2al search lang.translate
# → shows AIDs; pick one and fetch it
```

**Success looks like:** `a2al get <your-aid> /.well-known/agent.json` returns JSON from your
service. The other side's IP, network, or NAT configuration does not matter.

**Keep it running:** The bind is stored with the identity in the daemon data directory; it comes back when `a2ald` restarts from the same data dir. Published records expire within an hour if the daemon is down — keep it running across logins (Windows/macOS: `a2ald service install`; Linux: [deploy/linux](../deploy/linux/README.md)). See [User Guide → Access control](user-guide.md#access-control) if you need to restrict who can call.

---

## 2. Reach an agent that is behind NAT on someone else's network

**The situation:** A teammate, a remote workstation, or a home machine runs an agent. You
have its AID. You want to call it without either side needing a VPN, a public IP, or a tunnel
that breaks when the network changes.

**Prerequisites:** Both machines run `a2ald`. The remote agent has registered an AID and
published it (or has a service bound — see Recipe 1).

**On your side:**

```bash
# HTTP call — exactly like a local one
a2al get <their-aid> /.well-known/agent.json

# If you need a persistent TCP connection (SSH, database client, gRPC):
a2al tunnel open <their-aid> --local-port 2222
# → Listening on 127.0.0.1:2222
# Then: ssh -p 2222 user@127.0.0.1   (or whatever the service expects)
```

**Success looks like:** The call completes. The remote machine's IP may be completely
non-routable from the outside; `a2ald` handles NAT traversal transparently.

**If a2ald just started:** usable **< 1 min**; being found takes **1–2 min**.
If it is already running, call immediately. Do not wait for a peer count. Times: [User Guide — Timing](user-guide.md#timing).

**If they are offline:** Leave a note and they get it when they are back:

```bash
a2al note send <your-aid> <their-aid> "$(echo -n 'run job X' | base64)"
```

---

## 3. Connect your AI assistant to a local service

**The situation:** You use Claude, Cursor, or another MCP host. You want to let it call
something local — your own LLM, a private tool, a company API that is not on the internet —
without exposing the service publicly.

**Step 1 — Wire the MCP server (if not already done):**

```bash
a2ald mcp add
```

Run this with the prebuilt `a2ald` from [GitHub Releases](https://github.com/a2al/a2al/releases), then reload the host and confirm `a2al_*` tools appear. If a daemon endpoint is already available, point the host at its `/mcp/` URL instead.

**Step 2 — Register and bind your local service:**

In the host's chat, or via CLI:

```bash
a2al register                                # creates an AID
a2al inbound bind --addr 127.0.0.1:11434    # e.g. Ollama; use your actual port
```

Or ask the assistant directly: *"Register a new identity and bind my Ollama server at
127.0.0.1:11434 to it."* — it will use `a2al_agent_register` and `a2al_agent_patch`.

**Step 3 — Call the service through the assistant:**

Give the assistant the AID:
*"Fetch `/.well-known/agent.json` from `<aid>`."*

Or call it directly from another machine/agent using `a2al_fetch` or `a2al get`.

**For two assistants to call each other:**

On machine A: register, bind, publish.  
On machine B: `a2al_resolve <aid-from-A>`, then `a2al_fetch` to the path you need.  
The call is end-to-end encrypted; nothing passes through any server in between.

---

## 4. Build a private network for your own machines

**The situation:** You have several machines (home lab, team servers, air-gapped cluster)
and you want them to find and reach each other without joining the public Tangled Network.
No traffic should go to or from the public directory.

**On the first machine (seed node):**

```bash
a2ald --listen :4121 --data-dir /var/lib/a2al/node-a
```

Note its IP address, e.g. `192.168.1.10`.

**On every other machine:**

```bash
a2ald --bootstrap 192.168.1.10:4121 --data-dir /var/lib/a2al/node-b
```

`--bootstrap` with a non-empty list skips public DNS and beacons entirely.
Use a fresh `--data-dir` so old `peers.cache` does not dial public nodes.

**Running two nodes on the same machine** (for testing):

```bash
# Node A
a2ald --data-dir ./node-a --listen :4121 --fallback-host 127.0.0.1

# Node B
a2ald --data-dir ./node-b --listen :4122 --api-addr 127.0.0.1:2122 \
      --fallback-host 127.0.0.1 --bootstrap 127.0.0.1:4121

# Verify: from node-B, resolve an AID registered on node-A
a2al --api http://127.0.0.1:2122 resolve <aid-from-node-a>
```

**Agents, notes, rooms, and fetch all work the same way** on a private network — the protocol
is identical, the directory is yours.

**Add more nodes later:** point them at any already-running node's `--listen` address.
The network grows without any central coordination.

---

## 5. Hand off work to a machine that is offline

**The situation:** You want to delegate a task to another agent or machine, but it is not
online right now — maybe it's a workstation you haven't turned on yet, or a server that
reboots at night.

```bash
# Encode the task payload
PAYLOAD=$(echo -n '{"job":"process_data","file":"s3://..."}' | base64)

# Send it — the daemon stores it in the network until they are back
a2al note send <your-aid> <their-aid> "$PAYLOAD"
```

The recipient lists when they come back, then polls to take:

```bash
a2al note list <their-aid>   # look
a2al note poll <their-aid>   # take (removes)
```

**For agents via MCP:** `a2al_mailbox_send` / `a2al_mailbox_list` / `a2al_mailbox_poll`.  
A successful tool result will include `pending.mailbox: N` — that is the signal to list. Poll when you will act.
Do not poll every turn without that signal.

**Notes are not chat.** If you need back-and-forth, use `a2al chat` after both sides are
online. If you need guaranteed delivery with receipts, that is a layer above — notes are
best-effort store-and-forward.

---

## Where to go next

| Goal | Read |
|------|------|
| Access control — restrict who can call your service | [User Guide → Access control](user-guide.md#access-control) |
| 1:1 conversation between two agents | [User Guide → Chat](user-guide.md#chat-11) |
| Agents (and people) coordinating in a room | [User Guide → Rooms](user-guide.md#rooms) |
| Full REST / MCP parameter reference | [API Reference](api-reference.md) |
| Embed A2AL in a Go program | [Go SDK](API.md) |
