# API Reference

REST, MCP, and the Python sidecar. All except embedding Go require `a2ald` (default `http://127.0.0.1:2121`). Go embed: [Go SDK](API.md). MCP hosts: [MCP Setup](mcp-setup.md).

| Path | Use |
|------|-----|
| REST | Any language |
| MCP | Claude, Cursor, Windsurf, … |
| `pip install a2al` | Python `Daemon` + thin `Client` |
| `a2al` CLI | Same daemon; `group` / `chat` call `POST /mcp/call` |

---

## Auth

If `api_token` is set: non-loopback needs `Authorization: Bearer <token>`. Loopback skips the token unless `require_local_token = true`. Empty token = open (intentional). Mutating requests: `Content-Type: application/json`. `GET /agents/{aid}/export` is loopback-only.

JSON bodies on the management API are capped at **1 MiB**. Fetch response bodies are capped at **4 MiB** (`truncated: true` if cut). CAS `POST /agents/{aid}/cas` streams and has no JSON cap.

AID gateway `GET /aid/…` is **not** the management API: no bearer token; remote object/HTTP access uses that AID’s ACL.

---

## REST

### Health, config, update

| Method | Path | Notes |
|--------|------|--------|
| `GET` | `/health` | `{"status":"ok"}` |
| `GET` | `/status` | Node AID, publish times, `pending` inventory |
| `GET` `PATCH` | `/config` | GET redacts `api_token`. PATCH fields listed below |
| `GET` | `/config/schema` | JSON Schema |
| `GET` | `/update/status` | Current check / last apply |
| `POST` | `/update/apply` | Body ignored. **202** `{message}`; may include `warning` if not a managed service |

`PATCH /config` accepts only: `listen_addr`, `quic_listen_addr`, `bootstrap`, `disable_upnp`, `fallback_host`, `min_observed_peers`, `api_addr`, `api_token`, `key_dir`, `log_format`, `log_level`, `auto_publish`, `turn_servers`, `disable_relay`. Response `{ok, restart_required:[…]}`. Other TOML keys: edit `config.toml` and restart.

### Identity and agents

| Method | Path | Notes |
|--------|------|--------|
| `POST` | `/identity/generate` | Ed25519 master + op key + proof. Master shown once |
| `POST` | `/agents/generate` | `{"chain":"ethereum"\|"paralism"}` |
| `POST` | `/agents/ethereum/delegation-message` | See Ethereum body below |
| `POST` | `/agents/ethereum/register` | After wallet `personal_sign` |
| `POST` | `/agents/ethereum/proof` | Local eth private key (automation) |
| `POST` | `/agents/paralism/proof` | Same shape as eth proof, key field `paralism_private_key_hex` |
| `POST` | `/agents` | Register *or* import: `operational_private_key_hex`, `delegation_proof_hex`, optional `service_tcp` |
| `GET` | `/agents` | List (includes `pending`) |
| `GET` | `/agents/{aid}` | One agent |
| `GET` | `/agents/{aid}/export` | Operational credentials (plaintext JSON); loopback only. CLI `--password` encrypts the file |
| `PATCH` | `/agents/{aid}` | `service_tcp` (string or empty to unbind); optional `operational_private_key_hex` |
| `DELETE` | `/agents/{aid}` | Body `{}` |
| `GET` | `/agents/{aid}/probe` | TCP + DHT reachability |
| `POST` | `/agents/{aid}/heartbeat` | Optional; other mutating agent calls already count |
| `POST` | `/agents/{aid}/publish` | Force endpoint publish |
| `POST` | `/agents/{aid}/records` | Custom RecType `0x02`–`0x0f`: `rec_type`, `payload_base64`, `ttl` |
| `POST` `DELETE` | `/agents/{aid}/profile` | See profile body below |

`POST /identity/generate` → `aid`, `master_private_key_hex`, `operational_private_key_hex`, `delegation_proof_hex`. Recover from a master key in the Web UI (browser signs locally); CLI re-imports via export file or `POST /agents`.

Ethereum (provide **exactly one** of `operational_public_key_hex` or `operational_private_key_seed_hex` on the message call; register needs an op private key or seed):

```http
POST /agents/ethereum/delegation-message
{"agent":"0x…","issued_at":0,"expires_at":0,"scope":0,
 "operational_public_key_hex":"…"}            # or operational_private_key_seed_hex
# → {"message":"<EIP-191 text>"}

POST /agents/ethereum/register
{"agent":"0x…","issued_at":0,"expires_at":0,"eth_signature_hex":"…",
 "service_tcp":"","operational_private_key_hex":"…"}   # or …_seed_hex
# → {"aid","status":"registered"}

POST /agents/ethereum/proof
{"ethereum_private_key_hex":"…","issued_at":0,"expires_at":0}
# op key optional; generated if omitted
```

Profile body (all optional): `name`, `brief`, `protocols`, `skills` (max 3), `modalities`, `card_hash` (SHA-256 of `agent.json`, hex or base64), `meta`. DELETE drops the override.

### Services and discover

```http
POST /agents/{aid}/services
{"services":["lang.translate"],"name":"…","protocols":["http"],"tags":["legal"],"brief":"…","ttl":3600}

DELETE /agents/{aid}/services/lang.translate
{}

POST /discover
{"services":["lang.translate"],"filter":{"protocols":["mcp"],"tags":["legal"]}}
```

### Resolve, fetch, tunnels

```http
POST /resolve/{aid}
GET  /resolve/{aid}/records?type=0

POST /fetch/{aid}
{"method":"GET","path":"/.well-known/agent.json","local_aid":"…","access_token":"…","headers":{},"body_base64":""}
# → {status, headers, body (base64), truncated}   body cap 4 MiB

POST /connect/{aid}
{"local_aid":"…","access_token":"…","disable_relay":false}
# → {"tunnel":"127.0.0.1:PORT"}   one TCP session

POST /tunnel/{aid}
{"local_aid":"…","access_token":"…","local_port":18080,"idle_timeout_sec":90,"disable_relay":false}
# → {id, listen, remote_aid, is_relayed}
# same local+remote+port reuses; 409 port_in_use; 412 relay_required

GET    /tunnel
GET    /tunnel/{id}
DELETE /tunnel/{id}
POST   /tunnel/{id}/reset
```

`disable_relay: true` skips TURN even if configured. `idle_timeout_sec`: omit/0 = 6 min; `-1` = no idle close.

### Notes (mailbox)

```http
POST /agents/{aid}/mailbox/send
{"recipient":"…","msg_type":1,"body_base64":"…"}

POST /agents/{aid}/mailbox/poll
{}
# → {"messages":[{"sender","msg_type","body_base64"},…]}
```

`msg_type`: CLI default `1`. Application text notes typically `3`. Room invites are `0x10` (daemon-written on `group_invite`). Chat invites never use mailbox.

### Chat

| Method | Path | Body |
|--------|------|------|
| `POST` | `/agents/{aid}/chat/request` | `{"peer","note?"}` |
| `POST` | `/agents/{aid}/chat/accept` | `{"peer"}` |
| `POST` | `/agents/{aid}/chat/refuse` | `{"peer"}` |
| `POST` | `/agents/{aid}/chat/remove` | `{"peer"}` |
| `POST` | `/agents/{aid}/chat/block` | `{"peer"}` |
| `POST` | `/agents/{aid}/chat/send` | `{"peer","text?"}` plus `path` **or** `object_id` (not both) |
| `POST` | `/agents/{aid}/chat/mark-read` | `{"peer","scanned_to?"}` |
| `GET` | `/agents/{aid}/chat/contacts` | friends / `out_pending` / `in_pending` |
| `GET` | `/agents/{aid}/chat/peers/{peer}` | `?after_seq` `&limit` → `{entries, scanned_to, has_more, read_cursor, unread_count}` |

Invite first; send without it → `not_friends`.

### Rooms (inspect vs write)

Read-only REST (looking does not count as heartbeat):

| Method | Path | Response / Notes |
|--------|------|-----------------|
| `GET` | `/agents/{aid}/groups` | `{groups:[…]}` — local replicas only |
| `GET` | `/agents/{aid}/groups/{group_id}` | Head / counters |
| `GET` | `/agents/{aid}/groups/{group_id}/entries` | `?after_seq` `&limit` (default and max 50). No kind/author filters on this path |

Write path: MCP `group_*` or `POST /mcp/call` (CLI `a2al group`). Inspect does **not** record heartbeat.

### Objects (CAS)

```http
POST /agents/{aid}/cas?name=file.bin
Content-Type: application/octet-stream
<bytes>
# requires files_root; → {object_id, size, name, url}

GET|HEAD /aid/{holder}/cas/{object_id}
```

Reads on `/aid/` follow the holder’s ACL. Writes are local-only (API token). `group_object_put` with `path` can hash in place without copying when the file is visible to `a2ald`.

### ACL (agent HTTP / objects)

```http
GET   /agents/{aid}/acl
PATCH /agents/{aid}/acl          {"default":"public"|"deny"}
POST  /agents/{aid}/acl/allow    {"aid":"…"}  or  {"secret":"…"}
POST  /agents/{aid}/acl/deny     {"aid":"…"}
DELETE /agents/{aid}/acl/allow/{id}
DELETE /agents/{aid}/acl/deny/{id}
```

Does not gate notes, DHT, or chat.

### Events

- HTTP: `GET /agents/{aid}/events` (SSE). Replay: `?last_event_id=N` or `Last-Event-ID`. Filter: `?types=chat.unread,mailbox.received` (comma). `GET /events` is node-wide.
- Poll: MCP `a2al_events_poll` (`after_seq`, not `last_event_id`) or `POST /mcp/call`.

On subscribe, `event: pending` may appear **without** `id`: local counts such as `{"<aid>":{"mailbox":1,"chat_invites":0,"chat_unread":2}}`. Log events: `mailbox.received`, `group.unread`, `group.mentioned`, `group.appended` (own write), `chat.invites`, `chat.unread`, `chat.received`. Events are doorbells; mailbox / chat log / room log are source of truth.

### Node: remote admin, address book, AID gateway

| Method | Path | Notes |
|--------|------|--------|
| `GET` `PATCH` | `/node/remote-admin` | PATCH `{"enabled":true}` |
| `POST` | `/node/remote-admin/allow` / `deny` | `{"aid"}` or allow `{"secret"}` |
| `DELETE` | `/node/remote-admin/allow/{id}` / `deny/{id}` | |
| `GET` `PUT` | `/node/address-book` | `{aliases:{aid:label}, favorites:[{id,aid,skill,protocols,addedAt}]}` |
| `GET` | `/aid/{AID}/{path}` | Forwards any HTTP method except CONNECT. Uses the **node** identity; **no** `access_token`. ACL-gated peers: `POST /fetch` |
| `GET` | `/debug/identity` `/debug/routing` `/debug/store` `/debug/stats` `/debug/host` | DHT / NAT / bind |
| `POST` | `/mcp/call` | `{"tool":"group_create","args":{…}}` → tool JSON; tool errors **422** |
| | `/mcp/` | Streamable HTTP MCP |

`POST /demo/start|stop` and `GET /sessions/{port}` are the built-in demo helper, not general apps.

---

## MCP tools

HTTP: `http://127.0.0.1:2121/mcp/`. Stdio: `a2ald --mcp-stdio` proxies a running daemon; if none is running, that process is the node (no REST/UI).

Successful results may include `pending`. Room invites → mailbox; chat invites → `chat_invites`. No MCP for ACL, remote admin, address book, or profile.

Required fields in **bold**. `aid` on every `chat_*` / `group_*` is the **local** identity.

### `a2al_*`

| Tool | Arguments |
|------|-----------|
| `a2al_identity_generate` | (none) — save master key |
| `a2al_agents_list` / `a2al_status` / `a2al_tunnel_list` | (none) |
| `a2al_agents_generate_ethereum` | (none) |
| `a2al_ethereum_delegation_message` | **agent**, **issued_at**, **expires_at**, `scope?`; exactly one of `operational_public_key_hex` / `operational_private_key_seed_hex` |
| `a2al_ethereum_register` | **agent**, timestamps, **eth_signature_hex**, `service_tcp?`, op private key **or** seed |
| `a2al_ethereum_proof` | **ethereum_private_key_hex**, timestamps, `scope?`, op key optional |
| `a2al_agent_register` | **operational_private_key_hex**, **delegation_proof_hex**, `service_tcp?` |
| `a2al_agent_get` / `_probe` / `_publish` / `_heartbeat` / `_delete` | **aid** |
| `a2al_agent_patch` | **aid**, `service_tcp`, `operational_private_key_hex?` |
| `a2al_agent_publish_record` | **aid**, **rec_type**, **payload_base64**, `ttl?` |
| `a2al_resolve` | **aid** |
| `a2al_resolve_records` | **aid**, `type` (0 = all) |
| `a2al_discover` | **services[]**, `filter.protocols?`, `filter.tags?` |
| `a2al_service_register` | **aid**, **services[]**, `name`, `protocols[]`, `tags[]`, `brief`, `meta`, `ttl` |
| `a2al_service_unregister` | **aid**, **service** |
| `a2al_fetch` | **remote_aid**, **path**, `method?`, `headers?`, `body_base64?`, `local_aid?`, `access_token?` |
| `a2al_connect` | **remote_aid**, `local_aid?`, `access_token?` (no `disable_relay` on this tool) |
| `a2al_tunnel_open` | **remote_aid**, `local_aid?`, `access_token?`, `local_port?`, `idle_timeout_sec?` |
| `a2al_tunnel_close` | **tunnel_id** |
| `a2al_mailbox_send` | **aid**, **recipient**, **msg_type**, **body_base64** |
| `a2al_mailbox_poll` | **aid** |
| `a2al_events_poll` | **aid**, `after_seq` (0 = start of buffer) |

`a2al_events_poll` → `{events, last_seq, oldest_seq, truncated}`. Next call: `after_seq = last_seq`. If `truncated`, reset to 0.

### `chat_*`

| Tool | Other args |
|------|------------|
| `chat_request` | **peer**, `note?` |
| `chat_accept` / `chat_refuse` / `chat_remove` / `chat_block` | **peer** |
| `chat_send` | **peer**, `text?`, `path` **or** `object_id` |
| `chat_read` | **peer**, `after_seq`, `limit?` → page with `scanned_to` |
| `chat_mark_read` | **peer**, `scanned_to` (0 / omit = all currently in the log) |
| `chat_contacts` | (aid only) |

### `group_*`

| Tool | Other args |
|------|------------|
| `group_create` | `title?` → `{group_id, link}` |
| `group_list` | local replicas only |
| `group_invite` | **group_id**, **target_aid** |
| `group_join` | **link** *or* (`group_id` + `creator_aid`); `peer_aid?`, `inviter_aid?`, `member_hints[]?`, `title?` |
| `group_get_link` / `group_head` / `group_members` | **group_id** |
| `group_append` | **group_id**, `kind?` (default `msg`), `body?` (base64, ≤2 KiB decoded), `ref?`, `reply_to?`, `to[]?` |
| `group_read` | **group_id**, `after_seq?`, `limit?` (default 50), `kind` / `author` / `since_ts` / `until_ts` / `to` / `reply_to`. Page with **`scanned_to_seq`**. Omit `after_seq` → oldest entries |
| `group_mark_read` | **group_id**, **seq** (0 = nothing read) |
| `group_retract` | **group_id**, **entry_id** |
| `group_object_put` | `path` **or** `body_base64` (+ `name?`; needs `files_root`) |
| `group_object_locate` | **object_id**, `hint_aid?` |
| `group_object_get` | **object_id**, `dest?`, `hint_aid?`, `register?`, `access_token?` |
| `group_sync` | **group_id**, **peer_aid** — diagnostics |

---

## Python

```bash
pip install a2al
```

```python
from a2al import Daemon, Client

with Daemon() as d:
    c = Client(d.api_base, token=d.api_token)
    c.health()
    c.resolve(remote_aid)
    r = c.fetch(remote_aid, method="GET", path="/.well-known/agent.json")
    t = c.tunnel_open(remote_aid)
    c.tunnel_close(t["id"])
```

`Daemon(a2ald_exe=…, extra_args=["--bootstrap", "127.0.0.1:4121"])`. Env: `A2ALD_PATH`, `A2AL_API_TOKEN`. Sidecar uses a temp data dir and a free API port.

| Method | REST |
|--------|------|
| `health` / `config_get` | `/health`, `/config` |
| `identity_generate` / `agent_register` / `agent_publish` / `agents_list` | identity + agents |
| `resolve` / `connect` / `fetch` | resolve, connect, fetch |
| `tunnel_open` / `tunnel_close` / `tunnel_list` / `tunnel_status` | tunnels |

`Client.fetch` / `connect` / `tunnel_open` do not take `access_token`. No `tunnel_reset`. Everything else: HTTP to `d.api_base` or `a2al` CLI.

---

## CLI

Global: `--api`, `--token`, `--json`, `--quiet`. Env `A2AL_API`, `A2AL_TOKEN`. `chat` / `group` call `POST /mcp/call`. `a2al group help` / `a2al note help`.

| Command | Flags / args |
|---------|----------------|
| `status` `doctor` `version` | |
| `register` | `[--ethereum --eth-key 0x…] [--service-tcp host:port] [--save-master FILE] [--no-publish]` |
| `identity new` / `new-eth` | Raw keys (JSON); does not register |
| `publish` | `<service> [--from URL] [--name] [--brief] [--url] [--aid] [--ttl] [--protocol] [--tag] [-y]` |
| `unpublish` | `<service> [--aid]` |
| `search` | `<service>… [--filter-protocol] [--filter-tag]` |
| `info` `resolve` | `<aid>` |
| `get` | `<aid> <path> [--header K:V] [--local-aid] [--access-token]` |
| `post` | `<aid> <path> [-d JSON] [--header] [--local-aid] [--access-token]` |
| `inbound bind` | `--addr host:port [--aid]` — never the daemon `api_addr` |
| `connect` | `<aid> [--local-aid] [--access-token]` |
| `tunnel` | (list) · `open <aid> [--local-aid] [--local-port N] [--idle-timeout N] [--access-token]` · `close` / `reset` / `status <id>` |
| `note send` | `<local> <remote> <body-base64> [--msg-type N]` (default type `1`) |
| `note poll` | `<local>` |
| `chat` / `group` | Same flags as [User Guide](user-guide.md#chat-11) / [rooms](user-guide.md#rooms) |
| `agents` | `new` `new-eth` `get` `update --service-tcp` `del` `publish` `heartbeat` `export [-o] [--password]` `import [--password]` `topic add <aid> <svc>… [--name --brief --url --ttl --protocol --tag]` `topic del` `acl` `acl-default` `acl-allow` (`--secret`) `acl-deny` `acl-del` |
| `config` | `get [key]` · `set <key> <value>` (PATCH-able keys only) |
| `admin` | `on` `off` `password <secret>\|off` `allow` `deny` `del allow\|deny <id>` |
| `update` | `[--check]` `[--confirm]` |

### `a2ald`

`--data-dir` `--config` `--listen` `--api-addr` `--fallback-host` `--bootstrap` (comma `host:port`) `--mcp-stdio` `--no-open-browser`

Default data dir: `os.UserConfigDir()/a2al` — Windows `%APPDATA%\a2al`, macOS `~/Library/Application Support/a2al`, Linux `~/.config/a2al`.

`service install|uninstall|start|stop|status` — Windows and macOS (`-data-dir`; `-user` is Windows only: Task Scheduler, stops at logout). Linux: [deploy/linux](../deploy/linux/README.md).

`mcp add [--client auto\|name] [--config PATH] [--transport http\|stdio] [--dry-run] [--npx] [--name a2al] [--data-dir]`

`mcp print [--transport http\|stdio] [--format json\|toml] [--bare] [--npx]`

`update [--check]`
