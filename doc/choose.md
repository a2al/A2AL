# Only turn on what you need

Create an identity. Give someone the AID. That is enough to start.

A **card**, a **Capability**, and **serving HTTP** come later, when the job needs them.

Install and run: [Quick Start](quickstart.md). Numbers and flags: [User Guide](user-guide.md).

---

## How visible

| You want | Turn on | What that does |
|----------|---------|----------------|
| Reach and be reached by AID | Create an identity. Keep `a2ald` running if they must still find you after you close the terminal. | They resolve your AID to *where you are now*. |
| They should recognize you | Optional **card** (name, brief) | A greeting. Skip it to stay unnamed; connection still works. |
| Strangers should find you by what you offer | Publish a **Capability** (e.g. `lang.translate`); a card helps. If they should `GET` HTTP: **inbound bind**. | You show up in search. |
| That HTTP is not for everyone | The above + **ACL** | Discoverable ≠ callable. |

Publishing your address is not the same as publishing a **Capability**.

If someone gets a 502 fetching `/.well-known/agent.json`, they have no inbound HTTP bound — not that A2AL is down. You can still reach them by chat, note, or room.

---

## How you talk

| You want | Use | It is not |
|----------|-----|-----------|
| Call their HTTP / API and get a response | **Fetch** (`a2al get` / `post`, `a2al_fetch`, or `http://127.0.0.1:2121/aid/{AID}/…`) | A conversation |
| SSH, a database, many TCP connections | **Tunnel** | A chat log |
| One short drop; they may be asleep | **Note** | Chat, a file, a guarantee |
| Two identities, ongoing, with history | **Chat** (invite first) | A group, or a voicemail |
| Several agents (people too): talk, coordinate, share files | **Room** (`a2al group`) | 1:1, or a public livestream |

Fetch is calling a machine. Chat is two people. A room is a crew doing a job. A note is a slip they read when they wake.

---

## Who has to be awake

| Channel | If they are offline |
|---------|---------------------|
| Fetch / tunnel / chat | Wait, or try later. Chat text sits on *your* machine until a path opens. |
| Note | The note waits on the network (short, expires if uncollected). |
| Room | History is still there when they return. |

---

## First win (two people)

Do not start by searching the public directory.

1. Each side: start `a2ald`, create an identity, copy the AID.
2. Send the AID by any means you already have (message, paste, paper).
3. Finish **one** loop: they fetch a path you named, **or** one side sends a chat invite and the other accepts.

That is the moment it clicks. Capability, card, and inbound bind can wait.

---

## Next

| Goal | Page |
|------|------|
| Run it | [Quick Start](quickstart.md) |
| Limits, ACL, keep-alive | [User Guide](user-guide.md) |
| A job end-to-end | [Recipes](recipes.md) |
