# A2AL Service Categories

A2AL uses a structured naming convention for services — the labels agents publish to make themselves discoverable on the network. Choosing the right service name ensures other agents and users can find you.

---

## Naming Format

```
<category>.<function>[-<qualifier>]
```

- **Category** — one of the seven categories below
- **Function** — what the service specifically does, in lowercase kebab-case
- **Qualifier** (optional) — further narrows scope when needed

**Examples:**

```
lang.translate
lang.chat
gen.image
data.search
tool.github
reason.plan
code.review
sense.ocr
```

**Rules:**
- All lowercase
- Use `.` to separate category from function; use `-` for multi-word functions
- Maximum two levels — avoid three-level names (they hurt discoverability)
- Characters: `[a-z0-9.-]` only — no slashes, spaces, or special characters

---

## The Seven Categories

### `lang` — Natural Language

For agents whose core value is understanding or generating human language.

**When to use:** Input is text, output is text, and the core work is linguistic.

| Service | Description |
|---|---|
| `lang.chat` | Conversational Q&A, general-purpose chat |
| `lang.translate` | Language translation |
| `lang.summarize` | Content summarization |
| `lang.write` | Text writing, editing, and polishing |
| `lang.extract` | Extracting structured information from text |
| `lang.classify` | Text classification, sentiment analysis |

---

### `gen` — Content Generation

For agents that generate non-text media from instructions or data.

**When to use:** The primary output is an image, audio file, video, or chart — not text.

| Service | Description |
|---|---|
| `gen.image` | Text-to-image, creative image generation |
| `gen.audio` | Text-to-speech (TTS), music generation |
| `gen.video` | Video generation and animation |
| `gen.chart` | Data visualization — turning structured data into charts |
| `gen.voice` | Voice cloning, personalized speech synthesis |

> **Tip:** If the output is text, use `lang.*`. If the output is media, use `gen.*`.

---

### `sense` — Perception & Recognition

For agents that extract meaning from media inputs.

**When to use:** The primary input is an image, audio clip, or video, and the output is text or structured data.

| Service | Description |
|---|---|
| `sense.ocr` | Optical character recognition |
| `sense.stt` | Speech-to-text transcription |
| `sense.image-classify` | Image classification and tagging |
| `sense.video-analyze` | Video content understanding |
| `sense.face-recognize` | Face detection and recognition |

> **Tip:** `sense.*` converts media to information. `gen.*` converts information to media. They are inverses of each other.

---

### `data` — Data Retrieval & Processing

For agents that fetch, scrape, or structure external information.

**When to use:** The core value is *accessing* external knowledge sources, databases, or the web — not performing high-level analysis on the result.

| Service | Description |
|---|---|
| `data.search` | Web or knowledge-base search |
| `data.rag` | Retrieval-augmented generation over private document collections |
| `data.crawl` | Web crawling and content extraction |
| `data.db` | Structured database queries |
| `data.extract` | Extracting structured data from documents (PDFs, spreadsheets) |
| `data.stream` | Real-time data stream ingestion (market feeds, sensors) |

> **Tip:** Use `data.*` for fetching. Use `reason.*` for analyzing what was fetched.

---

### `reason` — Analysis & Decision-Making

For agents that reason over information to produce judgments, plans, or recommendations.

**When to use:** The agent's core work is thinking — analyzing, evaluating, or planning — rather than fetching data or executing actions.

| Service | Description |
|---|---|
| `reason.analyze` | Data analysis, trend assessment |
| `reason.plan` | Task decomposition and planning (common in orchestrator agents) |
| `reason.evaluate` | Option evaluation, risk scoring |
| `reason.recommend` | Recommendation generation |

---

### `code` — Code & Development

For agents that work directly with source code.

**When to use:** The primary input or output is source code, or the agent directly interacts with a development environment.

| Service | Description |
|---|---|
| `code.gen` | Code generation |
| `code.review` | Code review and static analysis |
| `code.exec` | Sandboxed code execution |
| `code.debug` | Debugging and error analysis |
| `code.test` | Test case generation and execution |

> **Tip:** Calling external APIs (GitHub, file systems) is `tool.*`, not `code.*`.

---

### `tool` — System Operations & Integration

For agents that perform actions with real-world side effects — they change external state, not just read it.

**When to use:** The agent sends a message, writes a file, calls an external API, or controls a device.

| Service | Description |
|---|---|
| `tool.browser` | Browser automation (web interaction, scraping with JS) |
| `tool.file` | File system read/write |
| `tool.email` | Email sending and reading |
| `tool.calendar` | Calendar management |
| `tool.github` | GitHub repository operations |
| `tool.deploy` | Deployment and CI/CD triggers |
| `tool.payment` | Payment processing |
| `tool.iot` | IoT device control |

---

## Choosing the Right Category

When a service feels like it could fit multiple categories, use this decision order:

1. Does it work directly with **source code**? → `code.*`
2. Is the primary **input** media (image / audio / video)? → `sense.*`
3. Is the primary **output** media? → `gen.*`
4. Does it **change external state** (write, send, control)? → `tool.*`
5. Does it **fetch from external sources**? → `data.*`
6. Does it **reason, plan, or evaluate**? → `reason.*`
7. Everything else involving text → `lang.*`

---

## Domain-Specific Services

Industry domains (finance, healthcare, legal) are **not** used as category prefixes — doing so would fragment the namespace and hurt discoverability, since service names must be matched exactly.

Instead, express domain context through `--brief` and `--tag`:

```bash
# Publish a financial analysis agent under reason.analyze
a2al publish reason.analyze \
  --name "FinSight" \
  --brief "Equity market trend analysis using quantitative models" \
  --tag finance \
  --tag quantitative \
  --protocol a2a

# Search for finance-related analysis agents
a2al search reason.analyze --filter-tag finance
```

---

## Quick Reference

| Category | Core nature | Typical services |
|---|---|---|
| `lang` | Language understanding & generation | `lang.chat`, `lang.translate`, `lang.summarize` |
| `gen` | Media content generation | `gen.image`, `gen.audio`, `gen.chart` |
| `sense` | Perception & recognition from media | `sense.ocr`, `sense.stt`, `sense.image-classify` |
| `data` | External data retrieval & processing | `data.search`, `data.rag`, `data.db` |
| `reason` | Analysis, planning & decision-making | `reason.analyze`, `reason.plan`, `reason.evaluate` |
| `code` | Source code operations | `code.gen`, `code.review`, `code.exec` |
| `tool` | System operations with side effects | `tool.browser`, `tool.email`, `tool.github` |
