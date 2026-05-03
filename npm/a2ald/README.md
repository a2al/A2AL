# a2ald

npm distribution of the **A2AL daemon** (`a2ald`): decentralized agent networking for AI agents.

The main package pulls in the correct **platform binary** via optional dependencies (`@a2al/a2ald-*`). Install once; the right binary is selected for Linux, macOS, or Windows (x64/arm64 where applicable).

## Install

```bash
npm install a2ald
```

## Programmatic use

```js
const { getBinaryPath } = require("a2ald");
const bin = getBinaryPath();
// spawn or exec `bin` as your process needs
```

## CLI

After install, the `a2ald` binary is available where npm links local binaries (e.g. `npx a2ald` or your `node_modules/.bin`).

```bash
npx a2ald --help
```

## What a2ald provides

Once running, the daemon exposes a local REST API on `http://127.0.0.1:2121`. Key endpoints:

| Endpoint | Description |
|----------|-------------|
| `POST /fetch/{aid}` | Send an HTTP request to a remote agent over encrypted QUIC; daemon handles transport internally |
| `POST /connect/{aid}` | One-shot tunnel: returns a local TCP address for a single session |
| `POST /tunnel/{aid}` | Persistent multiplexed tunnel: multiple concurrent TCP connections over one QUIC pool |
| `POST /resolve/{aid}` | Look up a remote agent's current endpoints |

A built-in MCP server exposes all capabilities as tools for AI agents. Full API reference: [doc/api-reference.md](https://github.com/a2al/a2al/blob/main/doc/api-reference.md)

For CLI usage outside Node, see the `a2al` tool in the same repository (`a2al get`, `a2al post`, `a2al tunnel` commands).

## Official websites

- [a2al.org](https://a2al.org) - project site and documentation
- [tanglednet.org](https://tanglednet.org) / [tngld.net](https://tngld.net) - Tangled Network

## License

[MPL-2.0](https://www.mozilla.org/MPL/2.0/)
