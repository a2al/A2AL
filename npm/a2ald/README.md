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

## Documentation

- Repository & full docs: [github.com/a2al/a2al](https://github.com/a2al/a2al)
- User-facing guides live under the repo `doc/` directory.

## Official websites

- **A2AL** — [a2al.org](https://a2al.org) — project site and documentation hub
- **Tangled Network** — [tanglednet.com](https://tanglednet.com) · short link [tngld.net](https://tngld.net)

## License

[MPL-2.0](https://www.mozilla.org/MPL/2.0/)
