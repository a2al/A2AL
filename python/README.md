# a2al (Python)

Python client for [a2al](https://github.com/a2al/a2al): spawns a local `a2ald` daemon and exposes a typed REST client for its API.

## Installation

```sh
pip install a2al
```

Pre-built `a2ald` binaries are bundled inside platform wheels for:

| Platform | Architecture |
|----------|-------------|
| Linux    | x86_64, arm64 |
| macOS    | x86_64, arm64 |
| Windows  | x86_64 |

On unsupported platforms, install `a2ald` manually and ensure it is on `PATH`, or set `A2ALD_PATH` to the executable path.

## Usage

```python
from a2al import Daemon, Client

with Daemon() as d:
    c = Client(d.api_base, token=d.api_token)
    print(c.health())
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `A2ALD_PATH` | Override path to the `a2ald` executable |
| `A2AL_API_TOKEN` | Bearer token when the daemon enforces auth |

## Requirements

- Python 3.10+
- No third-party dependencies (standard library only)
