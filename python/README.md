# a2al (Python)

Python sidecar: run a local `a2ald` child process and call its REST API.

- **Binary**: `a2ald` must be on `PATH`, or set the `A2ALD_PATH` environment variable to the executable’s absolute path.
- **Distribution**: This package does not yet ship prebuilt `a2ald` binaries inside wheels. For local development, build with `go build -o a2ald ./cmd/a2ald` (use `a2ald.exe` on Windows) and ensure the binary is on `PATH`.

```python
from a2al import Daemon, Client

with Daemon() as d:
    c = Client(d.api_base, token=d.api_token)
    print(c.health())
```

Optional environment variable: `A2AL_API_TOKEN` — pass the same value as `api_token` in `config.toml` to `Client` when the daemon enforces bearer auth.
