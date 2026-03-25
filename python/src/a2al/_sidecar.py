from __future__ import annotations

import atexit
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Mapping, Optional


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _host, port = s.getsockname()
    s.close()
    return int(port)


class Daemon:
    """Runs a2ald with a temp data dir and dynamic API port.

    Usage (recommended — ensures cleanup on exit)::

        with Daemon() as d:
            c = Client(d.api_base, token=d.api_token)
            ...

    Alternatively call ``start()`` / ``close()`` explicitly, or rely on the
    ``atexit`` handler registered by ``start()`` as a fallback.

    Note: ``_free_port`` binds and releases a port before passing it to a2ald,
    so a brief race window exists. In practice this is benign for local loopback.
    """

    def __init__(
        self,
        a2ald_exe: Optional[str] = None,
        api_token: Optional[str] = None,
        extra_args: Optional[list[str]] = None,
    ) -> None:
        self._exe = a2ald_exe or os.environ.get("A2ALD_PATH") or "a2ald"
        self._api_token = api_token if api_token is not None else os.environ.get("A2AL_API_TOKEN")
        self._extra = extra_args or []
        self._proc: Optional[subprocess.Popen[bytes]] = None
        self._dd: Optional[str] = None
        self.api_base: Optional[str] = None

    @property
    def api_token(self) -> Optional[str]:
        return self._api_token

    def start(self, timeout: float = 45.0) -> None:
        if self._proc is not None:
            return
        self._dd = tempfile.mkdtemp(prefix="a2al-")
        port = _free_port()
        self.api_base = f"http://127.0.0.1:{port}"
        args = [
            self._exe,
            "--data-dir",
            self._dd,
            "--api-addr",
            f"127.0.0.1:{port}",
            *self._extra,
        ]
        env = os.environ.copy()
        if self._api_token:
            env["A2AL_API_TOKEN"] = self._api_token
        self._proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=env,
        )
        atexit.register(self.close)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError("a2ald exited during startup")
            try:
                urllib.request.urlopen(self.api_base + "/health", timeout=1.0)
                return
            except (urllib.error.URLError, OSError):
                time.sleep(0.15)
        raise TimeoutError("a2ald /health not ready")

    def close(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        if self._dd:
            shutil.rmtree(self._dd, ignore_errors=True)
            self._dd = None
        self.api_base = None

    def __enter__(self) -> Daemon:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class Client:
    """JSON REST client for a2ald (localhost)."""

    def __init__(self, base_url: str, token: Optional[str] = None) -> None:
        self.base = base_url.rstrip("/")
        self.token = token

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        timeout: float = 120.0,
    ) -> Any:
        data = None
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                if not raw:
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            body_bytes = exc.read()
            try:
                err_body = json.loads(body_bytes)
                msg = err_body.get("error") or str(err_body)
            except Exception:
                msg = body_bytes.decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"HTTP {exc.code}: {msg}") from exc

    def health(self) -> Any:
        return self._request("GET", "/health", None)

    def config_get(self) -> Any:
        return self._request("GET", "/config", None)

    def agents_list(self) -> Any:
        return self._request("GET", "/agents", None)

    def identity_generate(self) -> Any:
        return self._request("POST", "/identity/generate", {})

    def agent_register(self, payload: Mapping[str, Any]) -> Any:
        return self._request("POST", "/agents", dict(payload))

    def agent_publish(self, aid: str) -> Any:
        return self._request("POST", f"/agents/{aid}/publish", {})

    def resolve(self, aid: str) -> Any:
        return self._request("POST", f"/resolve/{aid}", {})

    def connect(self, aid: str, local_aid: str = "") -> Any:
        body: dict[str, str] = {}
        if local_aid:
            body["local_aid"] = local_aid
        return self._request("POST", f"/connect/{aid}", body)
