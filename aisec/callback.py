"""The out-of-band listener that turns "the target fetched something" into a fact.

An SSRF verdict cannot be read off a response body: a target that refuses to
fetch and a target that fetches and hides the result can look identical from the
outside. So the signal comes from a second channel — a loopback HTTP server the
agent hands to the *target* by URL, and which records what actually arrived.

Two properties the oracle depends on:

* Every probe URL carries a nonce minted here. `hits()` returns
  `oracles.CallbackHit` objects directly, so a hit drops into `OracleContext`
  with no reshaping in between.
* The nonce is never shown to the model (see `tools.CALLBACK_TOKEN`). A model
  that has never seen a nonce cannot type one into a request, which is what
  makes `check_ssrf`'s attribution clause structurally true rather than
  conventionally true.
"""

from __future__ import annotations

import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aisec.oracles import CallbackHit


DEFAULT_BODY = b"callback observed"
PROBE_PREFIX = "/probe"


def mint_nonce() -> str:
    """A fresh, unguessable token to attribute one callback hit to one scan."""
    return f"aisec-{secrets.token_hex(6)}"


def nonce_from_path(path: str) -> str:
    """The last path segment, query stripped — the convention `url_for` writes."""
    return path.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]


class _Handler(BaseHTTPRequestHandler):
    """Records the request, answers 200, and never raises into the server loop."""

    server_version = "aisec-callback/1.0"

    def _record(self, *, write_body: bool) -> None:
        try:
            self.server.record(self.path)  # type: ignore[attr-defined]
            body = self.server.response_body  # type: ignore[attr-defined]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if write_body:
                self.wfile.write(body)
        except Exception:  # noqa: BLE001 - a hostile probe must not kill the listener
            return

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        self._record(write_body=True)

    def do_HEAD(self):  # noqa: N802 - BaseHTTPRequestHandler API
        self._record(write_body=False)

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        self._record(write_body=True)

    def log_message(self, _format, *_args):
        return


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, *, response_body: bytes):
        super().__init__(address, handler)
        self.response_body = response_body
        self._lock = threading.Lock()
        self._hits: list[CallbackHit] = []
        self.contacted = threading.Event()

    def record(self, path: str) -> None:
        hit = CallbackHit(
            path=path, nonce=nonce_from_path(path), received_at=time.time()
        )
        with self._lock:
            self._hits.append(hit)
        self.contacted.set()

    def snapshot(self) -> tuple[CallbackHit, ...]:
        with self._lock:
            return tuple(self._hits)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()
        self.contacted.clear()


class CallbackServer:
    """A loopback listener the target can reach and the agent cannot.

    `response_body` stays configurable because the target caps preview bodies at
    4096 bytes, and `tests/notes_app/test_fetch.py` exercises that cap by asking
    for an oversized reply.
    """

    def __init__(self, *, host: str = "127.0.0.1", response_body: bytes = DEFAULT_BODY):
        self.host = host
        self.response_body = response_body
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> CallbackServer:
        if self._server is not None:
            return self
        # Port 0: the OS picks a free ephemeral port, so parallel scans and test
        # runs never collide on a hardcoded one.
        self._server = _Server(
            (self.host, 0), _Handler, response_body=self.response_body
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="aisec-callback"
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        server, thread = self._server, self._thread
        self._server, self._thread = None, None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=2)

    def __enter__(self) -> CallbackServer:
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    # -- addressing --------------------------------------------------------

    def _live(self) -> _Server:
        if self._server is None:
            raise RuntimeError("callback server is not running")
        return self._server

    @property
    def port(self) -> int:
        return self._live().server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def url_for(self, nonce: str) -> str:
        """The probe URL to hand the target for this nonce."""
        return f"{self.base_url}{PROBE_PREFIX}/{nonce}"

    # -- observations ------------------------------------------------------

    @property
    def contacted(self) -> threading.Event:
        return self._live().contacted

    def hits(self) -> tuple[CallbackHit, ...]:
        """Everything recorded so far, ready to drop into an OracleContext."""
        return self._live().snapshot()

    def hits_for(self, nonce: str) -> tuple[CallbackHit, ...]:
        return tuple(hit for hit in self.hits() if hit.nonce == nonce)

    def wait_for(self, nonce: str, timeout: float = 2.0) -> bool:
        """Block until a hit carries `nonce`, or the timeout expires.

        The target fetches on its own thread, so a scan that read `hits()` the
        instant the response returned would race it.
        """
        deadline = time.monotonic() + timeout
        while True:
            if self.hits_for(nonce):
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))

    def reset(self) -> None:
        self._live().clear()
