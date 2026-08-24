from __future__ import annotations

import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from aisec.callback import PROBE_PREFIX, CallbackServer


APP_ROOT = Path(__file__).resolve().parents[1] / "notes-app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from app import create_app  # noqa: E402


@pytest.fixture
def app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "notes.sqlite3"),
            "DATA_ROOT": str(APP_ROOT / "data"),
            "RESET_DATABASE": True,
            "SAFE_PREVIEW_URL": "http://127.0.0.1:5000/api/public/link-preview",
            "FETCH_TIMEOUT_SECONDS": 1.0,
        }
    )


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def live_target(tmp_path):
    """The target on a real loopback socket, because pinning needs real HTTP.

    A Flask test client would let `http_request`'s host controls pass
    vacuously — there is no host to get wrong. `threaded=True` is load-bearing
    rather than cosmetic: `/api/links/preview` fetches the target itself, and a
    single-threaded WSGI server deadlocks serving its own sub-request. Phase 2
    never hit this because the trap 400s before it fetches.
    """
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "notes.sqlite3"),
            "DATA_ROOT": str(APP_ROOT / "data"),
            "RESET_DATABASE": True,
            "FETCH_TIMEOUT_SECONDS": 1.0,
        }
    )
    server = make_server("127.0.0.1", 0, app, threaded=True)
    base_url = f"http://127.0.0.1:{server.server_port}"
    # Config is read per request, so setting it before the thread starts is
    # enough — no monkeypatching needed.
    app.config["SAFE_PREVIEW_URL"] = f"{base_url}/api/public/link-preview"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def as_alice():
    return {"X-User": "alice"}


@pytest.fixture
def as_bob():
    return {"X-User": "bob"}


_last_callback: CallbackServer | None = None
_last_paths: list[str] = []


@contextmanager
def callback_server(*, body: bytes = b"callback observed"):
    """Loopback listener for tests — now the real `aisec.callback` one.

    The signature is unchanged from the phase-2 stand-in on purpose: the
    existing oracle and target tests are untouched, and become the real
    server's first proof.
    """
    global _last_callback, _last_paths
    server = CallbackServer(response_body=body)
    _last_callback, _last_paths = server, []
    with server:
        try:
            yield f"{server.base_url}{PROBE_PREFIX}", server.contacted
        finally:
            # Snapshot before shutdown so callers may read paths either inside
            # or after the block.
            _last_paths = [hit.path for hit in server.hits()]
    _last_callback = None


def callback_paths() -> list[str]:
    """Paths the listener saw, for building CallbackHits in tests."""
    if _last_callback is not None:
        return [hit.path for hit in _last_callback.hits()]
    return list(_last_paths)
