from __future__ import annotations

import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


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
def as_alice():
    return {"X-User": "alice"}


@pytest.fixture
def as_bob():
    return {"X-User": "bob"}


class _CallbackHandler(BaseHTTPRequestHandler):
    contacted = threading.Event()
    paths = []
    response_body = b"callback observed"

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        type(self).contacted.set()
        type(self).paths.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, _format, *_args):
        return


@contextmanager
def callback_server(*, body: bytes = b"callback observed"):
    """Throwaway loopback listener standing in for phase 3's real one."""
    _CallbackHandler.contacted = threading.Event()
    _CallbackHandler.paths = []
    _CallbackHandler.response_body = body
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/probe", _CallbackHandler.contacted
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def callback_paths() -> list[str]:
    """Paths the throwaway listener saw, for building CallbackHits in tests."""
    return list(_CallbackHandler.paths)
