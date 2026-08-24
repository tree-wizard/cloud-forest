from __future__ import annotations

import sys
from pathlib import Path

import pytest


APP_ROOT = Path(__file__).resolve().parents[2] / "notes-app"
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
