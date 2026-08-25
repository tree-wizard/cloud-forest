"""Application factory for the deliberately vulnerable notes test fixture."""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify

from auth import register_auth
from database import close_db, init_db
from routes.attachments import attachments_bp
from routes.fetch import fetch_bp
from routes.notes import notes_bp


APP_ROOT = Path(__file__).resolve().parent


def create_app(test_config: dict | None = None) -> Flask:
    """Create an app with deterministic seed state unless explicitly disabled."""

    port = int(os.environ.get("NOTES_APP_PORT", "5001"))
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=str(APP_ROOT / "instance" / "notes.sqlite3"),
        DATA_ROOT=str(APP_ROOT / "data"),
        RESET_DATABASE=True,
        FETCH_TIMEOUT_SECONDS=2.0,
        FETCH_BODY_LIMIT=4096,
        SAFE_PREVIEW_URL=f"http://127.0.0.1:{port}/api/public/link-preview",
    )
    if test_config:
        app.config.update(test_config)

    register_auth(app)
    app.teardown_appcontext(close_db)
    app.register_blueprint(notes_bp)
    app.register_blueprint(attachments_bp)
    app.register_blueprint(fetch_bp)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    with app.app_context():
        init_db(reset=app.config["RESET_DATABASE"])

    return app
