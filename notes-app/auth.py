"""Minimal deterministic identity handling for the scanner harness."""

from __future__ import annotations

from functools import wraps

from flask import g, jsonify, request

from database import get_note, get_user


def register_auth(app) -> None:
    @app.before_request
    def load_identity() -> None:
        identity = request.headers.get("X-User")
        g.current_user = get_user(identity) if identity else None


def _unauthorized():
    return jsonify(error="valid X-User identity required"), 401


def require_user(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.current_user is None:
            return _unauthorized()
        return view(*args, **kwargs)

    return wrapped


def require_note_owner(parameter: str = "note_id"):
    """Enforce note ownership outside the decorated route implementation."""

    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.current_user is None:
                return _unauthorized()

            note = get_note(kwargs[parameter])
            if note is None:
                return jsonify(error="note not found"), 404
            if note["owner_id"] != g.current_user["id"]:
                return jsonify(error="note belongs to another user"), 403

            g.authorized_note = note
            return view(*args, **kwargs)

        return wrapped

    return decorate
