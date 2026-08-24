"""URL-preview routes."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx
from flask import Blueprint, current_app, jsonify, request

from auth import require_user


fetch_bp = Blueprint("fetch", __name__, url_prefix="/api")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _payload_url() -> tuple[str | None, tuple | None]:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
        return None, (jsonify(error="JSON string field 'url' is required"), 400)
    return payload["url"], None


def _parse_http_url(url: str):
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return parsed


def _fetch(url: str):
    limit = current_app.config["FETCH_BODY_LIMIT"]
    timeout = current_app.config["FETCH_TIMEOUT_SECONDS"]
    try:
        with httpx.stream(
            "GET", url, timeout=timeout, follow_redirects=False
        ) as response:
            chunks = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > limit:
                    return None, (jsonify(error="preview response too large"), 502)
                chunks.append(chunk)
            body = b"".join(chunks).decode("utf-8", errors="replace")
            return {
                "status_code": response.status_code,
                "body": body,
            }, None
    except httpx.HTTPError:
        return None, (jsonify(error="preview request failed"), 502)


@fetch_bp.post("/imports/preview")
@require_user
def import_preview():
    url, error = _payload_url()
    if error:
        return error

    parsed = _parse_http_url(url)
    if parsed is None or parsed.hostname not in LOOPBACK_HOSTS:
        return jsonify(error="only loopback HTTP targets are enabled"), 400

    result, error = _fetch(url)
    if error:
        return error
    return jsonify(result)


@fetch_bp.post("/links/preview")
@require_user
def link_preview():
    url, error = _payload_url()
    if error:
        return error

    # Link previews only support the app-owned source, with redirects disabled.
    if _parse_http_url(url) is None or url != current_app.config["SAFE_PREVIEW_URL"]:
        return jsonify(error="URL is not in the preview allowlist"), 400

    result, error = _fetch(url)
    if error:
        return error
    return jsonify(result)


@fetch_bp.get("/public/link-preview")
def public_preview_source():
    return jsonify(
        title="Synthetic release notes",
        description="This is a harmless app-owned preview fixture.",
    )
