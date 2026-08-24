"""Synthetic attachment downloads."""

from __future__ import annotations

from pathlib import Path

from flask import Blueprint, Response, current_app, jsonify, request

from auth import require_user


attachments_bp = Blueprint("attachments", __name__, url_prefix="/api/attachments")


@attachments_bp.get("/download")
@require_user
def download():
    filename = request.args.get("filename")
    if not filename:
        return jsonify(error="filename is required"), 400

    data_root = Path(current_app.config["DATA_ROOT"]).resolve()
    attachments_root = data_root / "attachments"
    candidate = (attachments_root / filename).resolve()

    # Files outside the synthetic fixture tree must never be readable.
    try:
        candidate.relative_to(data_root)
    except ValueError:
        return jsonify(error="path escapes synthetic data directory"), 400

    if not candidate.is_file():
        return jsonify(error="attachment not found"), 404

    return Response(candidate.read_bytes(), mimetype="text/plain")
