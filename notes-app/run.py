#!/usr/bin/env python3
"""Run the notes fixture on loopback only."""

from __future__ import annotations

import os

from app import create_app


def main() -> None:
    port = int(os.environ.get("NOTES_APP_PORT", "5000"))
    app = create_app()
    app.run(
        host="127.0.0.1",
        port=port,
        debug=False,
        threaded=True,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
