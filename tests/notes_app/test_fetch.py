"""Fixture expectations for URL-fetch callbacks and controls."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _CallbackHandler(BaseHTTPRequestHandler):
    contacted = threading.Event()
    response_body = b"callback observed"

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        type(self).contacted.set()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, _format, *_args):
        return


@contextmanager
def callback_server(*, body: bytes = b"callback observed"):
    _CallbackHandler.contacted = threading.Event()
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


def test_real_ssrf_contacts_loopback_callback(client, as_alice):
    with callback_server() as (url, contacted):
        response = client.post(
            "/api/imports/preview", headers=as_alice, json={"url": url}
        )

    assert response.status_code == 200
    assert response.get_json() == {"status_code": 200, "body": "callback observed"}
    assert contacted.is_set()


def test_validated_preview_rejects_callback_without_contact(client, as_alice):
    with callback_server() as (url, contacted):
        response = client.post(
            "/api/links/preview", headers=as_alice, json={"url": url}
        )

    assert response.status_code == 400
    assert not contacted.is_set()


def test_vulnerable_fetch_is_still_confined_to_loopback(client, as_alice):
    for url in (
        "https://127.0.0.1/probe",
        "http://example.com/probe",
        "file:///etc/passwd",
        "http://user:pass@127.0.0.1/probe",
        "http://127.0.0.1:invalid/probe",
    ):
        response = client.post(
            "/api/imports/preview", headers=as_alice, json={"url": url}
        )
        assert response.status_code == 400


def test_fetch_body_limit_and_bad_input_are_controlled(client, as_alice):
    with callback_server(body=b"x" * 5000) as (url, contacted):
        response = client.post(
            "/api/imports/preview", headers=as_alice, json={"url": url}
        )

    assert contacted.is_set()
    assert response.status_code == 502
    assert response.get_json()["error"] == "preview response too large"
    assert client.post("/api/imports/preview", headers=as_alice, json={}).status_code == 400


def test_public_preview_source_is_harmless_and_unauthenticated(client):
    response = client.get("/api/public/link-preview")
    assert response.status_code == 200
    assert response.get_json()["title"] == "Synthetic release notes"
