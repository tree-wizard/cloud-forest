"""Fixture expectations for URL-fetch callbacks and controls."""

from __future__ import annotations

from conftest import callback_server


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
