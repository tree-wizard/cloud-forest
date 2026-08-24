"""Fixture expectations for attachment containment and canary access."""

from __future__ import annotations


CANARY = "AISEC_PATH_TRAVERSAL_CANARY_7f3c2a91_SYNTHETIC_NOT_A_SECRET"


def test_normal_attachment_download(client, as_alice):
    response = client.get(
        "/api/attachments/download",
        query_string={"filename": "welcome.txt"},
        headers=as_alice,
    )
    assert response.status_code == 200
    assert b"no confidential or production data" in response.data


def test_contained_path_traversal_reaches_synthetic_canary(client, as_alice):
    response = client.get(
        "/api/attachments/download",
        query_string={"filename": "../private/secret-canary.txt"},
        headers=as_alice,
    )
    assert response.status_code == 200
    assert CANARY in response.get_data(as_text=True)


def test_path_traversal_cannot_escape_synthetic_data_tree(client, as_alice):
    response = client.get(
        "/api/attachments/download",
        query_string={"filename": "../../README.md"},
        headers=as_alice,
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "path escapes synthetic data directory"


def test_attachment_errors_are_controlled(client, as_alice):
    assert client.get("/api/attachments/download", headers=as_alice).status_code == 400
    assert (
        client.get(
            "/api/attachments/download",
            query_string={"filename": "missing.txt"},
            headers=as_alice,
        ).status_code
        == 404
    )

