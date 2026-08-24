"""The listener: an out-of-band fact that drops straight into an OracleContext."""

from __future__ import annotations

import httpx

from aisec.callback import CallbackServer, mint_nonce, nonce_from_path
from aisec.oracles import CallbackHit, OracleContext, check_ssrf


def test_nonces_are_unguessable_and_distinct():
    nonces = {mint_nonce() for _ in range(200)}

    assert len(nonces) == 200
    assert all(n.startswith("aisec-") and len(n) > 12 for n in nonces)


def test_it_binds_an_ephemeral_loopback_port():
    with CallbackServer() as server:
        assert server.host == "127.0.0.1"
        assert server.port > 0
        assert server.base_url == f"http://127.0.0.1:{server.port}"
        assert server.url_for("aisec-abc").endswith("/probe/aisec-abc")


def test_a_hit_records_the_nonce_from_the_last_path_segment():
    nonce = mint_nonce()
    with CallbackServer() as server:
        httpx.get(server.url_for(nonce), timeout=2.0)

        assert server.wait_for(nonce)
        (hit,) = server.hits()
        assert isinstance(hit, CallbackHit)
        assert hit.nonce == nonce
        assert hit.path == f"/probe/{nonce}"
        assert hit.received_at > 0
        assert server.contacted.is_set()


def test_the_query_string_is_stripped_before_the_nonce_is_read():
    assert nonce_from_path("/probe/aisec-abc?x=1") == "aisec-abc"
    assert nonce_from_path("/probe/aisec-abc/") == "aisec-abc"
    assert nonce_from_path("/aisec-abc") == "aisec-abc"

    nonce = mint_nonce()
    with CallbackServer() as server:
        httpx.get(f"{server.url_for(nonce)}?redirected=1", timeout=2.0)

        assert server.wait_for(nonce)
        assert server.hits()[0].nonce == nonce


def test_hits_drop_straight_into_an_oracle_context():
    nonce = mint_nonce()
    with CallbackServer() as server:
        httpx.get(server.url_for(nonce), timeout=2.0)
        server.wait_for(nonce)

        ctx = OracleContext(callback_hits=server.hits(), callback_nonce=nonce)

    # No reshaping between the listener and the trust boundary. (The trace is
    # empty here, so the oracle correctly refuses to attribute the hit.)
    assert check_ssrf([], ctx).violated is False


def test_wait_for_is_true_on_a_hit_and_false_on_a_timeout():
    nonce = mint_nonce()
    with CallbackServer() as server:
        assert server.wait_for(nonce, timeout=0.1) is False

        httpx.get(server.url_for(nonce), timeout=2.0)

        assert server.wait_for(nonce, timeout=2.0) is True
        assert server.wait_for(mint_nonce(), timeout=0.1) is False


def test_head_and_post_probes_are_recorded_too():
    with CallbackServer() as server:
        for method in ("HEAD", "POST"):
            nonce = mint_nonce()
            httpx.request(method, server.url_for(nonce), timeout=2.0)
            assert server.wait_for(nonce), method


def test_reset_clears_the_record_without_restarting_the_server():
    nonce = mint_nonce()
    with CallbackServer() as server:
        port = server.port
        httpx.get(server.url_for(nonce), timeout=2.0)
        server.wait_for(nonce)

        server.reset()

        assert server.hits() == ()
        assert not server.contacted.is_set()
        assert server.port == port
        httpx.get(server.url_for(nonce), timeout=2.0)
        assert server.wait_for(nonce)


def test_the_reply_stays_under_the_targets_preview_body_cap():
    # The target caps preview bodies at 4096 bytes and 502s past it. A chatty
    # listener would turn every SSRF into "preview response too large".
    with CallbackServer() as server:
        response = httpx.get(server.url_for(mint_nonce()), timeout=2.0)

        assert response.status_code == 200
        assert len(response.content) < 4096
        assert response.headers["Content-Length"] == str(len(response.content))


def test_addressing_a_stopped_server_raises_rather_than_lying():
    server = CallbackServer().start()
    server.stop()

    for call in (lambda: server.port, server.hits, lambda: server.url_for("x")):
        try:
            call()
        except RuntimeError:
            continue
        raise AssertionError("expected a stopped server to refuse")
