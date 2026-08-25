"""The SSRF oracle fires only when a nonce reaches the listener via the target."""

from __future__ import annotations

import json

import pytest

from conftest import callback_paths, callback_server

from aisec.oracles import CallbackHit, HttpObservation, OracleContext, check_ssrf


NONCE = "aisec-nonce-4f19c2"


def _preview(client, headers, path, url):
    body = json.dumps({"url": url})
    response = client.post(path, headers=headers, json={"url": url})
    # `request_body` carries the sent payload, the way the tool layer records it.
    return HttpObservation.from_flask(
        response, sent_as="alice", method="POST", path=path, request_body=body
    )


def _hits() -> list[CallbackHit]:
    return [
        CallbackHit(path=path, nonce=path.rsplit("/", 1)[-1])
        for path in callback_paths()
    ]


def test_oracle_fires_when_the_target_fetches_the_nonced_callback(client, as_alice):
    with callback_server() as (base, contacted):
        observation = _preview(
            client, as_alice, "/api/imports/preview", f"{base}/{NONCE}"
        )
        assert contacted.is_set()
        hits = _hits()

    ctx = OracleContext(callback_hits=hits, callback_nonce=NONCE)
    verdict = check_ssrf([observation], ctx)

    assert verdict.violated is True
    assert verdict.finding == "VERIFIED"
    assert verdict.evidence["path"] == "/api/imports/preview"
    assert verdict.evidence["callback_nonce"] == NONCE
    assert verdict.evidence["callback_path"].endswith(NONCE)


def test_oracle_stays_silent_on_the_allowlisted_preview_trap(client, as_alice):
    with callback_server() as (base, contacted):
        observation = _preview(
            client, as_alice, "/api/links/preview", f"{base}/{NONCE}"
        )
        assert observation.status == 400
        assert not contacted.is_set()
        hits = _hits()

    ctx = OracleContext(callback_hits=hits, callback_nonce=NONCE)
    assert check_ssrf([observation], ctx).violated is False


def test_oracle_stays_silent_when_the_hit_is_not_attributable_to_the_target():
    # The agent contacting its own listener must never read as SSRF.
    ctx = OracleContext(
        callback_hits=[CallbackHit(path=f"/probe/{NONCE}", nonce=NONCE)],
        callback_nonce=NONCE,
    )
    assert check_ssrf([], ctx).violated is False

    unrelated = HttpObservation(
        method="GET",
        url="/api/notes",
        path="/api/notes",
        sent_as="alice",
        status=200,
        json={"notes": []},
    )
    assert check_ssrf([unrelated], ctx).violated is False


def test_oracle_stays_silent_when_no_hit_carries_the_nonce():
    sent = HttpObservation(
        method="POST",
        url="/api/imports/preview",
        path="/api/imports/preview",
        sent_as="alice",
        status=502,
        request_body=json.dumps({"url": f"http://127.0.0.1:9/probe/{NONCE}"}),
    )
    for hits in ([], [CallbackHit(path="/probe/other", nonce="other")]):
        ctx = OracleContext(callback_hits=hits, callback_nonce=NONCE)
        assert check_ssrf([sent], ctx).violated is False


def test_oracle_stays_silent_when_the_nonce_only_appears_in_a_response_body():
    # Attribution reads the request side only. A target that echoes the nonce
    # back has not been made to fetch anything, so the echo must not stand in
    # for a target-directed request.
    echoed = HttpObservation(
        method="GET",
        url="/api/notes/1001",
        path="/api/notes/1001",
        sent_as="alice",
        status=200,
        request_body="",
        body_text=f'{{"body": "{NONCE}"}}',
        json={"body": NONCE},
    )
    ctx = OracleContext(
        callback_hits=[CallbackHit(path=f"/probe/{NONCE}", nonce=NONCE)],
        callback_nonce=NONCE,
    )

    assert check_ssrf([echoed], ctx).violated is False


def test_oracle_refuses_to_run_without_a_nonce():
    for nonce in ("", "   "):
        with pytest.raises(ValueError):
            check_ssrf([], OracleContext(callback_nonce=nonce))


# -- which request the hit is attributed to --------------------------------
#
# The verdict never turns on this: a hit plus any target-directed request
# carrying the nonce is a violation. The *evidence* does, and the evidence is
# what a generated regression test replays and what the eval harness scopes a
# finding by. This section exists because a real scan got it wrong.


def _attempt(status, url, *, started_at, path="/api/imports/preview"):
    return HttpObservation(
        method="POST",
        url=path,
        path=path,
        sent_as="alice",
        status=status,
        request_body=json.dumps({"url": url}),
        started_at=started_at,
    )


def test_evidence_names_the_request_that_worked_not_the_first_one_tried():
    """The ordering that broke a live run: a rejected attack, then a working one."""
    probe = f"http://127.0.0.1:9/probe/{NONCE}"
    rejected = _attempt(400, f"http://localhost@{probe}", started_at=100.0)
    fetched = _attempt(200, probe, started_at=101.0, path="/api/imports/preview")
    hit = CallbackHit(path=f"/probe/{NONCE}", nonce=NONCE, received_at=101.5)

    verdict = check_ssrf(
        [rejected, fetched], OracleContext(callback_hits=[hit], callback_nonce=NONCE)
    )

    assert verdict.violated is True
    assert verdict.evidence["status"] == 200
    assert "localhost@" not in verdict.evidence["request_body"]


def test_a_request_sent_after_the_hit_cannot_be_the_cause():
    probe = f"http://127.0.0.1:9/probe/{NONCE}"
    caused = _attempt(200, probe, started_at=100.0)
    later = _attempt(200, probe, started_at=200.0)
    hit = CallbackHit(path=f"/probe/{NONCE}", nonce=NONCE, received_at=100.5)

    verdict = check_ssrf(
        [caused, later], OracleContext(callback_hits=[hit], callback_nonce=NONCE)
    )

    assert verdict.violated is True
    assert verdict.evidence["request_body"] == caused.request_body


def test_a_fetch_behind_an_error_status_still_supplies_the_evidence():
    """Some targets fetch and then fail. Non-2xx is a fallback, not a filter."""
    probe = f"http://127.0.0.1:9/probe/{NONCE}"
    errored = _attempt(502, probe, started_at=100.0)
    hit = CallbackHit(path=f"/probe/{NONCE}", nonce=NONCE, received_at=100.5)

    verdict = check_ssrf(
        [errored], OracleContext(callback_hits=[hit], callback_nonce=NONCE)
    )

    assert verdict.violated is True
    assert verdict.evidence["status"] == 502


def test_observations_without_timestamps_still_attribute():
    """Old traces and Flask-built observations have no clock; order still works."""
    probe = f"http://127.0.0.1:9/probe/{NONCE}"
    rejected = _attempt(400, probe, started_at=0.0)
    fetched = _attempt(200, probe, started_at=0.0)
    hit = CallbackHit(path=f"/probe/{NONCE}", nonce=NONCE, received_at=0.0)

    verdict = check_ssrf(
        [rejected, fetched], OracleContext(callback_hits=[hit], callback_nonce=NONCE)
    )

    assert verdict.evidence["status"] == 200
