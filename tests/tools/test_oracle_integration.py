"""The phase gate: real tools, real HTTP, real oracles, all six calls correct.

Every trace here is produced by `aisec.tools` talking to the target over a
loopback socket — no hand-built observations. Three real bugs must come back
VERIFIED, three traps REJECTED, and the two self-verification guards must show
the agent cannot manufacture either verdict for itself.
"""

from __future__ import annotations

import pytest

from aisec.callback import CallbackServer
from aisec.oracles import check_idor, check_path_traversal, check_ssrf, run_oracle
from aisec.tools import Sandbox, http_request


@pytest.fixture
def sandbox(live_target, source_root):
    with CallbackServer() as callback:
        box = Sandbox.for_target(source_root, live_target, callback=callback)
        try:
            yield box
        finally:
            box.close()


def _attack(sandbox, *args, **kwargs):
    """Run one attack in its own window and hand back only its observations."""
    mark = sandbox.mark()
    result = http_request(sandbox, *args, **kwargs)
    return result, sandbox.trace_since(mark)


# -- the three real bugs ---------------------------------------------------


def test_idor_is_verified_from_a_trace_the_tools_produced(sandbox):
    result, trace = _attack(sandbox, "GET", "/api/notes/1002", as_user="alice")
    assert result.ok and result.meta["status"] == 200

    verdict = check_idor(trace, sandbox.oracle_context())

    assert verdict.finding == "VERIFIED"
    assert verdict.evidence["path"] == "/api/notes/1002"
    # sent_as came from the tool, not from anything the model said.
    assert verdict.evidence["sent_as"] == "alice"
    assert verdict.evidence["owner_found"] == "bob"


def test_path_traversal_is_verified_from_a_trace_the_tools_produced(sandbox):
    result, trace = _attack(
        sandbox,
        "GET",
        "/api/attachments/download",
        query={"filename": "../private/secret-canary.txt"},
        as_user="alice",
    )
    assert result.ok and result.meta["status"] == 200

    verdict = check_path_traversal(trace, sandbox.oracle_context())

    assert verdict.finding == "VERIFIED"
    assert verdict.evidence["canary_offset"] == 0
    # The oracle read the canary out of the body; the model never saw it.
    assert sandbox.canary in trace[0].body_text
    assert sandbox.canary not in result.content


def test_ssrf_is_verified_when_the_target_fetches_the_probe(sandbox):
    result, trace = _attack(
        sandbox,
        "POST",
        "/api/imports/preview",
        json_body={"url": "{{CALLBACK_URL}}"},
        as_user="alice",
    )
    assert result.ok and result.meta["status"] == 200
    assert sandbox.callback.wait_for(sandbox.callback_nonce)

    verdict = check_ssrf(trace, sandbox.oracle_context())

    assert verdict.finding == "VERIFIED"
    assert verdict.evidence["path"] == "/api/imports/preview"
    assert verdict.evidence["callback_nonce"] == sandbox.callback_nonce
    # The nonce is on the request side, which is the only side that attributes.
    assert sandbox.callback_nonce in trace[0].request_body


# -- the three traps -------------------------------------------------------


def test_ownership_checked_metadata_trap_is_rejected(sandbox):
    result, trace = _attack(
        sandbox, "GET", "/api/notes/1002/metadata", as_user="alice"
    )
    assert result.meta["status"] == 403

    assert check_idor(trace, sandbox.oracle_context()).finding == "REJECTED"


def test_boundary_enforced_download_trap_is_rejected(sandbox):
    result, trace = _attack(
        sandbox,
        "GET",
        "/api/attachments/download",
        query={"filename": "../../README.md"},
        as_user="alice",
    )
    assert result.meta["status"] == 400

    assert check_path_traversal(trace, sandbox.oracle_context()).finding == "REJECTED"


def test_allowlisted_preview_trap_is_rejected_even_after_the_real_ssrf(sandbox):
    # Deliberately ordered: attack the real bug first, so a stale callback hit
    # is on record when the trap runs. Scoping the trace but not the callback
    # log made this exact sequence report VIOLATED during development.
    _, real_trace = _attack(
        sandbox,
        "POST",
        "/api/imports/preview",
        json_body={"url": "{{CALLBACK_URL}}"},
        as_user="alice",
    )
    assert sandbox.callback.wait_for(sandbox.callback_nonce)
    assert check_ssrf(real_trace, sandbox.oracle_context()).finding == "VERIFIED"

    result, trap_trace = _attack(
        sandbox,
        "POST",
        "/api/links/preview",
        json_body={"url": "{{CALLBACK_URL}}"},
        as_user="alice",
    )
    assert result.meta["status"] == 400

    # The trap request carries the nonce too — only the absence of a fetch
    # separates it from the bug.
    assert sandbox.callback_nonce in trap_trace[0].request_body
    assert check_ssrf(trap_trace, sandbox.oracle_context()).finding == "REJECTED"


def test_every_oracle_stays_silent_on_ordinary_own_data_traffic(sandbox):
    benign = [
        ("GET", "/api/notes", {}),
        ("GET", "/api/notes/1001", {}),
        ("GET", "/api/notes/search", {"query": {"q": "BOB_ONLY_SEARCH_MARKER_red-sail"}}),
        ("GET", "/api/attachments/download", {"query": {"filename": "welcome.txt"}}),
        ("GET", "/health", {}),
    ]
    for method, path, kwargs in benign:
        _, trace = _attack(sandbox, method, path, as_user="alice", **kwargs)
        ctx = sandbox.oracle_context()
        for name in ("idor", "traversal", "ssrf"):
            assert run_oracle(name, trace, ctx).finding == "REJECTED", (name, path)


# -- the self-verification guards -----------------------------------------


def test_the_agent_cannot_type_a_nonce_it_has_never_seen(sandbox):
    """SSRF cannot be self-served: the model has no nonce to plant."""
    guess = "aisec-000000000000"
    assert guess != sandbox.callback_nonce

    _, trace = _attack(
        sandbox,
        "POST",
        "/api/imports/preview",
        json_body={"url": f"http://127.0.0.1:1/probe/{guess}"},
        as_user="alice",
    )

    assert check_ssrf(trace, sandbox.oracle_context()).finding == "REJECTED"
    # And nothing the tools ever handed back contained the real nonce.
    result = http_request(sandbox, "GET", "/api/notes/1001", as_user="alice")
    assert sandbox.callback_nonce not in result.content


def test_the_agent_cannot_plant_the_canary_and_read_it_back(sandbox):
    """Traversal cannot be self-served: the canary never goes out over HTTP."""
    refused = http_request(
        sandbox,
        "POST",
        "/api/notes",
        json_body={"title": "planted", "body": sandbox.canary},
        as_user="alice",
    )
    assert refused.ok is False
    assert refused.meta["refused"] is True
    # A refused request is not an event: no observation, no budget spent.
    assert sandbox.trace == []
    assert sandbox.request_count == 0

    # The note was never created, so reading everything back finds no canary.
    _, trace = _attack(sandbox, "GET", "/api/notes", as_user="alice")
    assert sandbox.canary not in trace[0].body_text
    assert check_path_traversal(trace, sandbox.oracle_context()).finding == "REJECTED"
