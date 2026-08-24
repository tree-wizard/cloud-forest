"""Structural guards on the tool surface, mirroring tests/oracles/test_contract.py.

The oracle contract test proves no oracle can accept model-authored text. This
one proves the other half: nothing the model can *say* through a tool is shaped
like a verdict, and no tool exists that would let it run one.
"""

from __future__ import annotations

import json

import pytest

from aisec.oracles import ORACLES, Verdict
from aisec.tools import (
    TOOL_NAMES,
    TOOL_SCHEMAS,
    Hypothesis,
    Sandbox,
    dispatch,
    submit_hypothesis,
)


# A field the model fills in that the harness then trusts is the failure mode
# this whole design exists to prevent. `rationale` is deliberately absent from
# the list: model prose is fine as long as it cannot reach an oracle.
VERDICT_SHAPED = {
    "confidence",
    "severity",
    "verdict",
    "exploitable",
    "validated",
    "proven",
    "is_vulnerable",
}


@pytest.fixture
def sandbox(source_root):
    box = Sandbox.for_target(source_root, "http://127.0.0.1:1")
    try:
        yield box
    finally:
        box.close()


def _property_names(node) -> set[str]:
    names = set()
    if isinstance(node, dict):
        names |= set(node.get("properties", {}))
        for value in node.values():
            names |= _property_names(value)
    elif isinstance(node, list):
        for item in node:
            names |= _property_names(item)
    return names


def test_the_agent_gets_exactly_four_tools():
    assert TOOL_NAMES == (
        "read_file",
        "search_code",
        "http_request",
        "submit_hypothesis",
    )
    # No run_oracle, no check_callback, no list_findings. The model can propose
    # and attack; it cannot invoke or inspect the trust boundary.
    assert len(TOOL_SCHEMAS) == 4


def test_no_tool_exposes_a_verdict_shaped_field():
    for schema in TOOL_SCHEMAS:
        offenders = _property_names(schema["input_schema"]) & VERDICT_SHAPED
        assert not offenders, (schema["name"], offenders)


def test_the_hypothesis_record_carries_no_verdict_shaped_field():
    assert not set(Hypothesis.__dataclass_fields__) & VERDICT_SHAPED


def test_hypothesis_classes_are_generated_from_the_oracle_registry():
    schema = next(s for s in TOOL_SCHEMAS if s["name"] == "submit_hypothesis")

    assert schema["input_schema"]["properties"]["vuln_class"]["enum"] == sorted(ORACLES)


def test_http_request_cannot_be_told_a_host_or_a_header():
    schema = next(s for s in TOOL_SCHEMAS if s["name"] == "http_request")
    properties = schema["input_schema"]["properties"]

    assert "url" not in properties
    # `headers` is cut rather than validated: a parameter that exists only to be
    # refused is a parameter the model will keep trying.
    assert "headers" not in properties
    assert set(properties) == {"method", "path", "query", "json_body", "as_user"}


def test_submitting_a_hypothesis_produces_no_verdict(sandbox):
    result = submit_hypothesis(
        sandbox,
        vuln_class="idor",
        file="routes/notes.py",
        line=49,
        title="detail() never checks ownership",
        rationale="get_note is called with the raw path id and returned as-is.",
        attack_plan="GET /api/notes/1002 as alice.",
    )

    assert result.ok
    assert len(sandbox.hypotheses) == 1
    assert not isinstance(result.meta.get("index"), Verdict)
    assert not any(isinstance(value, Verdict) for value in result.meta.values())
    # Recorded is not verified, and the ack says so.
    assert "not verified" in result.content


def test_a_hypothesis_class_without_an_oracle_is_refused(sandbox):
    result = submit_hypothesis(
        sandbox,
        vuln_class="sqli",
        file="database.py",
        line=1,
        title="x",
        rationale="x",
        attack_plan="x",
    )

    assert result.ok is False
    assert sandbox.hypotheses == []


def test_an_unknown_tool_name_is_a_result_not_an_exception(sandbox):
    result = dispatch("run_oracle", {"vuln_class": "idor"}, sandbox)

    assert result.ok is False
    assert "unknown tool" in result.error


@pytest.mark.parametrize(
    "name,arguments",
    [
        ("read_file", {}),
        ("read_file", {"path": "app.py", "offset": 3}),
        ("search_code", {}),
        ("http_request", {"method": "GET"}),
        ("http_request", {}),
        ("submit_hypothesis", {"vuln_class": "idor"}),
        ("submit_hypothesis", None),
    ],
)
def test_missing_or_malformed_arguments_never_raise(sandbox, name, arguments):
    result = dispatch(name, arguments, sandbox)

    assert result.ok is False
    assert result.error


def test_tool_schemas_round_trip_through_json():
    # Phase 5 caches these; a schema that does not serialise cannot be cached.
    assert json.loads(json.dumps(TOOL_SCHEMAS)) == TOOL_SCHEMAS


def test_tool_results_render_without_a_verdict_vocabulary(sandbox):
    ok = dispatch("read_file", {"path": "app.py"}, sandbox)
    bad = dispatch("read_file", {"path": "/etc/passwd"}, sandbox)

    assert ok.to_text().startswith("app.py:")
    assert bad.to_text().startswith("ERROR: ")
