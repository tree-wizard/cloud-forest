"""Structural guards on the one rule: the model never renders a verdict."""

from __future__ import annotations

import inspect
import json

import pytest

from aisec.oracles import ORACLES, HttpObservation, OracleContext, Verdict, run_oracle


MODEL_AUTHORED = {
    "hypothesis",
    "rationale",
    "confidence",
    "claim",
    "reasoning",
    "model_output",
    "severity",
}


def test_no_oracle_accepts_model_authored_text():
    for name, oracle in ORACLES.items():
        parameters = set(inspect.signature(oracle).parameters)
        assert not parameters & MODEL_AUTHORED, name
        assert len(parameters) == 2, name


def test_unknown_vulnerability_class_raises_rather_than_passing():
    with pytest.raises(ValueError):
        run_oracle("sqli", [], OracleContext(canary="x" * 20))


def test_registry_dispatches_to_the_three_supported_classes():
    assert set(ORACLES) == {"idor", "traversal", "ssrf"}

    observation = HttpObservation(
        method="GET",
        url="/api/notes/1002",
        path="/api/notes/1002",
        sent_as="alice",
        status=200,
        json={"owner_id": "bob"},
    )
    verdict = run_oracle("idor", [observation], OracleContext())
    assert verdict.oracle == "idor"
    assert verdict.violated is True


def test_evidence_round_trips_through_json():
    observation = HttpObservation(
        method="GET",
        url="/api/notes/1002",
        path="/api/notes/1002",
        sent_as="alice",
        status=200,
        json={"id": 1002, "owner_id": "bob"},
    )
    verdict = run_oracle("idor", [observation], OracleContext())

    assert json.loads(json.dumps(verdict.evidence)) == verdict.evidence


def test_verdict_vocabulary_matches_the_reported_output():
    held = Verdict(oracle="idor", invariant="x", violated=False)
    violated = Verdict(oracle="idor", invariant="x", violated=True)

    assert (held.status, held.finding) == ("HELD", "REJECTED")
    assert (violated.status, violated.finding) == ("VIOLATED", "VERIFIED")
