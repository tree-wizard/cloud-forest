"""Deterministic verdicts — the trust boundary.

The model never renders a verdict; these functions do, from structured signals
(owner ids, the canary string, the callback flag), never response prose.
Implemented in phase 2, before the agent loop exists to depend on it.

Two deliberate calls, stated here because they are easy to erode later:

* Oracles receive observations only. The hypothesis that motivated an attack is
  never passed in, so model-authored text has no path to a verdict even by
  accident. `tests/oracles/test_contract.py` enforces that structurally.
* Everything fails closed. Non-2xx, unparseable JSON, an unknown identity, an
  empty trace, an exception mid-extraction — all resolve to HELD. Precision is
  the product claim, so ambiguity means "not proven", never "probably".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence


@dataclass(frozen=True)
class HttpObservation:
    """One request/response the tool layer actually performed."""

    method: str
    url: str
    path: str
    query: str = ""
    sent_as: str | None = None
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    body_text: str = ""
    json: Any = None
    elapsed_ms: float = 0.0

    @classmethod
    def from_flask(
        cls,
        response,
        *,
        sent_as: str | None,
        method: str,
        path: str,
        query: str = "",
        request_body: str = "",
    ) -> HttpObservation:
        """Build an observation from a Flask test-client response."""
        body_text = response.get_data(as_text=True)
        try:
            parsed = response.get_json(silent=True)
        except Exception:  # noqa: BLE001 - a hostile body must not crash the trace
            parsed = None
        url = path if not query else f"{path}?{query}"
        return cls(
            method=method.upper(),
            url=url,
            path=path,
            query=query,
            sent_as=sent_as,
            status=response.status_code,
            headers=dict(response.headers),
            request_body=request_body,
            body_text=body_text,
            json=parsed,
        )


@dataclass(frozen=True)
class CallbackHit:
    """One request the callback listener recorded."""

    path: str
    nonce: str
    received_at: float = 0.0


@dataclass(frozen=True)
class OracleContext:
    """Everything an oracle is allowed to know beyond the trace itself."""

    canary: str = ""
    callback_hits: Sequence[CallbackHit] = ()
    callback_nonce: str = ""
    owner_field: str = "owner_id"


@dataclass(frozen=True)
class Verdict:
    """The only thing that can close a finding."""

    oracle: str
    invariant: str
    violated: bool
    evidence: dict[str, Any] = field(default_factory=dict)
    detail: str = ""

    @property
    def status(self) -> str:
        return "VIOLATED" if self.violated else "HELD"

    @property
    def finding(self) -> str:
        return "VERIFIED" if self.violated else "REJECTED"


def _request_evidence(observation: HttpObservation) -> dict[str, Any]:
    """The exact reproducing request, in the shape phase 6 templates from."""
    return {
        "method": observation.method,
        "path": observation.path,
        "query": observation.query,
        "request_body": observation.request_body,
        "sent_as": observation.sent_as,
        "status": observation.status,
    }


def _walk_dicts(node: Any):
    """Yield every dict anywhere in a parsed JSON body."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)


def check_idor(
    trace: Sequence[HttpObservation], ctx: OracleContext
) -> Verdict:
    """VIOLATED iff a 2xx body carries an owner id other than the sender's."""
    invariant = f"response.{ctx.owner_field} == requesting_user_id"
    for observation in trace:
        if not 200 <= observation.status < 300:
            continue
        if observation.sent_as is None or observation.json is None:
            continue
        try:
            for node in _walk_dicts(observation.json):
                owner = node.get(ctx.owner_field)
                if not isinstance(owner, str) or owner == observation.sent_as:
                    continue
                evidence = _request_evidence(observation)
                evidence.update(
                    {
                        "owner_field": ctx.owner_field,
                        "owner_found": owner,
                        "requested_as": observation.sent_as,
                        "resource_id": node.get("id"),
                    }
                )
                return Verdict(
                    oracle="idor",
                    invariant=invariant,
                    violated=True,
                    evidence=evidence,
                    detail=(
                        f"{observation.method} {observation.url} as "
                        f"{observation.sent_as} returned {ctx.owner_field}="
                        f"{owner!r}"
                    ),
                )
        except Exception:  # noqa: BLE001 - fail closed on a malformed body
            continue
    return Verdict(
        oracle="idor",
        invariant=invariant,
        violated=False,
        detail="no 2xx response exposed another user's resource",
    )


def check_path_traversal(
    trace: Sequence[HttpObservation], ctx: OracleContext
) -> Verdict:
    """VIOLATED iff a successful response body contains the canary."""
    # An unset canary would make `"" in text` vacuously true and verify every
    # response — exactly the footgun that turns a precision claim into a lie.
    if len(ctx.canary.strip()) < 8:
        raise ValueError("path traversal oracle requires a non-trivial canary")

    invariant = "SECRET_CANARY not in response.text"
    for observation in trace:
        # A canary echoed in a 4xx/5xx error body is HELD: an error page is not
        # a successful file read.
        if observation.status >= 400 or observation.status == 0:
            continue
        offset = observation.body_text.find(ctx.canary)
        if offset < 0:
            continue
        evidence = _request_evidence(observation)
        evidence.update({"canary_offset": offset, "canary": ctx.canary})
        return Verdict(
            oracle="traversal",
            invariant=invariant,
            violated=True,
            evidence=evidence,
            detail=(
                f"{observation.method} {observation.url} returned the canary at "
                f"byte {offset}"
            ),
        )
    return Verdict(
        oracle="traversal",
        invariant=invariant,
        violated=False,
        detail="no successful response contained the canary",
    )


def check_ssrf(trace: Sequence[HttpObservation], ctx: OracleContext) -> Verdict:
    """VIOLATED iff the nonce reached the listener via a target-directed request."""
    if not ctx.callback_nonce.strip():
        raise ValueError("ssrf oracle requires a callback nonce")

    invariant = "callback_server.was_contacted(nonce) is False"
    nonce = ctx.callback_nonce
    hit = next((h for h in ctx.callback_hits if h.nonce == nonce), None)

    # Clause two: the contact must be attributable to a request *we sent to the
    # target*. Otherwise the agent could curl its own listener and call it SSRF.
    #
    # Only the *request* side counts. A target that echoes the nonce back in a
    # response body has not been made to fetch anything, and scanning responses
    # would let any echo endpoint satisfy this clause. SSRF always puts the
    # nonce on the request side, so the narrowing costs no recall.
    trigger = next(
        (
            o
            for o in trace
            if nonce in o.url
            or nonce in (o.query or "")
            or nonce in (o.request_body or "")
        ),
        None,
    )

    if hit is None or trigger is None:
        return Verdict(
            oracle="ssrf",
            invariant=invariant,
            violated=False,
            detail=(
                "callback hit not attributable to a target-directed request"
                if hit is not None
                else "no callback hit carried the nonce"
            ),
        )

    evidence = _request_evidence(trigger)
    evidence.update({"callback_nonce": nonce, "callback_path": hit.path})
    return Verdict(
        oracle="ssrf",
        invariant=invariant,
        violated=True,
        evidence=evidence,
        detail=(
            f"{trigger.method} {trigger.url} made the target contact the "
            f"listener at {hit.path}"
        ),
    )


ORACLES: dict[str, Callable[[Sequence[HttpObservation], OracleContext], Verdict]] = {
    "idor": check_idor,
    "traversal": check_path_traversal,
    "ssrf": check_ssrf,
}


def run_oracle(
    vuln_class: str, trace: Sequence[HttpObservation], ctx: OracleContext
) -> Verdict:
    """Dispatch to a registered oracle; an unknown class raises, never passes."""
    try:
        oracle = ORACLES[vuln_class]
    except KeyError:
        raise ValueError(f"no oracle registered for class {vuln_class!r}") from None
    return oracle(trace, ctx)
