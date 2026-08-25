"""Turns a verified finding into a committed pytest regression test.

The output of this tool is not a PDF. Every finding an oracle verified leaves a
file under `.security-tests/` that replays the exact request the oracle fired on
and re-runs *the same oracle function* over the response — so the generated test
and the product share one trust boundary instead of re-implementing the check in
a template.

Three things here are deliberate:

* **The assertion is the secure invariant, under `xfail(strict=True)`.** A test
  that asserted "the bug is still exploitable" would go red on the commit that
  fixes it, which is backwards for CI. So the file asserts what should hold once
  the bug is fixed, and carries a strict xfail recording that the bug was live
  when it was generated. Vulnerable target: assertion fails, xfail, suite green.
  Patched target: assertion passes, XPASS under strict, suite red — once, on the
  commit that fixes it, telling you to delete one marker line. After that it is a
  permanent regression test.

* **All the work happens at import, not in the test body.** `xfail` swallows
  exceptions raised inside a test, so a target that was simply down would look
  like an expected failure and the suite would be silently green. Replaying at
  module scope turns every such failure into a collection error instead. Same
  fail-closed instinct as the non-empty-canary check in `check_path_traversal`.

* **Nothing secret is templated in.** Every string that came off the wire goes
  through `Sandbox.scrub`, so the canary is redacted and the (already dead) probe
  URL is re-tokenized; the traversal test reads the canary from the target's own
  file at runtime and the SSRF test mints a fresh nonce from its own listener.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


DEFAULT_TESTS_DIR = Path(".security-tests")

_SLUG_UNSAFE = re.compile(r"[^a-z0-9]+")
_MAX_SLUG_CHARS = 60


class EmitError(RuntimeError):
    """A finding that must not become a test file."""


def _slug(text: str) -> str:
    slug = _SLUG_UNSAFE.sub("_", str(text).lower()).strip("_")
    return slug[:_MAX_SLUG_CHARS] or "target"


def test_filename(finding) -> str:
    """Deterministic name, so re-running a scan overwrites instead of piling up."""
    oracle = _slug(finding.verdict.oracle)
    path = _slug(finding.verdict.evidence.get("path", ""))
    return f"test_{oracle}_{path}.py"


def emit_test(finding, sandbox, out_dir: str | Path = DEFAULT_TESTS_DIR) -> Path:
    """Write one regression test for a VERIFIED finding and return its path.

    `sandbox` is needed for `scrub()` — and needs its callback listener still
    running, since that is what lets the probe URL be re-tokenized rather than
    baked into a committed file with a dead port in it.
    """
    if finding.status != "VERIFIED":
        # A test asserting a bug no oracle observed is exactly the model-opinion
        # artifact this project exists to not produce.
        raise EmitError(
            f"refusing to emit a test for a {finding.status} finding "
            f"({finding.verdict.oracle}): only an oracle's VIOLATED verdict "
            "justifies a regression test"
        )

    verdict = finding.verdict
    body = _render(finding, sandbox)

    if sandbox.canary and sandbox.canary in body:  # pragma: no cover - belt and braces
        raise EmitError("generated test contains the canary; refusing to write it")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / test_filename(finding)
    path.write_text(body, encoding="utf-8")
    return path


def emit_all(findings, sandbox, out_dir: str | Path = DEFAULT_TESTS_DIR) -> list[Path]:
    """Emit for every verified finding, skipping the rest without complaint."""
    return [
        emit_test(f, sandbox, out_dir) for f in findings if f.status == "VERIFIED"
    ]


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def _py(value: Any) -> str:
    """A literal safe to paste into the generated module."""
    return json.dumps(value, ensure_ascii=False) if isinstance(value, str) else repr(value)


_ORACLE_IMPORTS = {
    "idor": "check_idor",
    "traversal": "check_path_traversal",
    "ssrf": "check_ssrf",
}


def _render(finding, sandbox) -> str:
    verdict = finding.verdict
    oracle = verdict.oracle
    if oracle not in _ORACLE_IMPORTS:
        raise EmitError(f"no test template for oracle {oracle!r}")

    hyp = finding.hypothesis
    evidence = verdict.evidence
    scrub = sandbox.scrub

    header = _HEADER.format(
        title=scrub(hyp.title),
        oracle=oracle,
        invariant=verdict.invariant,
        detail=scrub(verdict.detail),
        source=f"{hyp.file}:{hyp.line}",
        vuln_class=hyp.vuln_class,
    )
    constants = _CONSTANTS.format(
        check=_ORACLE_IMPORTS[oracle],
        method=_py(evidence.get("method", "GET")),
        path=_py(evidence.get("path", "/")),
        query=_py(scrub(str(evidence.get("query", "") or ""))),
        request_body=_py(scrub(str(evidence.get("request_body", "") or ""))),
        sent_as=_py(evidence.get("sent_as")),
        status=_py(evidence.get("status", 0)),
    )
    context = _CONTEXTS[oracle].format(
        owner_field=_py(evidence.get("owner_field", "owner_id")),
        canary_file=_py(_canary_relpath(sandbox)),
    )
    test = _TEST.format(
        name=f"test_{_slug(oracle)}_{_slug(evidence.get('path', ''))}",
        reason=_py(f"{oracle} bug live in the target when this test was generated"),
        assertion=_ASSERTIONS[oracle],
    )
    return header + constants + context + test


def _canary_relpath(sandbox) -> str:
    """Where the traversal test should read the canary from at runtime.

    Relative to the repo root when it can be, so the committed file is not tied
    to one machine's checkout path.
    """
    canary_file = Path(sandbox.source_root) / "data" / "private" / "secret-canary.txt"
    try:
        return canary_file.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return canary_file.as_posix()


_HEADER = '''\
"""Regression test — {title}

GENERATED by `aisec scan` from a finding a deterministic oracle verified against a
running target. Not hand-written, and not a model's judgment: every value below is
the request the oracle actually fired on.

    class      {vuln_class}
    oracle     {oracle}
    invariant  {invariant}
    evidence   {detail}
    source     {source}

The assertion below is the SECURE invariant — what should hold once the bug is
fixed — so this file is a CI regression test, not a proof-of-exploit script. It
carries a strict xfail because the bug was live when it was generated:

    bug present -> assertion fails  -> xfail  -> `pytest .security-tests/` is GREEN
    bug fixed   -> assertion passes -> XPASS  -> RED, once, on the fixing commit

When it goes red, delete the `@pytest.mark.xfail` line. From then on it fails if
the bug ever comes back, which is the whole point of shipping it.

Requires the target to be running. Override the host with AISEC_TARGET_URL.
"""

from __future__ import annotations

import os
import pathlib
import time

import httpx
import pytest

'''

_CONSTANTS = '''\
from aisec.oracles import HttpObservation, OracleContext, {check}


BASE_URL = os.environ.get("AISEC_TARGET_URL", "http://127.0.0.1:5000").rstrip("/")

METHOD = {method}
PATH = {path}
QUERY = {query}
REQUEST_BODY = {request_body}
SENT_AS = {sent_as}
OBSERVED_STATUS = {status}


def _replay(request_body: str = REQUEST_BODY) -> HttpObservation:
    """Re-send the recorded request and observe it the way the scan did."""
    url = BASE_URL + PATH + (f"?{{QUERY}}" if QUERY else "")
    headers = {{"Accept": "application/json, text/plain, */*"}}
    if SENT_AS:
        # The tool layer chose this identity, not the model — see tools.http_request.
        headers["X-User"] = SENT_AS
    content = request_body.encode("utf-8") if request_body else b""
    if request_body:
        headers["Content-Type"] = "application/json"

    started = time.monotonic()
    with httpx.Client(timeout=10.0, follow_redirects=False) as client:
        response = client.request(METHOD, url, content=content, headers=headers)
    return HttpObservation.from_httpx(
        response,
        sent_as=SENT_AS,
        method=METHOD,
        path=PATH,
        query=QUERY,
        request_body=request_body,
        elapsed_ms=(time.monotonic() - started) * 1000,
    )


'''

# Everything below runs at import. An unreachable target, a missing canary or a
# listener that will not start must be a collection error — inside the test body
# xfail would swallow it and the suite would go green for the wrong reason.

_CONTEXTS = {
    "idor": '''\
def _verdict():
    observation = _replay()
    return check_idor([observation], OracleContext(owner_field={owner_field}))


VERDICT = _verdict()


''',
    "traversal": '''\
CANARY_FILE = pathlib.Path(os.environ.get("AISEC_CANARY_FILE", {canary_file}))


def _canary() -> str:
    """The canary is read from the target at runtime, never committed here."""
    if not CANARY_FILE.is_file():
        raise RuntimeError(
            f"canary file {{CANARY_FILE}} not found; set AISEC_CANARY_FILE to the "
            "target's private canary path"
        )
    text = CANARY_FILE.read_text(encoding="utf-8").strip()
    if len(text) < 8:
        raise RuntimeError(f"canary in {{CANARY_FILE}} is too short to be a signal")
    return text


def _verdict():
    observation = _replay()
    return check_path_traversal([observation], OracleContext(canary=_canary()))


VERDICT = _verdict()


''',
    "ssrf": '''\
from aisec.callback import CallbackServer, mint_nonce
from aisec.tools import CALLBACK_TOKEN


def _verdict():
    """A fresh listener and a fresh nonce: the recorded probe URL is long dead.

    The oracle's attribution clause still holds — the nonce reaches the listener
    only if the target fetched it, because nothing else here can contact it.
    """
    with CallbackServer() as callback:
        nonce = mint_nonce()
        body = REQUEST_BODY.replace(CALLBACK_TOKEN, callback.url_for(nonce))
        if CALLBACK_TOKEN in REQUEST_BODY and body == REQUEST_BODY:  # pragma: no cover
            raise RuntimeError("callback token substitution failed")
        observation = _replay(body)
        callback.wait_for(nonce)
        return check_ssrf(
            [observation],
            OracleContext(callback_hits=callback.hits(), callback_nonce=nonce),
        )


VERDICT = _verdict()


''',
}

_ASSERTIONS = {
    "idor": (
        "assert not VERDICT.violated, (\n"
        '        f"cross-tenant read still works: {VERDICT.detail}"\n'
        "    )"
    ),
    "traversal": (
        "assert not VERDICT.violated, (\n"
        '        f"the target still serves the private canary file: {VERDICT.detail}"\n'
        "    )"
    ),
    "ssrf": (
        "assert not VERDICT.violated, (\n"
        '        f"the target still fetches an attacker-supplied URL: {VERDICT.detail}"\n'
        "    )"
    ),
}

_TEST = '''\
@pytest.mark.xfail(strict=True, reason={reason})
def {name}():
    {assertion}
'''
