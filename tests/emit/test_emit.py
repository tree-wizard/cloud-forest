"""Phase-6 gate: verified findings become regression tests that really run.

Nothing here is scripted at the model layer, because the emitter never sees a
model: it templates from a `Verdict`, which only an oracle can produce. So these
drive the real tools against the real target, take the real verdict, emit the
file, and then *run it with pytest* — against the vulnerable target, where it
must xfail (suite green), and against a stub that behaves correctly, where the
strict xfail must turn into a failure (suite red on the fixing commit).
"""

from __future__ import annotations

import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from aisec.agent import Finding
from aisec.callback import CallbackServer
from aisec.emit import DEFAULT_TESTS_DIR, EmitError, emit_all, emit_test
from aisec.emit import test_filename as filename_for
from aisec.oracles import run_oracle
from aisec.tools import CALLBACK_TOKEN, Hypothesis, Sandbox, http_request


REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def sandbox(live_target, source_root):
    with CallbackServer() as callback:
        box = Sandbox.for_target(source_root, live_target, callback=callback)
        try:
            yield box
        finally:
            box.close()


def attack(sandbox, vuln_class, *, file="routes/x.py", line=1, **request):
    """Run one real attack in its own window and return the Finding it earned."""
    hypothesis = Hypothesis(
        vuln_class=vuln_class,
        file=file,
        line=line,
        title=f"{vuln_class} on {request.get('path')}",
        rationale="hand-written attack, no model involved",
        attack_plan="send the request",
    )
    mark = sandbox.mark()
    http_request(sandbox, request.pop("method", "GET"), **request)
    if vuln_class == "ssrf":
        sandbox.callback.wait_for(sandbox.callback_nonce)
    trace = sandbox.trace_since(mark)
    verdict = run_oracle(vuln_class, trace, sandbox.oracle_context())
    return Finding(
        hypothesis=hypothesis, verdict=verdict, observations=list(trace), window_index=0
    )


def idor_finding(sandbox):
    return attack(sandbox, "idor", path="/api/notes/1002", as_user="alice")


def traversal_finding(sandbox):
    return attack(
        sandbox,
        "traversal",
        path="/api/attachments/download",
        query={"filename": "../private/secret-canary.txt"},
        as_user="alice",
    )


def ssrf_finding(sandbox):
    return attack(
        sandbox,
        "ssrf",
        method="POST",
        path="/api/imports/preview",
        json_body={"url": CALLBACK_TOKEN},
        as_user="alice",
    )


def run_pytest(path: Path, base_url: str) -> subprocess.CompletedProcess:
    """Run one generated test file the way CI would."""
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", str(path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env={
            **_clean_env(),
            "AISEC_TARGET_URL": base_url,
            "PYTHONPATH": str(REPO_ROOT),
        },
        timeout=120,
    )


def _clean_env() -> dict:
    import os

    # An API key has no business in a regression test's environment.
    return {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}


# -- the verdict is the only thing that justifies a file -------------------


@pytest.fixture
def out_dir(tmp_path):
    """A directory only the emitter writes to — `live_target` uses tmp_path too."""
    path = tmp_path / "security-tests"
    path.mkdir()
    return path


def test_rejected_finding_is_refused(sandbox, out_dir):
    """The trap 400s and never fetches, so no oracle verified it — and no test."""
    finding = attack(
        sandbox,
        "ssrf",
        method="POST",
        path="/api/links/preview",
        json_body={"url": CALLBACK_TOKEN},
        as_user="alice",
    )
    assert finding.status == "REJECTED"
    with pytest.raises(EmitError):
        emit_test(finding, sandbox, out_dir)
    assert list(out_dir.iterdir()) == []


def test_emit_all_skips_everything_an_oracle_did_not_verify(sandbox, tmp_path):
    verified = idor_finding(sandbox)
    rejected = attack(sandbox, "idor", path="/api/notes/1001", as_user="alice")
    assert rejected.status == "REJECTED"

    written = emit_all([rejected, verified], sandbox, tmp_path)
    assert [p.name for p in written] == [filename_for(verified)]


def test_filename_is_deterministic_so_rescans_overwrite(sandbox, out_dir):
    finding = idor_finding(sandbox)
    first = emit_test(finding, sandbox, out_dir)
    second = emit_test(finding, sandbox, out_dir)
    assert first == second == out_dir / "test_idor_api_notes_1002.py"
    assert len(list(out_dir.iterdir())) == 1


def test_default_output_directory_is_the_committed_one():
    assert DEFAULT_TESTS_DIR == Path(".security-tests")


# -- what may and may not appear in a committed file -----------------------


@pytest.mark.parametrize(
    "build", [idor_finding, traversal_finding, ssrf_finding], ids=["idor", "traversal", "ssrf"]
)
def test_generated_file_is_valid_python_and_leaks_no_secret(build, sandbox, tmp_path):
    path = emit_test(build(sandbox), sandbox, tmp_path)
    source = path.read_text(encoding="utf-8")

    compile(source, str(path), "exec")
    assert sandbox.canary not in source
    assert sandbox.callback_nonce not in source
    assert sandbox.callback.base_url not in source
    # The live target's ephemeral port must not be baked in either — the file is
    # committed and read on another machine.
    assert sandbox.base_url not in source
    assert "AISEC_TARGET_URL" in source


def test_ssrf_test_carries_the_token_not_a_dead_probe_url(sandbox, tmp_path):
    source = emit_test(ssrf_finding(sandbox), sandbox, tmp_path).read_text()
    assert CALLBACK_TOKEN in source
    assert not re.search(r"/probe/aisec-[0-9a-f]+", source)


def test_traversal_test_reads_the_canary_from_the_target_at_runtime(sandbox, tmp_path):
    source = emit_test(traversal_finding(sandbox), sandbox, tmp_path).read_text()
    assert "AISEC_CANARY_FILE" in source
    assert "secret-canary.txt" in source


def test_header_records_the_oracle_not_the_model_s_opinion(sandbox, tmp_path):
    finding = idor_finding(sandbox)
    source = emit_test(finding, sandbox, tmp_path).read_text()
    assert finding.verdict.invariant in source
    assert "xfail(strict=True" in source
    # The hypothesis is context in the header, never an assertion.
    assert "rationale" not in source


# -- and it actually runs ---------------------------------------------------


@pytest.mark.parametrize(
    "build", [idor_finding, traversal_finding, ssrf_finding], ids=["idor", "traversal", "ssrf"]
)
def test_generated_test_is_green_against_the_vulnerable_target(build, sandbox, tmp_path):
    path = emit_test(build(sandbox), sandbox, tmp_path)
    result = run_pytest(path, sandbox.base_url)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "xfailed" in result.stdout


def test_generated_test_goes_red_once_the_bug_is_fixed(sandbox, tmp_path):
    """The direction that matters: a fixed target must fail this file.

    Pointed at a target that authorizes correctly, the assertion passes — and a
    strict xfail turns a pass into a failure, which is the signal to delete the
    marker and keep the test forever.
    """
    path = emit_test(idor_finding(sandbox), sandbox, tmp_path)
    with patched_target() as base_url:
        result = run_pytest(path, base_url)
    assert result.returncode != 0, result.stdout
    assert "XPASS(strict)" in result.stdout or "xpassed" in result.stdout


def test_unreachable_target_is_an_error_not_a_silent_xfail(sandbox, tmp_path):
    """xfail swallows exceptions in a test body, so the replay happens at import."""
    path = emit_test(idor_finding(sandbox), sandbox, tmp_path)
    result = run_pytest(path, "http://127.0.0.1:1")
    assert result.returncode != 0
    assert "xfailed" not in result.stdout
    assert "error" in (result.stdout + result.stderr).lower()


class _FixedApp:
    """Minimal WSGI stand-in for the target with object-level authz fixed."""

    def __call__(self, environ, start_response):
        body = b'{"error": "note belongs to another user"}'
        start_response(
            "403 FORBIDDEN",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        )
        return [body]


class patched_target:
    def __enter__(self) -> str:
        self._server = make_server("127.0.0.1", 0, _FixedApp(), threaded=True)
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=0.05), daemon=True
        )
        self._thread.start()
        return f"http://127.0.0.1:{self._server.server_port}"

    def __exit__(self, *_exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
