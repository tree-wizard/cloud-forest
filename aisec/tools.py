"""The four tools the agent gets, and the sandbox that bounds them.

This layer sits between the model and the oracles, and its job is to make the
oracles' preconditions *structurally* true rather than conventionally true. The
oracles were written first, in phase 2, and each one leans on something only the
tool layer can guarantee:

* `check_idor` trusts `observation.sent_as`. That is only trustworthy because
  `http_request` — not the model — decides the identity a request goes out as.
* `check_ssrf` requires the callback hit to be attributable to a *target-directed*
  request. The model never sees a nonce and cannot name a host, so the only way a
  nonce reaches the listener is for the target to have fetched it.
* `check_path_traversal` fires on the canary in a sub-400 body. The harness holds
  the canary, `read_file` denies the directory it lives in, and `http_request`
  refuses to *send* it — so the model cannot plant the canary and read it back.

Each of those is closed by removing the capability, not by filtering for it.

Deliberately absent: a tool that runs an oracle. The model can propose and
attack; it cannot invoke the trust boundary.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx

from aisec.callback import CallbackServer, mint_nonce
from aisec.oracles import ORACLES, HttpObservation, OracleContext


IDENTITIES = ("alice", "bob", "anonymous")
ALLOWED_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

# The model writes this literal token; `http_request` swaps in the real probe
# URL on the way out. See `_substitute_callback`.
CALLBACK_TOKEN = "{{CALLBACK_URL}}"
REDACTED_CANARY = "[REDACTED_CANARY]"

MAX_PATTERN_CHARS = 200
MAX_FILE_BYTES = 256_000
MAX_READ_LINES = 800
MAX_MATCHES = 50
MAX_REQUEST_BODY_BYTES = 16_000
MAX_RECORDED_BODY_BYTES = 200_000
MODEL_VIEW_CHARS = 4_000
DEFAULT_MAX_REQUESTS = 40
HTTP_TIMEOUT_SECONDS = 5.0

SKIP_DIRS = frozenset({".git", "__pycache__", "instance", ".venv", ".pytest_cache"})
# The canary lives here. Reading it is the *target's* bug to have, not a
# capability the agent gets handed for free.
DENIED_PREFIXES = ("data/private",)

_CONTROL_CHARS = re.compile(r"[\x00-\x20\x7f]")


# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolResult:
    """What a tool hands back. `agent.py` fences this as untrusted in phase 4."""

    ok: bool
    content: str = ""
    error: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_text(self) -> str:
        return self.content if self.ok else f"ERROR: {self.error}"


@dataclass(frozen=True)
class Hypothesis:
    """A claim awaiting an attack. Deliberately carries no verdict-shaped field.

    No confidence, no severity, no "exploitable" — a hypothesis is an intention
    to test, and nothing the model writes here can close a finding.
    """

    vuln_class: str
    file: str
    line: int
    title: str
    rationale: str
    attack_plan: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "file": self.file,
            "line": self.line,
            "title": self.title,
            "rationale": self.rationale,
            "attack_plan": self.attack_plan,
        }


# --------------------------------------------------------------------------
# sandbox
# --------------------------------------------------------------------------


@dataclass
class Sandbox:
    """Everything the tools are allowed to touch, and the record of what they did."""

    source_root: Path
    base_url: str
    canary: str  # never shown to the model; only ever reaches an OracleContext
    callback: CallbackServer | None = None
    callback_nonce: str = ""
    max_requests: int = DEFAULT_MAX_REQUESTS
    trace: list[HttpObservation] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    refusals: list[dict[str, Any]] = field(default_factory=list)
    request_count: int = 0
    client: httpx.Client | None = None

    @classmethod
    def for_target(
        cls,
        source_root: str | Path,
        base_url: str,
        *,
        callback: CallbackServer | None = None,
        callback_nonce: str = "",
        canary_file: str | Path | None = None,
        max_requests: int = DEFAULT_MAX_REQUESTS,
    ) -> Sandbox:
        root = Path(source_root).resolve()
        path = (
            Path(canary_file)
            if canary_file is not None
            else root / "data" / "private" / "secret-canary.txt"
        )
        canary = path.read_text(encoding="utf-8").strip()
        # The nonce is minted by the harness, never accepted from the model.
        if callback is not None and not callback_nonce:
            callback_nonce = mint_nonce()
        # The traversal oracle refuses to run on a trivial canary, because
        # `"" in text` is vacuously true and would verify every response. Fail
        # here, at construction, rather than mid-scan.
        if len(canary) < 8:
            raise ValueError(f"canary in {path} is too short to be a reliable signal")

        return cls(
            source_root=root,
            base_url=base_url.rstrip("/"),
            canary=canary,
            callback=callback,
            callback_nonce=callback_nonce,
            max_requests=max_requests,
            client=httpx.Client(
                timeout=HTTP_TIMEOUT_SECONDS,
                follow_redirects=False,  # a 30x is the other way off this host
            ),
        )

    # -- oracle handoff ----------------------------------------------------

    def oracle_context(self, *, owner_field: str = "owner_id") -> OracleContext:
        hits = self.callback.hits() if self.callback is not None else ()
        return OracleContext(
            canary=self.canary,
            callback_hits=hits,
            callback_nonce=self.callback_nonce,
            owner_field=owner_field,
        )

    def mark(self) -> int:
        """Open a fresh attack window and return a cursor into the trace.

        Without scoping, IDOR exploration early in a scan would still be in the
        trace when a *traversal* hypothesis is checked, and the wrong hypothesis
        would collect someone else's verdict.

        Clearing the callback log is part of the same window, not an extra:
        scoping the trace alone produced a live false positive. Attack the real
        SSRF, then probe the allowlisted preview trap — the trap 400s and never
        fetches, but its request still carries the nonce, and the *previous*
        attack's hit is still on record. Trace scoped, hits not, verdict wrong.
        The trace and the callback log are two halves of one observation.
        """
        if self.callback is not None:
            self.callback.reset()
        return len(self.trace)

    def trace_since(self, mark: int) -> list[HttpObservation]:
        return self.trace[mark:]

    # -- source tree -------------------------------------------------------

    def source_files(self) -> list[str]:
        found = []
        for path in self.source_root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(self.source_root).as_posix()
            if _skipped(rel):
                continue
            found.append(rel)
        return sorted(found)

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None

    # -- bookkeeping -------------------------------------------------------

    def refuse(self, tool: str, reason: str, **detail: Any) -> ToolResult:
        """Record and return a refusal. Deliberately leaves no observation.

        A refused request never happened, so it must not appear in the trace an
        oracle reads, and must not consume the request budget.
        """
        entry = {"tool": tool, "reason": reason, **detail}
        self.refusals.append(entry)
        return ToolResult(ok=False, error=reason, meta={"refused": True, **detail})

    def scrub(self, text: str) -> str:
        """Strip harness-only secrets out of anything model-facing.

        Belt and braces: `read_file` and `search_code` already deny the private
        directory, and `http_request` refuses to send the canary. This catches
        the one remaining route — a traversal that *works* — so the oracle sees
        the canary in the response body while the model does not.
        """
        if self.canary:
            text = text.replace(self.canary, REDACTED_CANARY)
        if self.callback_nonce:
            if self.callback is not None:
                try:
                    probe = self.callback.url_for(self.callback_nonce)
                except RuntimeError:  # listener already stopped
                    probe = ""
                if probe:
                    text = text.replace(probe, CALLBACK_TOKEN)
            text = text.replace(self.callback_nonce, CALLBACK_TOKEN)
        return text


def _skipped(rel_path: str) -> bool:
    return any(part in SKIP_DIRS for part in rel_path.split("/"))


def _denied(rel_path: str) -> bool:
    return any(
        rel_path == prefix or rel_path.startswith(prefix + "/")
        for prefix in DENIED_PREFIXES
    )


def _resolve_in_root(sandbox: Sandbox, path: str) -> tuple[Path | None, str]:
    """Contain `path` inside the source root, or explain why it does not fit.

    `resolve()` before `relative_to()` — deliberately getting right what the
    target's attachment route gets wrong.
    """
    if not isinstance(path, str) or not path.strip():
        return None, "path must be a non-empty string"
    candidate = Path(path)
    if candidate.is_absolute():
        return None, "path must be relative to the source root"
    try:
        resolved = (sandbox.source_root / candidate).resolve()
    except (OSError, ValueError):
        return None, "path is not a usable filesystem path"
    try:
        rel = resolved.relative_to(sandbox.source_root).as_posix()
    except ValueError:
        return None, "path escapes the source root"
    if _denied(rel):
        return None, f"{rel} is outside the agent's reach"
    return resolved, rel


# --------------------------------------------------------------------------
# read_file
# --------------------------------------------------------------------------


def read_file(sandbox: Sandbox, path: str) -> ToolResult:
    """Read one file under the source root, line-numbered so hypotheses can cite it."""
    resolved, rel = _resolve_in_root(sandbox, path)
    if resolved is None:
        return sandbox.refuse("read_file", rel, path=path)

    if resolved.is_dir():
        entries = sorted(
            f"{child.name}/" if child.is_dir() else child.name
            for child in resolved.iterdir()
            if not _skipped(f"{rel}/{child.name}".lstrip("/"))
        )
        return ToolResult(
            ok=True,
            content=f"{rel or '.'} is a directory:\n" + "\n".join(entries),
            meta={"path": rel, "kind": "directory", "entries": len(entries)},
        )

    if not resolved.is_file():
        return ToolResult(ok=False, error=f"{rel} does not exist")

    size = resolved.stat().st_size
    if size > MAX_FILE_BYTES:
        return ToolResult(
            ok=False, error=f"{rel} is {size} bytes, over the {MAX_FILE_BYTES} cap"
        )
    try:
        text = resolved.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ToolResult(ok=False, error=f"{rel} is not readable as UTF-8 text")

    lines = text.splitlines()
    truncated = len(lines) > MAX_READ_LINES
    shown = lines[:MAX_READ_LINES]
    body = "\n".join(f"{n:5d}\t{line}" for n, line in enumerate(shown, 1))
    if truncated:
        body += f"\n... truncated at {MAX_READ_LINES} of {len(lines)} lines"

    return ToolResult(
        ok=True,
        # Source comments are data. Injection bait in the target is returned
        # verbatim — sanitising it would hide the attack surface and is the
        # wrong defence; phase 4 fences tool output instead.
        content=sandbox.scrub(f"{rel}:\n{body}"),
        meta={"path": rel, "lines": len(lines), "truncated": truncated},
    )


# --------------------------------------------------------------------------
# search_code
# --------------------------------------------------------------------------


def search_code(
    sandbox: Sandbox,
    pattern: str,
    glob: str = "*.py",
    max_results: int = MAX_MATCHES,
) -> ToolResult:
    """Regex the source tree, reporting file:line for each match."""
    if not isinstance(pattern, str) or not pattern:
        return ToolResult(ok=False, error="pattern must be a non-empty string")
    if len(pattern) > MAX_PATTERN_CHARS:
        return ToolResult(
            ok=False,
            error=f"pattern is {len(pattern)} chars, over the {MAX_PATTERN_CHARS} cap",
        )
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return ToolResult(ok=False, error=f"invalid regular expression: {exc}")

    limit = max(1, min(int(max_results or MAX_MATCHES), MAX_MATCHES))
    matches: list[str] = []
    scanned = 0

    for path in sorted(sandbox.source_root.rglob(glob)):
        if len(matches) >= limit:
            break
        if not path.is_file():
            continue
        rel = path.relative_to(sandbox.source_root).as_posix()
        if _skipped(rel) or _denied(rel):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        # Matching per line, not per file: backtracking cost is then bounded by
        # the longest line rather than by file size. A wall-clock budget cannot
        # substitute — `re` is not interruptible from the calling thread, so the
        # check would only run after the hang.
        for lineno, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                matches.append(f"{rel}:{lineno}: {line.strip()}")
                if len(matches) >= limit:
                    break

    header = f"{len(matches)} match(es) for {pattern!r} in {scanned} file(s)"
    return ToolResult(
        ok=True,
        content=sandbox.scrub(header + ("\n" + "\n".join(matches) if matches else "")),
        meta={"matches": len(matches), "files_scanned": scanned, "glob": glob},
    )


# --------------------------------------------------------------------------
# http_request
# --------------------------------------------------------------------------


def _validate_path(path: str) -> str | None:
    """Reject anything that could name a host. Returns a reason, or None if fine.

    A path, never a URL. `httpx.Client(base_url=...)` does *not* pin — merging
    an absolute URL just returns it — so an allowlist here would mean
    out-parsing every `http:/\\evil` trick. Making a host inexpressible removes
    the class instead of filtering it.
    """
    if not isinstance(path, str) or not path:
        return "path must be a non-empty string"
    if not path.startswith("/"):
        return "path must start with '/' (it is a path, not a URL)"
    if path.startswith("//"):
        return "path must not start with '//' (that names a host)"
    if "://" in path:
        return "path must not contain a scheme"
    if "\\" in path:
        return "path must not contain backslashes"
    if _CONTROL_CHARS.search(path):
        return "path must not contain whitespace or control characters"
    return None


def _substitute_callback(value: Any, url: str) -> Any:
    """Swap the literal token for the real probe URL, anywhere in the payload."""
    if isinstance(value, str):
        return value.replace(CALLBACK_TOKEN, url)
    if isinstance(value, dict):
        return {k: _substitute_callback(v, url) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_callback(v, url) for v in value]
    return value


def _contains(value: Any, needle: str) -> bool:
    return needle in json.dumps(value, default=str)


def http_request(
    sandbox: Sandbox,
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    json_body: Any = None,
    as_user: str = "anonymous",
) -> ToolResult:
    """Send one request to the target, as an identity the *tool* chooses."""
    method = str(method or "").upper()
    if method not in ALLOWED_METHODS:
        return sandbox.refuse(
            "http_request",
            f"method {method!r} is not one of {list(ALLOWED_METHODS)}",
            method=method,
        )
    if as_user not in IDENTITIES:
        return sandbox.refuse(
            "http_request",
            f"as_user {as_user!r} is not one of {list(IDENTITIES)}",
            as_user=as_user,
        )
    reason = _validate_path(path)
    if reason is not None:
        return sandbox.refuse("http_request", reason, path=path)
    if sandbox.request_count >= sandbox.max_requests:
        return sandbox.refuse(
            "http_request",
            f"request budget of {sandbox.max_requests} is exhausted",
            path=path,
        )

    if query is not None and not isinstance(query, dict):
        return sandbox.refuse("http_request", "query must be an object", path=path)

    # Callback substitution. The model writes the token; only the harness knows
    # the nonce, so a nonce it never saw is one it cannot plant.
    probe_url = ""
    if sandbox.callback is not None and sandbox.callback_nonce:
        probe_url = sandbox.callback.url_for(sandbox.callback_nonce)
    if not probe_url and (
        (query is not None and _contains(query, CALLBACK_TOKEN))
        or (json_body is not None and _contains(json_body, CALLBACK_TOKEN))
    ):
        return sandbox.refuse(
            "http_request", "no callback listener is configured for this scan", path=path
        )
    query = _substitute_callback(query, probe_url) if query else None
    json_body = (
        _substitute_callback(json_body, probe_url) if json_body is not None else None
    )

    # Attack hygiene, and it belongs here rather than in the oracle: telling
    # "read the canary out of the target" from "posted it there first" would
    # make the oracle stateful, and a stateful oracle is a weaker trust
    # boundary than a tool that simply cannot send the string.
    if (
        sandbox.canary in path
        or (query is not None and _contains(query, sandbox.canary))
        or (json_body is not None and _contains(json_body, sandbox.canary))
    ):
        return sandbox.refuse(
            "http_request",
            "outbound request carries the canary; a planted secret proves nothing",
            path=path,
        )

    query_string = urlencode(query, doseq=True) if query else ""
    url = f"{sandbox.base_url}{path}" + (f"?{query_string}" if query_string else "")

    # Defence in depth: after all of the above, the URL had better still be the
    # target. If this ever fires, a validation rule above has a hole in it.
    target, final = urlsplit(sandbox.base_url), urlsplit(url)
    if (final.scheme, final.hostname, final.port) != (
        target.scheme,
        target.hostname,
        target.port,
    ):
        return sandbox.refuse(
            "http_request", "resolved URL left the target host", path=path
        )

    body_bytes = b""
    headers = {"Accept": "application/json, text/plain, */*"}
    request_body = ""
    if json_body is not None:
        request_body = json.dumps(json_body)
        body_bytes = request_body.encode("utf-8")
        if len(body_bytes) > MAX_REQUEST_BODY_BYTES:
            return sandbox.refuse(
                "http_request",
                f"request body is over the {MAX_REQUEST_BODY_BYTES}-byte cap",
                path=path,
            )
        headers["Content-Type"] = "application/json"

    # The *tool* decides the identity, so `sent_as` on the observation is a fact
    # about what was sent rather than a model assertion — which is exactly what
    # `check_idor` trusts.
    #
    # anonymous maps to sent_as=None on purpose. If it were sent_as="anonymous",
    # then any 2xx body carrying any owner_id — alice's own notes included —
    # would satisfy `owner != sent_as` and fire the IDOR oracle. None routes it
    # into the oracle's existing "identity the tool layer could not attribute"
    # branch, which is HELD. Do not "fix" this.
    sent_as = None if as_user == "anonymous" else as_user
    if sent_as is not None:
        headers["X-User"] = sent_as

    client = sandbox.client
    if client is None:
        client = sandbox.client = httpx.Client(
            timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False
        )

    sandbox.request_count += 1
    started = time.monotonic()
    try:
        response = client.request(method, url, content=body_bytes, headers=headers)
    except httpx.HTTPError as exc:
        # A target that refuses the connection is an observation, not a crash.
        elapsed = (time.monotonic() - started) * 1000
        sandbox.trace.append(
            HttpObservation(
                method=method,
                url=url,
                path=path,
                query=query_string,
                sent_as=sent_as,
                status=0,
                request_body=request_body,
                body_text="",
                json=None,
                elapsed_ms=elapsed,
            )
        )
        return ToolResult(
            ok=False,
            error=f"request failed: {type(exc).__name__}: {exc}",
            meta={"status": 0, "path": path},
        )

    elapsed = (time.monotonic() - started) * 1000

    # The observation carries the whole body, because the oracle reads it. The
    # model gets a truncated, scrubbed view. `from_httpx` is shared with the
    # regression tests `emit.py` writes, so a generated test observes the target
    # through the same constructor the scan did.
    observation = HttpObservation.from_httpx(
        response,
        sent_as=sent_as,
        method=method,
        path=path,
        query=query_string,
        request_body=request_body,
        elapsed_ms=elapsed,
        max_body_bytes=MAX_RECORDED_BODY_BYTES,
    )
    sandbox.trace.append(observation)
    body_text = observation.body_text

    view = body_text[:MODEL_VIEW_CHARS]
    if len(body_text) > MODEL_VIEW_CHARS:
        view += f"\n... truncated at {MODEL_VIEW_CHARS} of {len(body_text)} chars"
    content = sandbox.scrub(
        f"{method} {path}"
        + (f"?{query_string}" if query_string else "")
        + f" as {as_user}\n"
        + f"HTTP {response.status_code}\n"
        + view
    )
    return ToolResult(
        ok=True,
        content=content,
        meta={
            "status": response.status_code,
            "path": path,
            "sent_as": sent_as,
            "elapsed_ms": round(elapsed, 1),
        },
    )


# --------------------------------------------------------------------------
# submit_hypothesis
# --------------------------------------------------------------------------


def submit_hypothesis(
    sandbox: Sandbox,
    *,
    vuln_class: str,
    file: str,
    line: int,
    title: str,
    rationale: str,
    attack_plan: str,
) -> ToolResult:
    """Record a claim to be tested. Recording is not verifying."""
    if vuln_class not in ORACLES:
        return ToolResult(
            ok=False,
            error=(
                f"no oracle exists for {vuln_class!r}; "
                f"supported classes are {sorted(ORACLES)}"
            ),
        )
    for name, value in (
        ("file", file),
        ("title", title),
        ("rationale", rationale),
        ("attack_plan", attack_plan),
    ):
        if not isinstance(value, str) or not value.strip():
            return ToolResult(ok=False, error=f"{name} must be a non-empty string")
    try:
        line_number = int(line)
    except (TypeError, ValueError):
        return ToolResult(ok=False, error="line must be an integer")

    hypothesis = Hypothesis(
        vuln_class=vuln_class,
        file=file,
        line=line_number,
        title=title.strip(),
        rationale=rationale.strip(),
        attack_plan=attack_plan.strip(),
    )
    sandbox.hypotheses.append(hypothesis)
    return ToolResult(
        ok=True,
        content=(
            f"Recorded hypothesis #{len(sandbox.hypotheses)} ({vuln_class} at "
            f"{file}:{line_number}). Recorded, not verified — only an attack "
            f"observed by an oracle can close it. Now execute the attack plan "
            f"with http_request."
        ),
        meta={"index": len(sandbox.hypotheses), "vuln_class": vuln_class},
    )


# --------------------------------------------------------------------------
# schemas + dispatch
# --------------------------------------------------------------------------


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": (
            "Read a source file from the target application, with line numbers. "
            "Paths are relative to the source root; a directory returns a listing."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path relative to the source root, e.g. 'routes/notes.py'.",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "search_code",
        "description": (
            "Search the target source with a Python regular expression, matched "
            "per line. Returns file:line for each match."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": f"Regular expression, at most {MAX_PATTERN_CHARS} characters.",
                },
                "glob": {
                    "type": "string",
                    "description": "Filename glob to scan, e.g. '*.py'. Defaults to '*.py'.",
                },
                "max_results": {
                    "type": "integer",
                    "description": f"Maximum matches to return (cap {MAX_MATCHES}).",
                },
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "http_request",
        "description": (
            "Send one HTTP request to the running target and return its response. "
            "You supply a path, never a URL: the host is fixed to the target and "
            "cannot be changed. To make the target fetch an out-of-band URL, put "
            f"the literal token {CALLBACK_TOKEN} in the query or body — the harness "
            "substitutes a one-time probe URL and records whether the target "
            "contacted it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": list(ALLOWED_METHODS)},
                "path": {
                    "type": "string",
                    "description": "Request path starting with '/', e.g. '/api/notes/1002'.",
                },
                "query": {
                    "type": "object",
                    "description": "Query-string parameters as a flat object.",
                },
                "json_body": {
                    "type": "object",
                    "description": "JSON request body, sent as application/json.",
                },
                "as_user": {
                    "type": "string",
                    "enum": list(IDENTITIES),
                    "description": (
                        "Which identity to send as. The harness attaches the "
                        "credential; you cannot forge one."
                    ),
                },
            },
            "required": ["method", "path"],
        },
    },
    {
        "name": "submit_hypothesis",
        "description": (
            "Record a vulnerability hypothesis before attacking it. Recording is "
            "not verifying: a deterministic oracle decides the outcome from what "
            "your attack actually did to the target."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_class": {"type": "string", "enum": sorted(ORACLES)},
                "file": {"type": "string", "description": "Source file the claim is about."},
                "line": {"type": "integer", "description": "Line number in that file."},
                "title": {"type": "string", "description": "One-line summary of the claim."},
                "rationale": {
                    "type": "string",
                    "description": "Why the code suggests this class of bug.",
                },
                "attack_plan": {
                    "type": "string",
                    "description": "The concrete requests you will send to test it.",
                },
            },
            "required": [
                "vuln_class",
                "file",
                "line",
                "title",
                "rationale",
                "attack_plan",
            ],
        },
    },
]

TOOL_NAMES = tuple(schema["name"] for schema in TOOL_SCHEMAS)

_HANDLERS = {
    "read_file": read_file,
    "search_code": search_code,
    "http_request": http_request,
    "submit_hypothesis": submit_hypothesis,
}


def dispatch(name: str, arguments: dict[str, Any], sandbox: Sandbox) -> ToolResult:
    """Route a tool call. A bad name or bad arguments is a result, never a raise."""
    handler = _HANDLERS.get(name)
    if handler is None:
        return ToolResult(ok=False, error=f"unknown tool {name!r}; expected one of {list(TOOL_NAMES)}")
    if not isinstance(arguments, dict):
        return ToolResult(ok=False, error=f"{name} arguments must be an object")

    try:
        if name == "http_request":
            return http_request(
                sandbox,
                arguments["method"],
                arguments["path"],
                query=arguments.get("query"),
                json_body=arguments.get("json_body"),
                as_user=arguments.get("as_user", "anonymous"),
            )
        if name == "submit_hypothesis":
            return submit_hypothesis(sandbox, **arguments)
        return handler(sandbox, **arguments)
    except (TypeError, KeyError) as exc:
        return ToolResult(ok=False, error=f"bad arguments for {name}: {exc}")
    except Exception as exc:  # noqa: BLE001 - a tool must not crash the agent loop
        return ToolResult(ok=False, error=f"{name} failed: {type(exc).__name__}: {exc}")
