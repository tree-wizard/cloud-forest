"""aisec CLI: `scan` runs the agent against a target, `eval` runs the benchmark suite.

`scan` is phase 4. It connects to an already-running target (it never starts one:
the agent is meant to be pointed at whatever is deployed), health-checks it, runs
the loop, and prints a transcript in the shape the README advertises. It exits 0
even on a partial scan — a hit cap is a result, not a failure.

`eval` (phase 7) runs the yaml benchmark under `evals/`: one scan per case against
the same running target, graded from oracle verdicts, with one cost meter across
the suite. It exits non-zero when a case fails, so it is usable as a gate — and
`--report` writes `evals/RESULTS.md` from the run that just happened, which is the
only way numbers get into that file.

Every eval run also leaves an immutable JSON record in `evals/runs/` (see
`aisec/runlog.py`), whether or not `--report` was passed: `RESULTS.md` is a single
slot that each report truncates, so the archive is what keeps a run's evidence
after the next run replaces the view of it. Because of that, `--report` on its
*default* path refuses a filtered or capped run rather than quietly publishing a
subset's numbers as the suite's.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from datetime import datetime, timezone

import httpx


DEFAULT_BASE_URL = "http://127.0.0.1:5001"
DEFAULT_REPORT_PATH = "evals/RESULTS.md"
DEFAULT_ARCHIVE_DIR = "evals/runs"


def _health_ok(base_url: str) -> bool:
    try:
        resp = httpx.get(f"{base_url}/health", timeout=3.0)
    except httpx.HTTPError:
        return False
    return resp.status_code == 200


def cmd_scan(args: argparse.Namespace) -> int:
    from aisec.agent import run_scan
    from aisec.callback import CallbackServer
    from aisec.emit import EmitError, emit_test
    from aisec.tools import Sandbox

    base_url = args.base_url
    if not _health_ok(base_url):
        print(
            f"target at {base_url} is not reachable.\n"
            f"start it first, e.g. ./notes-app/run.py, or pass --base-url.",
            file=sys.stderr,
        )
        return 2

    if not _api_key_present():
        print(
            "ANTHROPIC_API_KEY is not set. Export it (from the environment only) "
            "before scanning.",
            file=sys.stderr,
        )
        return 2

    with CallbackServer() as callback:
        sandbox = Sandbox.for_target(args.target, base_url, callback=callback)
        try:
            report = run_scan(
                sandbox,
                model=args.model,
                max_turns=args.max_turns,
                budget_usd=args.budget,
            )
            # Emit while the listener is still up: `Sandbox.scrub` needs it to
            # re-tokenize the probe URL, and a committed test must not carry a
            # dead port. A finding is a finding either way, so a template that
            # fails is reported, never fatal.
            emitted: dict[int, str] = {}
            if not args.no_tests:
                for index, finding in enumerate(report.findings):
                    if finding.status != "VERIFIED":
                        continue
                    try:
                        emitted[index] = str(
                            emit_test(finding, sandbox, args.tests_dir)
                        )
                    except (EmitError, OSError) as exc:
                        emitted[index] = f"(not written: {exc})"
        finally:
            sandbox.close()

    _print_report(report, emitted)
    return 0


def _print_report(report, emitted: dict[int, str] | None = None) -> None:
    print(f"\naisec scan {report.source_root}  (model {report.model})\n")

    emitted = emitted or {}
    for index, finding in enumerate(report.findings):
        hyp = finding.hypothesis
        print(f"[HYPOTHESIS] {hyp.title}   {hyp.file}:{hyp.line}")
        print("  testing...")
        for obs in finding.observations:
            ident = obs.sent_as or "anonymous"
            print(f"  {obs.method} {obs.url}  as {ident}  -> {obs.status}")
        v = finding.verdict
        print(f"  ORACLE  {v.oracle}: {v.invariant}   -> {v.status}")
        mark = "✓ VERIFIED" if finding.status == "VERIFIED" else "✗ REJECTED"
        print(f"  {mark}  {v.detail}")
        if index in emitted:
            print(f"  regression test written: {emitted[index]}")
        print()

    if report.injection_attempts:
        print(f"prompt-injection attempts logged: {len(report.injection_attempts)}")
        for attempt in report.injection_attempts:
            print(f"  [{attempt.tool}] {attempt.pattern} (turn {attempt.turn}) — ignored")
        print()

    verified = len(report.verified)
    rejected = len(report.rejected)
    totals = report.usage.get("totals", {})
    print(
        f"{verified} verified, {rejected} rejected, "
        f"{len(report.hypotheses)} hypotheses over {report.turns_used} turns, "
        f"{report.requests_made} requests."
    )
    print(
        f"tokens: {totals.get('input_tokens', 0)} in / "
        f"{totals.get('output_tokens', 0)} out"
        + (
            f", {totals.get('cache_read_tokens', 0)} cache-read"
            if totals.get("cache_read_tokens")
            else ""
        )
        + f"   cost: ${report.cost_usd:.4f}"
    )
    if report.partial:
        detail = f": {report.error}" if report.error else ""
        print(f"(partial scan — stopped on {report.stop_reason}{detail})")


def cmd_eval(args: argparse.Namespace) -> int:
    from aisec.evalsuite import (
        as_record,
        format_markdown,
        format_table,
        load_cases,
        run_suite,
    )
    from aisec.runlog import ledger, load_records, write_record

    try:
        cases = load_cases(args.cases)
    except (FileNotFoundError, ValueError) as exc:
        print(f"eval cases: {exc}", file=sys.stderr)
        return 2

    if args.case:
        wanted = set(args.case)
        unknown = wanted - {c.id for c in cases}
        if unknown:
            print(f"no such case(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        cases = [c for c in cases if c.id in wanted]
    if args.kind:
        cases = [c for c in cases if c.kind == args.kind]
    if not cases:
        print("no cases selected", file=sys.stderr)
        return 2

    if args.list:
        # Deliberately free: seeing what would run should never cost a token.
        for case in cases:
            print(f"{case.id:32} {case.kind:15} expect {case.expect:9} {case.source}")
        return 0

    base_url = args.base_url
    if not _health_ok(base_url):
        print(
            f"target at {base_url} is not reachable.\n"
            f"start it first, e.g. ./notes-app/run.py, or pass --base-url.",
            file=sys.stderr,
        )
        return 2
    if not _api_key_present():
        print(
            "ANTHROPIC_API_KEY is not set. Export it (from the environment only) "
            "before running the eval suite.",
            file=sys.stderr,
        )
        return 2

    def announce(result) -> None:
        mark = "PASS" if result.passed else "FAIL"
        print(
            f"  [{mark}] {result.case.id}: {result.outcome} — {result.reason} "
            f"(${result.cost_usd:.4f})",
            flush=True,
        )

    print(f"running {len(cases)} eval case(s) against {base_url}...", flush=True)
    started_at = datetime.now(timezone.utc).isoformat()
    suite = run_suite(
        cases,
        source_root=args.target,
        base_url=base_url,
        model=args.model,
        on_case=announce,
    )

    print()
    print(format_table(suite), end="", flush=True)

    # A run that spent money leaves evidence whether or not `--report` was asked
    # for. The archive is append-only, so this can never destroy a prior run.
    filtered = {k: v for k, v in (("case", args.case), ("kind", args.kind)) if v} or None
    record = as_record(
        suite,
        case_filter=filtered,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc).isoformat(),
    )
    archived: pathlib.Path | None = None
    try:
        archived = write_record(record, args.archive_dir)
        print(f"\narchived run to {archived}")
    except OSError as exc:
        print(f"\ncould not archive this run: {exc}", file=sys.stderr)

    if args.report:
        report_path = pathlib.Path(args.report)
        default_report = args.report == DEFAULT_REPORT_PATH
        # `--case`/`--kind` filtering happens above, before this write. Letting a
        # filtered or capped run land on the default path would replace the
        # suite's numbers with a subset's while the file still claimed to be the
        # suite. An explicit `--report PATH` is the user's call and still writes.
        refusal = None
        if default_report and filtered:
            refusal = "this run was filtered, so its numbers are not the suite's"
        elif default_report and suite.metrics()["partial_scans"]:
            refusal = "this run has scan(s) that stopped on a cap"
        if refusal:
            print(
                f"not writing {report_path}: {refusal}.\n"
                f"the full record is in {archived or 'the archive'}; pass an explicit "
                f"--report PATH to write it anyway.",
                file=sys.stderr,
            )
        else:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(
                format_markdown(
                    suite, record=record, spend=ledger(load_records(args.archive_dir))
                ),
                encoding="utf-8",
            )
            print(f"wrote {report_path}")

    return 0 if suite.metrics()["failed"] == 0 else 1


def _api_key_present() -> bool:
    import os

    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aisec")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan", help="hunt for and verify vulnerabilities in a target app"
    )
    scan_parser.add_argument("target", help="path to the target app source")
    scan_parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"running target base URL (default {DEFAULT_BASE_URL})",
    )
    scan_parser.add_argument(
        "--model", default="claude-sonnet-5", help="model id for the scan loop"
    )
    scan_parser.add_argument("--max-turns", type=int, default=24)
    scan_parser.add_argument(
        "--budget", type=float, default=5.0, help="per-scan dollar cap"
    )
    scan_parser.add_argument(
        "--tests-dir",
        default=".security-tests",
        help="where regression tests for verified findings are written "
        "(default .security-tests)",
    )
    scan_parser.add_argument(
        "--no-tests", action="store_true", help="verify only; write no test files"
    )
    scan_parser.set_defaults(func=cmd_scan)

    eval_parser = subparsers.add_parser(
        "eval", help="run the eval suite and report precision/recall/cost"
    )
    eval_parser.add_argument(
        "target", nargs="?", default="./notes-app", help="path to the target app source"
    )
    eval_parser.add_argument("--cases", default="evals", help="directory of yaml cases")
    eval_parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"running target base URL (default {DEFAULT_BASE_URL})",
    )
    eval_parser.add_argument(
        "--model", default="claude-sonnet-5", help="model id for every case"
    )
    eval_parser.add_argument(
        "--case", action="append", default=[], help="run only this case id (repeatable)"
    )
    eval_parser.add_argument(
        "--kind", choices=("true_positive", "false_positive", "adversarial")
    )
    eval_parser.add_argument(
        "--list", action="store_true", help="list the selected cases and exit, spending nothing"
    )
    eval_parser.add_argument(
        "--report",
        nargs="?",
        const=DEFAULT_REPORT_PATH,
        default=None,
        help="write markdown results to PATH (default evals/RESULTS.md); "
        "omit the flag and no file is touched",
    )
    eval_parser.add_argument(
        "--archive-dir",
        default=DEFAULT_ARCHIVE_DIR,
        help=f"append-only run archive (default {DEFAULT_ARCHIVE_DIR})",
    )
    eval_parser.set_defaults(func=cmd_eval)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
