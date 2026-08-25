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
"""

from __future__ import annotations

import argparse
import pathlib
import sys

import httpx


DEFAULT_BASE_URL = "http://127.0.0.1:5000"


def _health_ok(base_url: str) -> bool:
    try:
        resp = httpx.get(f"{base_url}/health", timeout=3.0)
    except httpx.HTTPError:
        return False
    return resp.status_code == 200


def cmd_scan(args: argparse.Namespace) -> int:
    from aisec.agent import run_scan
    from aisec.callback import CallbackServer
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
        finally:
            sandbox.close()

    _print_report(report)
    return 0


def _print_report(report) -> None:
    print(f"\naisec scan {report.source_root}  (model {report.model})\n")

    for finding in report.findings:
        hyp = finding.hypothesis
        print(f"[HYPOTHESIS] {hyp.title}   {hyp.file}:{hyp.line}")
        print("  testing...")
        for obs in finding.observations:
            ident = obs.sent_as or "anonymous"
            print(f"  {obs.method} {obs.url}  as {ident}  -> {obs.status}")
        v = finding.verdict
        print(f"  ORACLE  {v.oracle}: {v.invariant}   -> {v.status}")
        mark = "✓ VERIFIED" if finding.status == "VERIFIED" else "✗ REJECTED"
        print(f"  {mark}  {v.detail}\n")

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
    from aisec.evalsuite import format_markdown, format_table, load_cases, run_suite

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
    suite = run_suite(
        cases,
        source_root=args.target,
        base_url=base_url,
        model=args.model,
        on_case=announce,
    )

    print()
    print(format_table(suite), end="")

    if args.report:
        report_path = pathlib.Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(format_markdown(suite), encoding="utf-8")
        print(f"\nwrote {report_path}")

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
        const="evals/RESULTS.md",
        default=None,
        help="write markdown results to PATH (default evals/RESULTS.md); "
        "omit the flag and no file is touched",
    )
    eval_parser.set_defaults(func=cmd_eval)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
