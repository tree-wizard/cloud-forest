"""aisec CLI: `scan` runs the agent against a target, `eval` runs the benchmark suite.

`scan` is phase 4. It connects to an already-running target (it never starts one:
the agent is meant to be pointed at whatever is deployed), health-checks it, runs
the loop, and prints a transcript in the shape the README advertises. It exits 0
even on a partial scan — a hit cap is a result, not a failure. `eval` is still a
phase-7 stub.
"""

from __future__ import annotations

import argparse
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
    print("aisec eval: not yet implemented (phase 7)")
    return 1


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
    eval_parser.set_defaults(func=cmd_eval)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
