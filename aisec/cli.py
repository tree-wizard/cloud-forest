"""aisec CLI: `scan` runs the agent against a target, `eval` runs the benchmark suite.

Phase 0 stub — subcommands are wired but not yet implemented (phases 4 and 7).
"""

import argparse
import sys


def cmd_scan(args: argparse.Namespace) -> int:
    print(f"aisec scan: not yet implemented (target={args.target})")
    return 1


def cmd_eval(args: argparse.Namespace) -> int:
    print("aisec eval: not yet implemented")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aisec")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="hunt for and verify vulnerabilities in a target app")
    scan_parser.add_argument("target", help="path to the target app source")
    scan_parser.set_defaults(func=cmd_scan)

    eval_parser = subparsers.add_parser("eval", help="run the eval suite and report precision/recall/cost")
    eval_parser.set_defaults(func=cmd_eval)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
