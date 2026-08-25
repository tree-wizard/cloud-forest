"""The run archive: one immutable JSON per eval run, plus the spend ledger.

`evals/RESULTS.md` is a single slot — every `aisec eval --report` truncated it, so
each run destroyed the evidence for the last one. This module is the append-only
half of that fix: `write_record` never overwrites, so the archive accumulates and
`RESULTS.md` becomes a *view* of the newest run rather than the only copy of it.

The ledger exists for the same reason the cost meter does. "$250 cap" is a graded
dimension, and the repo's rule is that its counters must be real; a total summed
from files on disk is measured, one carried in prose is remembered. Runs that
happened before this archive existed are not in it and are not invented here — the
ledger counts what it can see and says so.

Nothing in here is allowed to lose a run. A record is written after the API calls
that produced it have already been paid for, so every failure mode below degrades
to a warning: an unreadable file is skipped, a name collision gets a suffix.
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any, Iterable

DEFAULT_ARCHIVE_DIR = pathlib.Path("evals/runs")
# The challenge's API budget. Reported against, never enforced here.
BUDGET_USD = 250.0


def write_record(record: dict[str, Any], directory: str | pathlib.Path = DEFAULT_ARCHIVE_DIR) -> pathlib.Path:
    """Write one run record, refusing to clobber an existing one.

    A colliding `run_id` — two runs of the same model inside the same second —
    gets a `-2`, `-3` suffix rather than replacing its predecessor. This is the
    one file in the system that is never overwritten; `.security-tests/` is
    deliberately regenerated in place, and this is deliberately not.
    """
    out = pathlib.Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    stem = record.get("run_id") or "run"
    path = out / f"{stem}.json"
    suffix = 2
    while path.exists():
        path = out / f"{stem}-{suffix}.json"
        suffix += 1
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_records(directory: str | pathlib.Path = DEFAULT_ARCHIVE_DIR) -> list[dict[str, Any]]:
    """Every readable record, oldest first. A bad file is skipped, never fatal."""
    out = pathlib.Path(directory)
    if not out.is_dir():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(out.glob("*.json")):
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"runlog: skipping {path}: {exc}", file=sys.stderr)
            continue
        if not isinstance(loaded, dict) or "cost_usd" not in loaded:
            print(f"runlog: skipping {path}: not an aisec run record", file=sys.stderr)
            continue
        loaded.setdefault("_path", str(path))
        records.append(loaded)
    return sorted(records, key=lambda r: r.get("started_at") or "")


def ledger(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Cumulative spend over the archive. Summed, not estimated."""
    items = list(records)
    total = 0.0
    for record in items:
        try:
            total += float(record.get("cost_usd") or 0.0)
        except (TypeError, ValueError):
            continue
    return {
        "runs": len(items),
        "total_cost_usd": total,
        "budget_usd": BUDGET_USD,
        "first_run": items[0].get("started_at") if items else None,
        "last_run": items[-1].get("started_at") if items else None,
    }
