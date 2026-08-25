# Run transcripts

Raw output of the live runs the README and `RESULTS.md` quote. Committed as
evidence: every number in the write-up should be findable here.

| file | what produced it |
| --- | --- |
| `scan-sonnet-5.txt` | `aisec scan ./notes-app` — the transcript at the top of the README |
| `eval-sonnet-5.txt` | `aisec eval --report evals/RESULTS.md` — the benchmark run |
| `eval-haiku-4-5.txt` | `aisec eval --model claude-haiku-4-5` — the cross-model comparison |
| `security-tests-against-patched-target.txt` | `pytest .security-tests/` against a target with all three bugs fixed — every generated test goes red, which is the check that a regression test is worth committing |

## Two kinds of artifact

Since the run archive landed, this directory holds both:

* **`*.txt`** — human-readable transcripts, saved by hand with a shell redirect.
  What a run looked like.
* **`*.json`** — machine records, written automatically by every `aisec eval` run
  (`aisec/runlog.py`). One file per run, named `<UTC timestamp>-<model>.json`, and
  **never overwritten**: a name collision gets a `-2` suffix rather than replacing
  its predecessor. Each carries the run id, UTC start/finish, git sha and dirty
  flag, the argv, the `--case`/`--kind` selection, every metric verbatim from
  `SuiteResult.metrics()`, and the full cost meter including `priced_on` and the
  per-model rates — so a dollar figure in the write-up can be audited back to the
  prices it was computed with.

`evals/RESULTS.md` is a *view* of the newest full run, not the only copy of it. It
is still truncated on every `--report`, which is now safe: the evidence it was
built from is in the archive. `--report` on its default path refuses a filtered
(`--case`/`--kind`) or cap-stopped run, because those are a subset's numbers and
the file reads as the suite's.

The cumulative spend line in `RESULTS.md` is summed from the `*.json` files here.
**The archive starts empty**, so it does not include the six runs that produced the
numbers in the README — those predate it and are not backfilled, because a record
nobody measured is not evidence. The ledger will read low until enough runs
accumulate; the `.txt` transcripts remain the record for everything before it.
