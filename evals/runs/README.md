# Run transcripts

Raw output of the live runs the README and `RESULTS.md` quote. Committed as
evidence: every number in the write-up should be findable here.

| file | what produced it |
| --- | --- |
| `scan-sonnet-5.txt` | `aisec scan ./notes-app` — the transcript at the top of the README |
| `eval-sonnet-5.txt` | `aisec eval --report evals/RESULTS.md` — the benchmark run |
| `eval-haiku-4-5.txt` | `aisec eval --model claude-haiku-4-5` — the cross-model comparison |
| `security-tests-against-patched-target.txt` | `pytest .security-tests/` against a target with all three bugs fixed — every generated test goes red, which is the check that a regression test is worth committing |
