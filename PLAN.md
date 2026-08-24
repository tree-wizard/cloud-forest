# Build plan

Scope discipline first: the brief says *a few hours of hands-on work* and *a small,
sharp, working thing beats an ambitious broken one*. This is an MVP with one sharp
claim — **findings are executed, not asserted** — and everything else is cut.

## In scope

- Vulnerable target app (Flask) with 3 real bugs, 3 false-positive traps, and
  2 prompt-injection surfaces.
- Agent loop: `read_file`, `search_code`, `http_request`, `submit_hypothesis`.
- 3 deterministic oracles: IDOR, path traversal, SSRF.
- Regression-test generation for verified findings.
- Eval harness with true-positive / false-positive / adversarial cases + real cost
  accounting.
- Model routing (Haiku → Sonnet → Opus-on-failure) and a `sha256(file)` analysis cache.

## Explicitly out of scope

No web UI. No multi-repo support. No auth beyond the target's seeded users. No
SAST integration. No agent memory across runs beyond the file cache. No classes
beyond the three — extra bug types exist only as traps to be *rejected*.

## Phases

| # | Phase | Output | Est. |
| - | --- | --- | --- |
| 0 | Scaffold | repo layout, `aisec` CLI stub | 20m |
| 1 | Target app | routes + seeded data + canary + traps + injection bait | 45m |
| 2 | Oracles first | `oracles.py` + tests proving each fires on a hand-written exploit and stays silent otherwise | 40m |
| 3 | Tools | sandboxed `http_request` (host-pinned), `read_file`, `search_code`, callback server | 40m |
| 4 | Agent loop | Claude tool loop, untrusted-data fencing, hypothesis schema | 60m |
| 5 | Routing + cache + cost meter | `router.py`, sha256 cache, token/$ counters | 30m |
| 6 | Regression test emitter | templates → `.security-tests/test_*.py`, must pass `pytest` | 25m |
| 7 | Evals | yaml cases + `aisec eval` table + `evals/RESULTS.md` | 45m |
| 8 | README truth pass | real numbers, real cost log, the real astray-incident | 30m |

**Phase 2 before phase 4 is deliberate.** If the oracles land after the agent, there's a
strong pull to let the model's judgment stand in for them. Building them first means the
agent is written against an interface that never lets it self-certify.

## Definition of done

- `./notes-app/run.py && aisec scan ./notes-app` verifies all 3 real bugs.
- All 3 traps produce a hypothesis and a **REJECTED** verdict.
- Both injection cases: agent does not report a pass; the attempt is logged.
- `pytest .security-tests/` passes against the vulnerable target and *fails* if the bug
  is patched (that's the actual test of a regression test).
- `aisec eval` prints real, non-hardcoded metrics and cost.
- README's decision/cost/astray sections contain real content, not placeholders.

## Risks

- **Agent loops without converging** → hard caps on turns and per-scan dollars; a scan
  that hits the cap reports partial results rather than dying.
- **Flaky verification** → oracles read structured signals (owner ids, canary string,
  callback flag), never response prose.
- **Time overrun** → phases 5 and 6 are the drop candidates, in that order. Phases 1–4
  and 7 are the submission.

## Budget

$250 cap. Target: well under. Dev iteration is the real spend, not the demo runs —
so cache aggressively from phase 5 on, and run evals on Haiku/Sonnet while iterating,
reserving full-fidelity runs for the numbers that go in the README.
