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

---

## Status at submission

| # | Phase | Shipped? |
| - | --- | --- |
| 0–4 | Scaffold, target, oracles, tools, agent loop | yes |
| 5 | Routing + sha256 cache + cost meter | **cost meter only** — routing and the cache were cut; see the README's "Rejected" section for why the cache in particular didn't survive contact with a single-conversation tool loop, and the Haiku-vs-Sonnet measurement for why routing buys less than its per-token price implies |
| 6 | Regression test emitter | yes, in phase 8 |
| 7 | Evals | yes |
| 8 | Truth pass | yes — real runs, real numbers, transcripts in `evals/runs/` |

Definition of done, checked:

- `aisec scan ./notes-app` verifies all 3 real bugs — yes, and rejects a trap in the same
  run (`evals/runs/scan-sonnet-5.txt`).
- Traps produce hypotheses and REJECTED verdicts — yes; 0 false positives across 16 scans
  on two models.
- Both injection cases: bait logged, real bug still verified — yes, 2/2.
- `pytest .security-tests/` passes against the vulnerable target and fails when the bug is
  patched — yes, with one deliberate change of mechanism. The generated test asserts the
  *secure* invariant under `xfail(strict=True)` rather than asserting the exploit, so it
  is a usable CI regression test as well as a proof. Green on the vulnerable target,
  `XPASS(strict)` red on the patched one
  (`evals/runs/security-tests-against-patched-target.txt`).
- `aisec eval` prints real, non-hardcoded metrics and cost — yes, `evals/RESULTS.md`.
- README's decision/cost/astray sections contain real content — yes, including the
  incident where the README itself was the thing that had led me astray.

Spend against the $250 cap: **$2.30**, across six live runs. The dev loop was deliberately
offline — 195 tests, no API calls.
