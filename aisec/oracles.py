"""Deterministic verdicts — the trust boundary.

The model never renders a verdict; these functions do, from structured signals
(owner ids, the canary string, the callback flag), never response prose.
Implemented in phase 2, before the agent loop exists to depend on it.
"""
