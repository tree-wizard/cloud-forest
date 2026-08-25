"""Model routing, the sha256(contents) analysis cache, and the cost meter.

Phase 4 lands the meter only. It is here rather than in `agent.py` because the
counters it produces are what phase 5's routing decisions will be judged by, and
because the README's cost log has to be fed by something that measured a real run
rather than something that estimated one. Phase 5 adds routing and the cache
alongside it; nothing here moves.

The prices are per-token, from the published per-million rates. Cached input is
billed at a fraction of the input rate and cache *writes* at a premium, so a meter
that ignored them would overstate the cost of a well-cached scan — which is the
number the submission is graded on.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ($ per input token, $ per output token)
PRICES: dict[str, tuple[float, float]] = {
    "claude-haiku-4-5": (1.00e-6, 5.00e-6),
    "claude-sonnet-5": (3.00e-6, 15.00e-6),
    "claude-opus-5": (5.00e-6, 25.00e-6),
}

CACHE_READ_FACTOR = 0.1
CACHE_WRITE_FACTOR = 1.25

_COUNTERS = ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens")


@dataclass
class CostMeter:
    """Real token and dollar counters for one scan.

    `record` reads its argument with `getattr`, so it accepts an SDK usage object
    or any stand-in with the same field names. Unknown models are metered at zero
    dollars and reported by name rather than silently priced at a guess.
    """

    requests: int = 0
    per_model: dict[str, dict[str, int]] = field(default_factory=dict)
    unpriced_models: set[str] = field(default_factory=set)

    def record(self, usage: object, model: str) -> None:
        self.requests += 1
        bucket = self.per_model.setdefault(model, dict.fromkeys(_COUNTERS, 0))
        bucket["input_tokens"] += _count(usage, "input_tokens")
        bucket["output_tokens"] += _count(usage, "output_tokens")
        bucket["cache_read_tokens"] += _count(usage, "cache_read_input_tokens")
        bucket["cache_write_tokens"] += _count(usage, "cache_creation_input_tokens")
        if model not in PRICES:
            self.unpriced_models.add(model)

    def dollars(self) -> float:
        total = 0.0
        for model, bucket in self.per_model.items():
            price = PRICES.get(model)
            if price is None:
                continue
            per_input, per_output = price
            total += bucket["input_tokens"] * per_input
            total += bucket["output_tokens"] * per_output
            total += bucket["cache_read_tokens"] * per_input * CACHE_READ_FACTOR
            total += bucket["cache_write_tokens"] * per_input * CACHE_WRITE_FACTOR
        return total

    def totals(self) -> dict[str, int]:
        combined = dict.fromkeys(_COUNTERS, 0)
        for bucket in self.per_model.values():
            for name in _COUNTERS:
                combined[name] += bucket[name]
        return combined

    def as_dict(self) -> dict:
        return {
            "requests": self.requests,
            "totals": self.totals(),
            "per_model": {m: dict(b) for m, b in self.per_model.items()},
            "dollars": round(self.dollars(), 6),
            "unpriced_models": sorted(self.unpriced_models),
        }


def _count(usage: object, name: str) -> int:
    """One usage counter, defaulting to 0. A missing or null field is not a crash."""
    value = getattr(usage, name, 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
