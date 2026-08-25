"""Model routing, the sha256(contents) analysis cache, and the cost meter.

Phase 4 landed the meter. Phase 5 — routing and the sha256 analysis cache — was
cut; see the README's decision log for why the cache in particular did not
survive contact with a single-conversation tool loop. So this module is the cost
meter, and the name is now a little bigger than the contents.

It is here rather than in `agent.py` because the README's cost log has to be fed
by something that measured a real run rather than something that estimated one:
`record` reads the SDK's usage object and nothing in this file guesses.

The prices are per-token, from the published per-million rates, and include
promotional rates while they are in force — the meter reports what the account is
charged, not what the list price would suggest. Cached input is
billed at a fraction of the input rate and cache *writes* at a premium, so a meter
that ignored them would overstate the cost of a well-cached scan — which is the
number the submission is graded on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


# ($ per input token, $ per output token), from the published per-million rates.
PRICES: dict[str, tuple[float, float]] = {
    "claude-haiku-4-5": (1.00e-6, 5.00e-6),
    "claude-sonnet-5": (3.00e-6, 15.00e-6),
    "claude-opus-5": (5.00e-6, 25.00e-6),
}

# Promotional rates that are what an account is actually charged while they last.
# Billing Sonnet 5 at list during its introductory window would overstate this
# project's spend by ~1.5x — a flattering error, which is the kind a cost log has
# to correct rather than round in its own favour.
INTRO_PRICES: dict[str, tuple[tuple[float, float], date]] = {
    "claude-sonnet-5": ((2.00e-6, 10.00e-6), date(2026, 8, 31)),
}


def price_for(model: str, on: date) -> tuple[float, float] | None:
    """The rate really in force for `model` on `on`, or None if unpriced."""
    intro = INTRO_PRICES.get(model)
    if intro is not None and on <= intro[1]:
        return intro[0]
    return PRICES.get(model)


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
    # Fixed at construction so a run that straddles midnight, or the end of a
    # promotional window, prices every request in it the same way.
    priced_on: date = field(default_factory=date.today)

    def record(self, usage: object, model: str) -> None:
        self.requests += 1
        bucket = self.per_model.setdefault(model, dict.fromkeys(_COUNTERS, 0))
        bucket["input_tokens"] += _count(usage, "input_tokens")
        bucket["output_tokens"] += _count(usage, "output_tokens")
        bucket["cache_read_tokens"] += _count(usage, "cache_read_input_tokens")
        bucket["cache_write_tokens"] += _count(usage, "cache_creation_input_tokens")
        if price_for(model, self.priced_on) is None:
            self.unpriced_models.add(model)

    def dollars(self) -> float:
        total = 0.0
        for model, bucket in self.per_model.items():
            price = price_for(model, self.priced_on)
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
            "priced_on": self.priced_on.isoformat(),
            "rates": {
                model: price_for(model, self.priced_on)
                for model in sorted(self.per_model)
            },
        }


def _count(usage: object, name: str) -> int:
    """One usage counter, defaulting to 0. A missing or null field is not a crash."""
    value = getattr(usage, name, 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
