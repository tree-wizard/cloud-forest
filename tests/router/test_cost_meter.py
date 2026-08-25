"""The cost meter feeds a graded number, so it gets tested like one.

Every dollar figure in the README comes out of `CostMeter`. These prove it counts
what the SDK reported, prices cache reads and writes at their real factors, bills
promotional rates while they last, and never quietly invents a price for a model
it does not know.
"""

from __future__ import annotations

from datetime import date
from types import SimpleNamespace

import pytest

from aisec.router import (
    CACHE_READ_FACTOR,
    CACHE_WRITE_FACTOR,
    INTRO_PRICES,
    PRICES,
    CostMeter,
    price_for,
)


def usage(i=0, o=0, cr=0, cw=0):
    return SimpleNamespace(
        input_tokens=i,
        output_tokens=o,
        cache_read_input_tokens=cr,
        cache_creation_input_tokens=cw,
    )


LIST_DAY = date(2027, 1, 1)  # after every promotional window below


def test_counters_are_the_sdk_s_numbers_not_an_estimate():
    meter = CostMeter()
    meter.record(usage(i=100, o=10, cr=5, cw=7), "claude-sonnet-5")
    meter.record(usage(i=200, o=20), "claude-sonnet-5")

    assert meter.requests == 2
    assert meter.totals() == {
        "input_tokens": 300,
        "output_tokens": 30,
        "cache_read_tokens": 5,
        "cache_write_tokens": 7,
    }


def test_cache_reads_and_writes_are_priced_at_their_own_factors():
    meter = CostMeter(priced_on=LIST_DAY)
    meter.record(usage(cr=1_000_000), "claude-sonnet-5")
    per_input, _ = PRICES["claude-sonnet-5"]

    assert meter.dollars() == pytest.approx(1_000_000 * per_input * CACHE_READ_FACTOR)

    writes = CostMeter(priced_on=LIST_DAY)
    writes.record(usage(cw=1_000_000), "claude-sonnet-5")
    assert writes.dollars() == pytest.approx(
        1_000_000 * per_input * CACHE_WRITE_FACTOR
    )


def test_promotional_rate_applies_inside_its_window_and_lapses_after():
    intro_rate, expires = INTRO_PRICES["claude-sonnet-5"]
    assert intro_rate < PRICES["claude-sonnet-5"]

    assert price_for("claude-sonnet-5", expires) == intro_rate
    assert price_for("claude-sonnet-5", date.fromordinal(expires.toordinal() + 1)) == (
        PRICES["claude-sonnet-5"]
    )

    during = CostMeter(priced_on=expires)
    during.record(usage(i=1_000_000), "claude-sonnet-5")
    after = CostMeter(priced_on=date.fromordinal(expires.toordinal() + 1))
    after.record(usage(i=1_000_000), "claude-sonnet-5")
    # The list-price meter would have overstated the run's real cost.
    assert during.dollars() < after.dollars()


def test_a_run_prices_every_request_on_one_day():
    """Fixed at construction, so a scan straddling a rate change stays coherent."""
    meter = CostMeter()
    assert meter.priced_on == date.today()
    assert meter.as_dict()["priced_on"] == date.today().isoformat()


def test_unknown_model_is_reported_by_name_never_guessed_at():
    meter = CostMeter()
    meter.record(usage(i=1_000_000, o=1_000_000), "claude-not-a-real-model")

    assert meter.dollars() == 0.0
    assert meter.as_dict()["unpriced_models"] == ["claude-not-a-real-model"]


def test_missing_or_null_usage_fields_are_zero_not_a_crash():
    meter = CostMeter()
    meter.record(None, "claude-sonnet-5")
    meter.record(SimpleNamespace(input_tokens=None, output_tokens="x"), "claude-sonnet-5")

    assert meter.requests == 2
    assert meter.dollars() == 0.0


def test_per_model_split_and_rates_are_reported():
    meter = CostMeter(priced_on=LIST_DAY)
    meter.record(usage(i=10, o=1), "claude-haiku-4-5")
    meter.record(usage(i=20, o=2), "claude-sonnet-5")

    snapshot = meter.as_dict()
    assert set(snapshot["per_model"]) == {"claude-haiku-4-5", "claude-sonnet-5"}
    assert snapshot["rates"]["claude-haiku-4-5"] == PRICES["claude-haiku-4-5"]
    assert snapshot["dollars"] == pytest.approx(meter.dollars(), rel=1e-9)
