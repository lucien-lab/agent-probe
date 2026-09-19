"""版本化价格表与费用估算测试：全程 ``Decimal``、缺失即 unknown、禁止 float。"""

from __future__ import annotations

import json
from datetime import date
from decimal import Decimal

import pytest

from agent_probe.llm.pricing import (
    DEFAULT_PRICE_TABLE,
    CostUnknownReason,
    ModelPrice,
    PriceTable,
    PricingUnit,
    estimate_cost,
)
from agent_probe.llm.usage import TokenUsage, UsageStatus, extract_usage_from_json

from llm.fixtures import openai_json_body

TABLE = PriceTable(
    version="test-2026-02-01",
    effective_date=date(2026, 2, 1),
    currency="USD",
    unit=PricingUnit.PER_MILLION_TOKENS,
    provenance="unit-test",
    verified=True,
    entries=(
        ModelPrice("gpt-4o-mini", "0.15", "0.60", cache_read_per_unit="0.075"),
        ModelPrice("gpt-4o", "2.50", "10.00", cache_read_per_unit="1.25"),
        ModelPrice("claude-3-5-sonnet", "3.00", "15.00", cache_read_per_unit="0.30", cache_write_per_unit="3.75"),
        ModelPrice("no-cache-model", "1", "2"),
    ),
)


def usage(**kwargs) -> TokenUsage:
    return TokenUsage(**kwargs)


def cost(usage_value: TokenUsage | None, table: PriceTable = TABLE, model: str | None = None, status: UsageStatus | None = None):
    resolved_status = status if status is not None else (
        UsageStatus.PRESENT if usage_value is not None else UsageStatus.ABSENT
    )
    return estimate_cost(
        usage=usage_value, usage_status=resolved_status, price_table=table, model=model
    )


# ----------------------------------------------------------------------
# 精确计算
# ----------------------------------------------------------------------


def test_cost_is_computed_exactly_with_decimals() -> None:
    estimate = cost(usage(model="gpt-4o-mini", input_tokens=1000, output_tokens=500, total_tokens=1500))
    assert estimate.complete
    assert estimate.total_cost == Decimal("0.00045")
    assert isinstance(estimate.total_cost, Decimal)
    assert estimate.currency == "USD"
    assert estimate.unit is PricingUnit.PER_MILLION_TOKENS
    assert estimate.effective_date == date(2026, 2, 1)
    assert estimate.price_table_version == "test-2026-02-01"
    assert estimate.matched_price_model == "gpt-4o-mini"
    assert {component.name for component in estimate.components} == {"input", "output"}


def test_no_float_appears_in_estimate_record() -> None:
    estimate = cost(usage(model="gpt-4o", input_tokens=1234567, output_tokens=7654321))
    record = estimate.to_record()

    def walk(value: object) -> None:
        assert not isinstance(value, float), f"出现 float: {value!r}"
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item)

    walk(record)
    assert isinstance(record["total_cost"], str)
    assert json.loads(json.dumps(record))["currency"] == "USD"


def test_decimal_arithmetic_has_no_binary_rounding() -> None:
    # 0.1 + 0.2 在 float 下不精确；Decimal 下必须精确。
    table = PriceTable(
        version="v",
        effective_date=date(2026, 1, 1),
        verified=True,
        entries=(ModelPrice("m", "100000", "100000"),),
    )
    estimate = cost(usage(model="m", input_tokens=1, output_tokens=2), table)
    assert estimate.total_cost == Decimal("0.3")


def test_per_thousand_unit_divisor() -> None:
    table = PriceTable(
        version="v",
        effective_date=date(2026, 1, 1),
        unit=PricingUnit.PER_THOUSAND_TOKENS,
        verified=True,
        entries=(ModelPrice("m", "0.5", "1.5"),),
    )
    estimate = cost(usage(model="m", input_tokens=100, output_tokens=200), table)
    assert estimate.total_cost == Decimal("0.35")


# ----------------------------------------------------------------------
# 模型匹配
# ----------------------------------------------------------------------


def test_exact_match_beats_prefix() -> None:
    estimate = cost(usage(model="gpt-4o", input_tokens=1_000_000, output_tokens=0))
    assert estimate.matched_price_model == "gpt-4o"
    assert estimate.total_cost == Decimal("2.50")


def test_longest_prefix_match_wins_for_versioned_model_ids() -> None:
    estimate = cost(usage(model="gpt-4o-mini-2024-07-18", input_tokens=1_000_000, output_tokens=0))
    assert estimate.matched_price_model == "gpt-4o-mini"
    assert estimate.total_cost == Decimal("0.15")


def test_prefix_must_end_on_a_boundary() -> None:
    estimate = cost(usage(model="gpt-4oX", input_tokens=10, output_tokens=10))
    assert estimate.complete is False
    assert estimate.total_cost is None
    assert estimate.unknown_reasons == (CostUnknownReason.MODEL_NOT_IN_PRICE_TABLE,)


def test_unknown_model_is_reported() -> None:
    estimate = cost(usage(input_tokens=10, output_tokens=10), model=None)
    assert estimate.unknown_reasons == (CostUnknownReason.MODEL_UNKNOWN,)
    assert estimate.is_unknown


def test_model_outside_the_table_is_reported() -> None:
    estimate = cost(usage(model="future-model", input_tokens=10, output_tokens=10))
    assert estimate.unknown_reasons == (CostUnknownReason.MODEL_NOT_IN_PRICE_TABLE,)
    assert estimate.total_cost is None


# ----------------------------------------------------------------------
# usage 缺失 / 不可用
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (UsageStatus.ABSENT, CostUnknownReason.USAGE_MISSING),
        (UsageStatus.UNPARSEABLE, CostUnknownReason.USAGE_UNPARSEABLE),
        (UsageStatus.NOT_CAPTURED, CostUnknownReason.USAGE_NOT_CAPTURED),
    ],
)
def test_missing_usage_yields_unknown_cost(status: UsageStatus, expected: CostUnknownReason) -> None:
    estimate = cost(None, status=status)
    assert estimate.complete is False
    assert estimate.total_cost is None
    assert estimate.priced_subtotal is None
    assert estimate.unknown_reasons == (expected,)
    assert estimate.is_unknown


def test_empty_usage_object_is_unknown() -> None:
    estimate = cost(usage(model="gpt-4o-mini"))
    assert estimate.unknown_reasons == (CostUnknownReason.USAGE_EMPTY,)
    assert estimate.total_cost is None


def test_partial_usage_missing_output_is_incomplete_but_has_subtotal() -> None:
    estimate = cost(usage(model="gpt-4o-mini", input_tokens=1_000_000))
    assert estimate.complete is False
    assert estimate.total_cost is None
    assert estimate.priced_subtotal == Decimal("0.15")
    assert estimate.unknown_reasons == (CostUnknownReason.OUTPUT_TOKENS_MISSING,)


def test_usage_extraction_feeds_estimate_directly() -> None:
    extraction = extract_usage_from_json(openai_json_body(prompt_tokens=1000, completion_tokens=500))
    estimate = estimate_cost(
        usage=extraction.usage, usage_status=extraction.status, price_table=TABLE
    )
    assert estimate.complete
    assert estimate.total_cost == Decimal("0.000450")


# ----------------------------------------------------------------------
# 缓存明细
# ----------------------------------------------------------------------


def test_cached_tokens_included_in_input_are_not_double_counted() -> None:
    estimate = cost(
        usage(
            model="gpt-4o-mini",
            input_tokens=1_000_000,
            output_tokens=0,
            cache_read_tokens=400_000,
            cache_read_included_in_input=True,
        )
    )
    assert estimate.complete
    by_name = {component.name: component for component in estimate.components}
    assert by_name["input"].tokens == 600_000
    assert by_name["cache_read"].tokens == 400_000
    assert estimate.total_cost == Decimal("0.09") + Decimal("0.03")


def test_anthropic_style_cache_tokens_are_added_on_top() -> None:
    estimate = cost(
        usage(
            model="claude-3-5-sonnet",
            input_tokens=1_000_000,
            output_tokens=0,
            cache_read_tokens=100_000,
            cache_write_tokens=50_000,
            cache_read_included_in_input=False,
            cache_write_included_in_input=False,
        )
    )
    assert estimate.complete
    assert estimate.total_cost == Decimal("3.00") + Decimal("0.03") + Decimal("0.1875")


def test_unknown_cache_inclusion_makes_cost_incomplete() -> None:
    estimate = cost(
        usage(
            model="gpt-4o-mini",
            input_tokens=1000,
            output_tokens=10,
            cache_read_tokens=100,
            cache_read_included_in_input=None,
        )
    )
    assert estimate.complete is False
    assert CostUnknownReason.CACHE_INCLUSION_UNKNOWN in estimate.unknown_reasons
    assert estimate.priced_subtotal is not None


def test_missing_cache_price_makes_cost_incomplete() -> None:
    estimate = cost(
        usage(
            model="no-cache-model",
            input_tokens=1000,
            output_tokens=10,
            cache_read_tokens=100,
            cache_read_included_in_input=True,
        )
    )
    assert estimate.complete is False
    assert CostUnknownReason.CACHE_PRICE_MISSING in estimate.unknown_reasons


def test_cache_read_exceeding_input_is_clamped_with_a_note() -> None:
    estimate = cost(
        usage(
            model="gpt-4o-mini",
            input_tokens=10,
            output_tokens=1,
            cache_read_tokens=100,
            cache_read_included_in_input=True,
        )
    )
    by_name = {component.name: component for component in estimate.components}
    assert by_name["input"].tokens == 0
    assert by_name["cache_read"].tokens == 100
    assert any("大于" in note for note in estimate.notes)


def test_usage_from_message_with_transport_truncation_still_prices_what_it_has() -> None:
    estimate = cost(usage(model="gpt-4o-mini", input_tokens=1000, output_tokens=100))
    assert estimate.complete and estimate.total_cost is not None


# ----------------------------------------------------------------------
# 价格表自身
# ----------------------------------------------------------------------


def test_float_price_is_rejected() -> None:
    with pytest.raises(TypeError):
        ModelPrice("m", 0.15, 0.6)  # type: ignore[arg-type]


def test_float_in_price_table_mapping_is_rejected() -> None:
    with pytest.raises(TypeError):
        PriceTable.from_mapping(
            {
                "version": "v",
                "effective_date": "2026-01-01",
                "models": [{"model": "m", "input_per_unit": 0.15, "output_per_unit": "0.6"}],
            }
        )


def test_price_table_json_round_trip() -> None:
    text = TABLE.to_json(indent=2)
    restored = PriceTable.from_json(text)
    assert restored.version == TABLE.version
    assert restored.effective_date == TABLE.effective_date
    assert restored.currency == TABLE.currency
    assert restored.unit is TABLE.unit
    assert restored.verified is True
    assert restored.find("gpt-4o-mini") == TABLE.find("gpt-4o-mini")


def test_price_table_requires_version_and_date() -> None:
    with pytest.raises(ValueError):
        PriceTable(version="", effective_date=date(2026, 1, 1))
    with pytest.raises(TypeError):
        PriceTable(version="v", effective_date="2026-01-01")  # type: ignore[arg-type]


def test_find_returns_none_for_missing_model() -> None:
    assert TABLE.find(None) is None
    assert TABLE.find("nope") is None


def test_builtin_price_table_is_marked_unverified_and_carries_metadata() -> None:
    assert DEFAULT_PRICE_TABLE.verified is False
    assert DEFAULT_PRICE_TABLE.version
    assert DEFAULT_PRICE_TABLE.provenance
    assert DEFAULT_PRICE_TABLE.currency == "USD"
    estimate = estimate_cost(
        usage=TokenUsage(model="gpt-4o-mini", input_tokens=1, output_tokens=1),
        usage_status=UsageStatus.PRESENT,
        price_table=DEFAULT_PRICE_TABLE,
    )
    assert estimate.price_table_verified is False
    assert any("未核验" in note for note in estimate.notes)


def test_verified_table_has_no_unverified_note() -> None:
    estimate = cost(usage(model="gpt-4o-mini", input_tokens=1, output_tokens=1))
    assert estimate.notes == ()
