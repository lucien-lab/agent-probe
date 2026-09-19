"""版本化价格表与费用估算（全程 ``Decimal``，禁止 ``float``）。

口径（对应 plan.md M1："使用版本化价格表估算费用，记录币种、计价单位与日期；
不宣称等于实际账单"）：

* 价格表带 ``version`` / ``effective_date`` / ``currency`` / ``unit`` /
  ``provenance`` / ``verified``。``verified=False`` 表示该表**未核验**，
  估算结果会带提示，不得用于账单对照。
* 估算结果记录所用价格表的版本与日期，并给出 ``complete`` 与 ``unknown_reasons``。
  usage 缺失、模型不在价格表中、缓存明细包含关系未知时，``total_cost`` 为
  ``None``（unknown），**不会**用 0 或部分金额冒充总额；部分金额另放在
  ``priced_subtotal`` 中并显式标注。
* 所有金额均为 :class:`decimal.Decimal`；序列化时转为字符串，避免任何浮点误差。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
from enum import Enum
from typing import Any, Mapping, Sequence

from agent_probe.llm.usage import TokenUsage, UsageStatus

__all__ = [
    "PricingUnit",
    "CostUnknownReason",
    "ModelPrice",
    "PriceTable",
    "CostComponent",
    "CostEstimate",
    "DEFAULT_PRICE_TABLE",
    "estimate_cost",
]


class PricingUnit(str, Enum):
    """计价单位。"""

    PER_MILLION_TOKENS = "per_1m_tokens"
    PER_THOUSAND_TOKENS = "per_1k_tokens"


_UNIT_DIVISOR: dict[PricingUnit, Decimal] = {
    PricingUnit.PER_MILLION_TOKENS: Decimal(1_000_000),
    PricingUnit.PER_THOUSAND_TOKENS: Decimal(1_000),
}


class CostUnknownReason(str, Enum):
    """费用未知/不完整的原因（稳定标识，供报告聚合）。"""

    USAGE_MISSING = "usage_missing"
    USAGE_EMPTY = "usage_empty"
    USAGE_UNPARSEABLE = "usage_unparseable"
    USAGE_NOT_CAPTURED = "usage_not_captured"
    MODEL_UNKNOWN = "model_unknown"
    MODEL_NOT_IN_PRICE_TABLE = "model_not_in_price_table"
    INPUT_TOKENS_MISSING = "input_tokens_missing"
    OUTPUT_TOKENS_MISSING = "output_tokens_missing"
    CACHE_PRICE_MISSING = "cache_price_missing"
    CACHE_INCLUSION_UNKNOWN = "cache_inclusion_unknown"


def _to_decimal(value: object, field_name: str) -> Decimal:
    """把价格输入统一成 ``Decimal``；显式拒绝 ``float``。"""
    if isinstance(value, Decimal):
        return value
    if isinstance(value, bool):
        raise TypeError(f"{field_name} 不接受 bool")
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, str):
        try:
            return Decimal(value)
        except ArithmeticError as exc:  # pragma: no cover - Decimal 的非法字面量
            raise ValueError(f"{field_name} 不是合法十进制字面量: {value!r}") from exc
    raise TypeError(
        f"{field_name} 必须是 Decimal/int/str（禁止 float 以免引入二进制误差），"
        f"得到 {type(value).__name__}"
    )


@dataclass(frozen=True)
class ModelPrice:
    """单个模型的单价（按 ``PriceTable.unit`` 计价）。"""

    model: str
    input_per_unit: Decimal
    output_per_unit: Decimal
    cache_read_per_unit: Decimal | None = None
    cache_write_per_unit: Decimal | None = None

    def __post_init__(self) -> None:
        if not self.model:
            raise ValueError("model 不能为空")
        object.__setattr__(self, "input_per_unit", _to_decimal(self.input_per_unit, "input_per_unit"))
        object.__setattr__(
            self, "output_per_unit", _to_decimal(self.output_per_unit, "output_per_unit")
        )
        if self.cache_read_per_unit is not None:
            object.__setattr__(
                self,
                "cache_read_per_unit",
                _to_decimal(self.cache_read_per_unit, "cache_read_per_unit"),
            )
        if self.cache_write_per_unit is not None:
            object.__setattr__(
                self,
                "cache_write_per_unit",
                _to_decimal(self.cache_write_per_unit, "cache_write_per_unit"),
            )

    def to_record(self) -> dict[str, object]:
        return {
            "model": self.model,
            "input_per_unit": str(self.input_per_unit),
            "output_per_unit": str(self.output_per_unit),
            "cache_read_per_unit": None
            if self.cache_read_per_unit is None
            else str(self.cache_read_per_unit),
            "cache_write_per_unit": None
            if self.cache_write_per_unit is None
            else str(self.cache_write_per_unit),
        }


def _normalize(model: str) -> str:
    return model.strip().lower()


def _matches(entry_model: str, model: str) -> bool:
    """前缀匹配，要求边界字符（避免 ``gpt-4o`` 误匹配 ``gpt-4oX``）。"""
    entry = _normalize(entry_model)
    target = _normalize(model)
    if target == entry:
        return True
    if not target.startswith(entry):
        return False
    return target[len(entry)] in "-.:@/"


@dataclass(frozen=True)
class PriceTable:
    """版本化价格表。"""

    version: str
    effective_date: date
    entries: tuple[ModelPrice, ...] = ()
    currency: str = "USD"
    unit: PricingUnit = PricingUnit.PER_MILLION_TOKENS
    provenance: str = ""
    verified: bool = False

    def __post_init__(self) -> None:
        if not self.version:
            raise ValueError("价格表必须有 version")
        if not isinstance(self.effective_date, date):
            raise TypeError("effective_date 必须是 datetime.date")
        if not self.currency:
            raise ValueError("价格表必须有 currency")
        if not isinstance(self.unit, PricingUnit):
            object.__setattr__(self, "unit", PricingUnit(self.unit))
        object.__setattr__(self, "entries", tuple(self.entries))

    def find(self, model: str | None) -> ModelPrice | None:
        """精确匹配优先，其次最长前缀匹配。"""
        if not model:
            return None
        exact = [entry for entry in self.entries if _normalize(entry.model) == _normalize(model)]
        if exact:
            return exact[0]
        prefix_matches = [entry for entry in self.entries if _matches(entry.model, model)]
        if not prefix_matches:
            return None
        return max(prefix_matches, key=lambda entry: len(entry.model))

    def to_record(self) -> dict[str, object]:
        return {
            "version": self.version,
            "effective_date": self.effective_date.isoformat(),
            "currency": self.currency,
            "unit": self.unit.value,
            "provenance": self.provenance,
            "verified": self.verified,
            "models": [entry.to_record() for entry in self.entries],
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_record(), ensure_ascii=False, indent=indent, sort_keys=True)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> PriceTable:
        """从映射/JSON 对象构造。价格值必须是字符串或整数（拒绝浮点字面量）。"""
        raw_entries = data.get("models", data.get("entries", ()))
        if not isinstance(raw_entries, Sequence) or isinstance(raw_entries, (str, bytes)):
            raise TypeError("models 必须是数组")
        entries = []
        for raw in raw_entries:
            if not isinstance(raw, Mapping):
                raise TypeError("models 的每一项必须是对象")
            entries.append(
                ModelPrice(
                    model=str(raw["model"]),
                    input_per_unit=raw["input_per_unit"],  # type: ignore[arg-type]
                    output_per_unit=raw["output_per_unit"],  # type: ignore[arg-type]
                    cache_read_per_unit=raw.get("cache_read_per_unit"),  # type: ignore[arg-type]
                    cache_write_per_unit=raw.get("cache_write_per_unit"),  # type: ignore[arg-type]
                )
            )
        effective = data.get("effective_date")
        if not isinstance(effective, str):
            raise TypeError("effective_date 必须是 ISO 日期字符串")
        return cls(
            version=str(data["version"]),
            effective_date=date.fromisoformat(effective),
            entries=tuple(entries),
            currency=str(data.get("currency", "USD")),
            unit=PricingUnit(str(data.get("unit", PricingUnit.PER_MILLION_TOKENS.value))),
            provenance=str(data.get("provenance", "")),
            verified=bool(data.get("verified", False)),
        )

    @classmethod
    def from_json(cls, text: str) -> PriceTable:
        parsed = json.loads(text)
        if not isinstance(parsed, Mapping):
            raise TypeError("价格表 JSON 顶层必须是对象")
        return cls.from_mapping(parsed)


@dataclass(frozen=True)
class CostComponent:
    """一个计价分项。"""

    name: str
    tokens: int
    unit_price: Decimal
    cost: Decimal

    def to_record(self) -> dict[str, object]:
        return {
            "name": self.name,
            "tokens": self.tokens,
            "unit_price": str(self.unit_price),
            "cost": str(self.cost),
        }


@dataclass(frozen=True)
class CostEstimate:
    """费用估算结果。``total_cost is None`` 表示 unknown（不得当作 0）。"""

    currency: str
    unit: PricingUnit
    effective_date: date
    price_table_version: str
    price_table_verified: bool
    usage_status: UsageStatus
    model: str | None = None
    matched_price_model: str | None = None
    components: tuple[CostComponent, ...] = ()
    priced_subtotal: Decimal | None = None
    total_cost: Decimal | None = None
    complete: bool = False
    unknown_reasons: tuple[CostUnknownReason, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_unknown(self) -> bool:
        """总额是否未知（而非 0）。"""
        return self.total_cost is None

    def to_record(self) -> dict[str, object]:
        return {
            "currency": self.currency,
            "unit": self.unit.value,
            "effective_date": self.effective_date.isoformat(),
            "price_table_version": self.price_table_version,
            "price_table_verified": self.price_table_verified,
            "usage_status": self.usage_status.value,
            "model": self.model,
            "matched_price_model": self.matched_price_model,
            "components": [component.to_record() for component in self.components],
            "priced_subtotal": None if self.priced_subtotal is None else str(self.priced_subtotal),
            "total_cost": None if self.total_cost is None else str(self.total_cost),
            "complete": self.complete,
            "unknown_reasons": [reason.value for reason in self.unknown_reasons],
            "notes": list(self.notes),
        }


def _unit_cost(tokens: int, unit_price: Decimal, divisor: Decimal) -> Decimal:
    """精确计算：``tokens`` 为整数、``divisor`` 为 10 的幂，除法无舍入误差。"""
    return (Decimal(tokens) * unit_price) / divisor


def _ordered_unique(reasons: Sequence[CostUnknownReason]) -> tuple[CostUnknownReason, ...]:
    seen: list[CostUnknownReason] = []
    for reason in reasons:
        if reason not in seen:
            seen.append(reason)
    return tuple(seen)


def estimate_cost(
    *,
    usage: TokenUsage | None,
    usage_status: UsageStatus,
    price_table: PriceTable,
    model: str | None = None,
) -> CostEstimate:
    """按版本化价格表估算费用。

    ``usage_status`` 必须是调用方对 usage 可得性的判断；只有
    ``UsageStatus.PRESENT`` 且 ``usage`` 非空时才会尝试计价。
    """
    divisor = _UNIT_DIVISOR[price_table.unit]
    notes: list[str] = []
    if not price_table.verified:
        notes.append(
            "价格表 verified=False（未核验），仅供离线估算，不得用于账单对照"
            f"（version={price_table.version}）"
        )

    def _unknown(reasons: Sequence[CostUnknownReason], model_name: str | None) -> CostEstimate:
        return CostEstimate(
            currency=price_table.currency,
            unit=price_table.unit,
            effective_date=price_table.effective_date,
            price_table_version=price_table.version,
            price_table_verified=price_table.verified,
            usage_status=usage_status,
            model=model_name,
            components=(),
            priced_subtotal=None,
            total_cost=None,
            complete=False,
            unknown_reasons=_ordered_unique(reasons),
            notes=tuple(notes),
        )

    if usage is None or usage_status is not UsageStatus.PRESENT:
        reason = {
            UsageStatus.ABSENT: CostUnknownReason.USAGE_MISSING,
            UsageStatus.UNPARSEABLE: CostUnknownReason.USAGE_UNPARSEABLE,
            UsageStatus.NOT_CAPTURED: CostUnknownReason.USAGE_NOT_CAPTURED,
            UsageStatus.PRESENT: CostUnknownReason.USAGE_MISSING,
        }[usage_status]
        return _unknown((reason,), usage.model if usage is not None else model)

    assert usage is not None
    resolved_model = usage.model or model
    if usage.is_empty:
        return _unknown((CostUnknownReason.USAGE_EMPTY,), resolved_model)

    matched = price_table.find(resolved_model)
    if resolved_model is None:
        return _unknown((CostUnknownReason.MODEL_UNKNOWN,), None)
    if matched is None:
        return _unknown((CostUnknownReason.MODEL_NOT_IN_PRICE_TABLE,), resolved_model)

    reasons: list[CostUnknownReason] = []
    components: list[CostComponent] = []

    input_tokens = usage.input_tokens
    output_tokens = usage.output_tokens
    cache_read = usage.cache_read_tokens
    cache_write = usage.cache_write_tokens

    if input_tokens is None and cache_read is None and cache_write is None:
        reasons.append(CostUnknownReason.INPUT_TOKENS_MISSING)
    if output_tokens is None and input_tokens is not None:
        reasons.append(CostUnknownReason.OUTPUT_TOKENS_MISSING)

    if input_tokens is not None:
        billed_input = input_tokens
        if cache_read is not None and usage.cache_read_included_in_input is True:
            billed_input = max(0, input_tokens - cache_read)
            if input_tokens - cache_read < 0:
                notes.append("cache_read_tokens 大于 input_tokens，按 0 计并保留原始值")
        components.append(
            CostComponent(
                name="input",
                tokens=billed_input,
                unit_price=matched.input_per_unit,
                cost=_unit_cost(billed_input, matched.input_per_unit, divisor),
            )
        )
    if output_tokens is not None:
        components.append(
            CostComponent(
                name="output",
                tokens=output_tokens,
                unit_price=matched.output_per_unit,
                cost=_unit_cost(output_tokens, matched.output_per_unit, divisor),
            )
        )
    if cache_read is not None:
        if usage.cache_read_included_in_input is None:
            reasons.append(CostUnknownReason.CACHE_INCLUSION_UNKNOWN)
        if matched.cache_read_per_unit is None:
            reasons.append(CostUnknownReason.CACHE_PRICE_MISSING)
        else:
            components.append(
                CostComponent(
                    name="cache_read",
                    tokens=cache_read,
                    unit_price=matched.cache_read_per_unit,
                    cost=_unit_cost(cache_read, matched.cache_read_per_unit, divisor),
                )
            )
    if cache_write is not None:
        if usage.cache_write_included_in_input is None:
            reasons.append(CostUnknownReason.CACHE_INCLUSION_UNKNOWN)
        if matched.cache_write_per_unit is None:
            reasons.append(CostUnknownReason.CACHE_PRICE_MISSING)
        else:
            components.append(
                CostComponent(
                    name="cache_write",
                    tokens=cache_write,
                    unit_price=matched.cache_write_per_unit,
                    cost=_unit_cost(cache_write, matched.cache_write_per_unit, divisor),
                )
            )

    subtotal: Decimal | None = None
    if components:
        subtotal = sum((component.cost for component in components), Decimal(0))
    complete = not reasons
    return CostEstimate(
        currency=price_table.currency,
        unit=price_table.unit,
        effective_date=price_table.effective_date,
        price_table_version=price_table.version,
        price_table_verified=price_table.verified,
        usage_status=usage_status,
        model=resolved_model,
        matched_price_model=matched.model,
        components=tuple(components),
        priced_subtotal=subtotal,
        total_cost=subtotal if complete else None,
        complete=complete,
        unknown_reasons=_ordered_unique(reasons),
        notes=tuple(notes),
    )


#: 内置离线价格表。
#:
#: **注意**：这些数值仅用于离线夹具与格式演示，本里程碑**未**做厂商核验，
#: 因此 ``verified=False``。任何账单对照都必须换成本项目自行核验、
#: 带日期的价格表（见 docs/01-llm.md）。
DEFAULT_PRICE_TABLE = PriceTable(
    version="builtin-fixture-2026-01-01",
    effective_date=date(2026, 1, 1),
    currency="USD",
    unit=PricingUnit.PER_MILLION_TOKENS,
    provenance=(
        "内置离线夹具价格：用于单元测试与费用格式演示；未在本里程碑核验，"
        "不得作为账单依据。"
    ),
    verified=False,
    entries=(
        ModelPrice(
            model="gpt-4o-mini",
            input_per_unit=Decimal("0.15"),
            output_per_unit=Decimal("0.60"),
            cache_read_per_unit=Decimal("0.075"),
        ),
        ModelPrice(
            model="gpt-4o",
            input_per_unit=Decimal("2.50"),
            output_per_unit=Decimal("10.00"),
            cache_read_per_unit=Decimal("1.25"),
        ),
        ModelPrice(
            model="claude-3-5-sonnet",
            input_per_unit=Decimal("3.00"),
            output_per_unit=Decimal("15.00"),
            cache_read_per_unit=Decimal("0.30"),
            cache_write_per_unit=Decimal("3.75"),
        ),
    ),
)
