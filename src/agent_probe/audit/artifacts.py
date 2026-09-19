"""M4 成本审计的最小、可重放 calls artifact。"""
from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping

from .errors import AuditInputError

__all__ = ["CALLS_ARTIFACT_VERSION", "AuditableCall", "CallsArtifact", "load_calls_artifact"]
CALLS_ARTIFACT_VERSION = 1


def _decimal(value: object, name: str) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise AuditInputError(f"{name} 不能是 bool")
    try:
        return Decimal(str(value))
    except InvalidOperation as exc:
        raise AuditInputError(f"{name} 必须是十进制字符串或整数") from exc


@dataclass(frozen=True, slots=True)
class AuditableCall:
    physical_request_id: str
    run_id: str
    model: str | None = None
    agent: str | None = None
    task_id: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    currency: str | None = None
    total_cost: Decimal | None = None
    cost_complete: bool = False
    unknown_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.physical_request_id or not self.run_id:
            raise AuditInputError("call 的 physical_request_id 与 run_id 不能为空")
        for name in ("input_tokens", "output_tokens", "total_tokens"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise AuditInputError(f"{name} 必须是非负整数或 null")
        if self.total_cost is not None and not isinstance(self.total_cost, Decimal):
            object.__setattr__(self, "total_cost", _decimal(self.total_cost, "total_cost"))
        if self.cost_complete and (self.total_cost is None or not self.currency):
            raise AuditInputError("cost_complete=true 时必须有 currency 与 total_cost")
        object.__setattr__(self, "unknown_reasons", tuple(sorted(set(self.unknown_reasons))))

    def to_dict(self) -> dict[str, Any]:
        return {"physical_request_id": self.physical_request_id, "run_id": self.run_id,
                "model": self.model, "agent": self.agent, "task_id": self.task_id,
                "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "total_tokens": self.total_tokens, "currency": self.currency,
                "total_cost": None if self.total_cost is None else str(self.total_cost),
                "cost_complete": self.cost_complete, "unknown_reasons": list(self.unknown_reasons)}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "AuditableCall":
        allowed = {"physical_request_id", "run_id", "model", "agent", "task_id", "input_tokens", "output_tokens", "total_tokens", "currency", "total_cost", "cost_complete", "unknown_reasons"}
        if set(raw) - allowed:
            raise AuditInputError(f"call 有未知字段：{sorted(set(raw) - allowed)}")
        reasons = raw.get("unknown_reasons", ())
        if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
            raise AuditInputError("unknown_reasons 必须是字符串列表")
        return cls(physical_request_id=str(raw["physical_request_id"]), run_id=str(raw["run_id"]),
                   model=raw.get("model"), agent=raw.get("agent"), task_id=raw.get("task_id"),
                   input_tokens=raw.get("input_tokens"), output_tokens=raw.get("output_tokens"), total_tokens=raw.get("total_tokens"),
                   currency=raw.get("currency"), total_cost=_decimal(raw.get("total_cost"), "total_cost"),
                   cost_complete=bool(raw.get("cost_complete", False)), unknown_reasons=tuple(reasons))


@dataclass(frozen=True, slots=True)
class CallsArtifact:
    run_id: str
    calls: tuple[AuditableCall, ...]
    schema_version: int = CALLS_ARTIFACT_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CALLS_ARTIFACT_VERSION or not self.run_id:
            raise AuditInputError("calls artifact 的 schema_version 或 run_id 无效")
        object.__setattr__(self, "calls", tuple(self.calls))
        ids = [call.physical_request_id for call in self.calls]
        if len(ids) != len(set(ids)) or any(call.run_id != self.run_id for call in self.calls):
            raise AuditInputError("calls artifact 的请求 ID 必须唯一且 run_id 一致")

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "run_id": self.run_id,
                "calls": [call.to_dict() for call in self.calls]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CallsArtifact":
        calls = raw.get("calls")
        if not isinstance(calls, list):
            raise AuditInputError("calls artifact 的 calls 必须是列表")
        if any(not isinstance(item, Mapping) for item in calls):
            raise AuditInputError("calls artifact 的每项必须是对象")
        return cls(schema_version=raw.get("schema_version"), run_id=str(raw["run_id"]),
                   calls=tuple(AuditableCall.from_dict(item) for item in calls))


def load_calls_artifact(path: str | Path) -> CallsArtifact:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditInputError(f"无法读取 calls artifact：{exc}") from exc
    if not isinstance(raw, Mapping):
        raise AuditInputError("calls artifact 顶层必须是对象")
    return CallsArtifact.from_dict(raw)
