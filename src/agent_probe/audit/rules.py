"""M4 规则策略与受限 YAML 读取器。

为保持运行时零依赖，读取器故意只支持本项目的规则形状：顶层标量和
``rules`` 下的对象列表，列表字段只能是标量列表。它支持通常的缩进 YAML 与
注释，但拒绝 anchors、tags、flow mapping 和多行字符串；这些限制会以
``RuleLoadError`` 明确报出，而不是静默误读策略。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import RuleLoadError, RuleSchemaError

__all__ = [
    "RULE_SCHEMA_VERSION", "RuleKind", "AuditRule", "AuditPolicy",
    "policy_from_mapping", "load_policy", "parse_yaml_rules",
]

RULE_SCHEMA_VERSION = 1


class RuleKind(StrEnum):
    FORBIDDEN_WRITE = "forbidden_write"
    SENSITIVE_READ = "sensitive_read"
    DESTINATION_ALLOWLIST = "destination_allowlist"
    COST_LIMIT = "cost_limit"


@dataclass(frozen=True, slots=True)
class AuditRule:
    rule_id: str
    kind: RuleKind
    paths: tuple[str, ...] = ()
    allowed_destinations: tuple[str, ...] = ()
    max_cost: Decimal | None = None
    currency: str | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,127}", self.rule_id):
            raise RuleSchemaError("rule id 必须是 1–128 位字母开头的安全标识")
        object.__setattr__(self, "kind", RuleKind(self.kind))
        object.__setattr__(self, "paths", tuple(self.paths))
        object.__setattr__(self, "allowed_destinations", tuple(self.allowed_destinations))
        if self.kind in (RuleKind.FORBIDDEN_WRITE, RuleKind.SENSITIVE_READ):
            if not self.paths or any(not path.startswith("/") for path in self.paths):
                raise RuleSchemaError(f"{self.kind} 规则必须有至少一个绝对 paths 项")
        elif self.kind is RuleKind.DESTINATION_ALLOWLIST:
            if not self.allowed_destinations:
                raise RuleSchemaError("destination_allowlist 规则必须有 allowed_destinations")
        elif self.kind is RuleKind.COST_LIMIT:
            if self.max_cost is None or self.max_cost < 0 or not self.currency:
                raise RuleSchemaError("cost_limit 规则必须有非负 max_cost 与 currency")
        if self.max_cost is not None and not isinstance(self.max_cost, Decimal):
            try:
                object.__setattr__(self, "max_cost", Decimal(str(self.max_cost)))
            except (InvalidOperation, ValueError) as exc:
                raise RuleSchemaError("max_cost 必须是十进制数") from exc


@dataclass(frozen=True, slots=True)
class AuditPolicy:
    schema_version: int
    rules: tuple[AuditRule, ...]

    def __post_init__(self) -> None:
        if self.schema_version != RULE_SCHEMA_VERSION:
            raise RuleSchemaError(f"仅支持规则 schema_version={RULE_SCHEMA_VERSION}")
        object.__setattr__(self, "rules", tuple(self.rules))
        ids = [rule.rule_id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise RuleSchemaError("规则 rule_id 不能重复")


def _scalar(text: str, *, line: int) -> object:
    value = text.strip()
    if not value:
        return ""
    if value[0:1] in ("'", '"'):
        if len(value) < 2 or value[-1] != value[0]:
            raise RuleLoadError(f"第 {line} 行：未闭合的 YAML 引号")
        if value[0] == '"':
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise RuleLoadError(f"第 {line} 行：无效双引号字符串") from exc
        return value[1:-1].replace("''", "'")
    if value in ("true", "True"):
        return True
    if value in ("false", "False"):
        return False
    if value in ("null", "Null", "NULL", "~"):
        return None
    if value.startswith(("[", "{", "&", "*", "!", "|", ">")):
        raise RuleLoadError(f"第 {line} 行：不支持该 YAML 结构；请使用缩进列表与标量")
    return value


def _without_comment(line: str) -> str:
    quoted: str | None = None
    for index, char in enumerate(line):
        if char in ("'", '"'):
            if quoted is None:
                quoted = char
            elif quoted == char:
                quoted = None
        if char == "#" and quoted is None and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def parse_yaml_rules(text: str) -> Mapping[str, Any]:
    """解析受限、正常缩进的 M4 YAML 规则文件。"""

    result: dict[str, Any] = {}
    rules: list[dict[str, Any]] | None = None
    current: dict[str, Any] | None = None
    list_key: str | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        line = _without_comment(raw).rstrip()
        if not line.strip():
            continue
        if "\t" in line[: len(line) - len(line.lstrip())]:
            raise RuleLoadError(f"第 {number} 行：YAML 缩进不能使用 tab")
        indent = len(line) - len(line.lstrip(" "))
        content = line.strip()
        if indent == 0:
            if ":" not in content:
                raise RuleLoadError(f"第 {number} 行：顶层项必须是 key: value")
            key, value = content.split(":", 1)
            if key == "rules":
                if value.strip():
                    raise RuleLoadError(f"第 {number} 行：rules 必须使用缩进列表")
                rules = []
                result[key] = rules
                current = None
                list_key = None
            else:
                result[key] = _scalar(value, line=number)
            continue
        if rules is None:
            raise RuleLoadError(f"第 {number} 行：仅支持顶层 rules 下的规则")
        if indent == 2 and content.startswith("- "):
            current = {}
            rules.append(current)
            list_key = None
            content = content[2:].strip()
            if ":" not in content:
                raise RuleLoadError(f"第 {number} 行：规则项必须以 key: value 开始")
            key, value = content.split(":", 1)
            current[key] = _scalar(value, line=number)
            continue
        if current is None:
            raise RuleLoadError(f"第 {number} 行：rules 必须以 '- id: ...' 开始")
        if indent == 4 and not content.startswith("-"):
            if ":" not in content:
                raise RuleLoadError(f"第 {number} 行：字段必须是 key: value")
            key, value = content.split(":", 1)
            if value.strip():
                current[key] = _scalar(value, line=number)
                list_key = None
            else:
                current[key] = []
                list_key = key
            continue
        if indent == 6 and content.startswith("- ") and list_key is not None:
            current[list_key].append(_scalar(content[2:], line=number))
            continue
        raise RuleLoadError(f"第 {number} 行：不支持的 YAML 缩进或嵌套结构")
    return result


def _strings(raw: object, field: str) -> tuple[str, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise RuleSchemaError(f"{field} 必须是字符串列表")
    if any(not isinstance(item, str) or not item for item in raw):
        raise RuleSchemaError(f"{field} 的每项必须是非空字符串")
    return tuple(raw)


def policy_from_mapping(data: Mapping[str, Any]) -> AuditPolicy:
    if not isinstance(data.get("schema_version"), (int, str)):
        raise RuleSchemaError("缺少 schema_version")
    try:
        version = int(data["schema_version"])
    except ValueError as exc:
        raise RuleSchemaError("schema_version 必须是整数") from exc
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, Sequence) or isinstance(raw_rules, (str, bytes)):
        raise RuleSchemaError("rules 必须是规则列表")
    rules: list[AuditRule] = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, Mapping):
            raise RuleSchemaError(f"rules[{index}] 必须是对象")
        allowed = {"id", "kind", "paths", "allowed_destinations", "max_cost", "currency"}
        unknown = set(raw) - allowed
        if unknown:
            raise RuleSchemaError(f"rules[{index}] 含未知字段：{sorted(unknown)}")
        try:
            kind = RuleKind(raw["kind"])
            rule_id = raw["id"]
        except (KeyError, ValueError) as exc:
            raise RuleSchemaError(f"rules[{index}] 缺少或含无效 id/kind") from exc
        if not isinstance(rule_id, str):
            raise RuleSchemaError(f"rules[{index}].id 必须是字符串")
        max_cost = raw.get("max_cost")
        if max_cost is not None:
            try:
                max_cost = Decimal(str(max_cost))
            except InvalidOperation as exc:
                raise RuleSchemaError(f"rules[{index}].max_cost 必须是十进制数") from exc
        rules.append(AuditRule(
            rule_id=rule_id, kind=kind,
            paths=_strings(raw.get("paths", ()), f"rules[{index}].paths"),
            allowed_destinations=_strings(raw.get("allowed_destinations", ()), f"rules[{index}].allowed_destinations"),
            max_cost=max_cost, currency=raw.get("currency"),
        ))
    return AuditPolicy(schema_version=version, rules=tuple(rules))


def load_policy(path: str | Path) -> AuditPolicy:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleLoadError(f"无法读取规则文件 {path!s}: {exc}") from exc
    return policy_from_mapping(parse_yaml_rules(text))
