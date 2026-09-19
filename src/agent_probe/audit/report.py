"""M4 可重算审计报告。

报告不是一次性展示对象：它保存参与判定的原始事件和 calls artifact，因而可在
离线环境以同一策略重新计算。未知值始终以 ``insufficient_evidence`` 或数据质量
计数出现，绝不在汇总时被当成零或 pass。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable, Mapping

from agent_probe.events import Event, ledger_digest, scan_ledger

from .artifacts import AuditableCall, CallsArtifact
from .evaluate import evaluate_cost_rule, evaluate_event_rule
from .findings import AuditFinding, Verdict
from .rules import AuditPolicy, RuleKind

__all__ = ["AUDIT_REPORT_VERSION", "AuditReport", "audit_ledger", "build_audit_report"]

AUDIT_REPORT_VERSION = 1


def _call_group_key(call: AuditableCall) -> tuple[str, str, str]:
    """缺少关联标签是事实，使用明确的未采集桶而不是凭空归因。"""

    return (
        call.agent or "<unattributed-agent>",
        call.task_id or "<unattributed-task>",
        call.model or "<unknown-model>",
    )


def _policy_dict(policy: AuditPolicy) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    for rule in policy.rules:
        item: dict[str, Any] = {"id": rule.rule_id, "kind": rule.kind.value}
        if rule.paths:
            item["paths"] = list(rule.paths)
        if rule.allowed_destinations:
            item["allowed_destinations"] = list(rule.allowed_destinations)
        if rule.max_cost is not None:
            item["max_cost"] = str(rule.max_cost)
        if rule.currency is not None:
            item["currency"] = rule.currency
        rules.append(item)
    return {"schema_version": policy.schema_version, "rules": rules}


@dataclass(frozen=True, slots=True)
class AuditReport:
    """一次审计的完整、可解释快照。"""

    policy: AuditPolicy
    events: tuple[Event, ...]
    calls: tuple[AuditableCall, ...] | None
    findings: tuple[AuditFinding, ...]
    ledger_digest: str | None = None
    schema_version: int = AUDIT_REPORT_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != AUDIT_REPORT_VERSION:
            raise ValueError(f"仅支持 audit report schema_version={AUDIT_REPORT_VERSION}")
        object.__setattr__(self, "events", tuple(self.events))
        object.__setattr__(self, "calls", None if self.calls is None else tuple(self.calls))
        object.__setattr__(self, "findings", tuple(self.findings))
        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("AuditReport 的 event_id 不能重复")
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("AuditReport 的 finding_id 不能重复")

    @property
    def run_ids(self) -> tuple[str, ...]:
        return tuple(sorted({event.run_id for event in self.events} | {
            call.run_id for call in self.calls or ()
        }))

    @property
    def verdict_counts(self) -> Mapping[Verdict, int]:
        counts: Counter[Verdict] = Counter(finding.verdict for finding in self.findings)
        return {verdict: counts[verdict] for verdict in Verdict}

    @property
    def event_by_id(self) -> Mapping[str, Event]:
        return {event.event_id: event for event in self.events}

    def recompute(self) -> "AuditReport":
        """以保存的策略和原始输入重算；用于验证结果未依赖展示层。"""

        return build_audit_report(
            self.policy, self.events, calls=self.calls, ledger_digest=self.ledger_digest
        )

    def summary(self) -> dict[str, Any]:
        groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        for call in self.calls or ():
            key = _call_group_key(call)
            group = groups.setdefault(key, {
                "agent": key[0], "task_id": key[1], "model": key[2], "calls": 0,
                "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
                "unknown_call_ids": [], "cost_by_currency": {},
            })
            group["calls"] += 1
            for name in ("input_tokens", "output_tokens", "total_tokens"):
                value = getattr(call, name)
                if value is None:
                    group["unknown_call_ids"].append(call.physical_request_id)
                else:
                    group[name] += value
            if call.currency and call.total_cost is not None:
                costs: dict[str, Decimal] = group["cost_by_currency"]
                costs[call.currency] = costs.get(call.currency, Decimal(0)) + call.total_cost
            if not call.cost_complete and call.physical_request_id not in group["unknown_call_ids"]:
                group["unknown_call_ids"].append(call.physical_request_id)
        serialized_groups: list[dict[str, Any]] = []
        for key in sorted(groups):
            group = groups[key]
            group["unknown_call_ids"].sort()
            group["cost_by_currency"] = {
                currency: str(total) for currency, total in sorted(group["cost_by_currency"].items())
            }
            serialized_groups.append(group)
        unknown_events = [event.event_id for event in self.events if event.result.value == "unknown"]
        return {
            "runs": list(self.run_ids),
            "event_count": len(self.events),
            "call_count": 0 if self.calls is None else len(self.calls),
            "findings_by_verdict": {verdict.value: self.verdict_counts[verdict] for verdict in Verdict},
            "data_quality": {
                "unknown_event_ids": sorted(unknown_events),
                "calls_artifact_provided": self.calls is not None,
                "ledger_digest": self.ledger_digest,
            },
            "by_agent_task_model": serialized_groups,
        }

    def to_dict(self, *, include_inputs: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "policy": _policy_dict(self.policy),
            "summary": self.summary(),
            "findings": [finding.to_dict() for finding in self.findings],
        }
        if include_inputs:
            data["events"] = [event.to_dict() for event in self.events]
            data["calls"] = None if self.calls is None else [call.to_dict() for call in self.calls]
        return data


def build_audit_report(
    policy: AuditPolicy,
    events: Iterable[Event],
    *,
    calls: Iterable[AuditableCall] | CallsArtifact | None = None,
    ledger_digest: str | None = None,
) -> AuditReport:
    """从原始事件、可选 calls artifact 和策略构造确定性报告。"""

    frozen_events = tuple(events)
    frozen_calls = None if calls is None else tuple(calls.calls if isinstance(calls, CallsArtifact) else calls)
    findings: list[AuditFinding] = []
    for rule in policy.rules:
        if rule.kind is RuleKind.COST_LIMIT:
            findings.extend(evaluate_cost_rule(rule, frozen_calls))
        else:
            findings.extend(evaluate_event_rule(rule, frozen_events))
    return AuditReport(
        policy=policy, events=frozen_events, calls=frozen_calls,
        findings=tuple(findings), ledger_digest=ledger_digest,
    )


def audit_ledger(
    policy: AuditPolicy,
    ledger_path: str | Path,
    *,
    calls: Iterable[AuditableCall] | CallsArtifact | None = None,
) -> AuditReport:
    """只读重放 JSONL 账本并生成报告，不创建或修改派生索引。"""

    scan = scan_ledger(ledger_path)
    # 使用同一次扫描的 records 计算摘要，避免两次读取之间账本追加造成不一致。
    return build_audit_report(
        policy, scan.events, calls=calls, ledger_digest=ledger_digest(scan.records)
    )
