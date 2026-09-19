"""从 audit report 回溯原始事件与 finding 的解释接口。"""

from __future__ import annotations

from typing import Any

from .errors import AuditInputError
from .findings import Verdict
from .report import AuditReport

__all__ = ["explain_event", "explain_finding"]


def _finding_view(report: AuditReport, finding_id: str) -> dict[str, Any]:
    finding = next((item for item in report.findings if item.finding_id == finding_id), None)
    if finding is None:
        raise AuditInputError(f"未找到 finding_id：{finding_id}")
    events = report.event_by_id
    return {
        "finding": finding.to_dict(),
        "evidence_events": [events[event_id].to_dict() for event_id in finding.event_ids if event_id in events],
        "missing_event_ids": [event_id for event_id in finding.event_ids if event_id not in events],
        "classification": (
            "evidence_gap" if finding.verdict is Verdict.INSUFFICIENT_EVIDENCE
            else "observed_fact" if finding.verdict is Verdict.VIOLATION else "bounded_non_observation"
        ),
    }


def explain_finding(report: AuditReport, finding_id: str) -> dict[str, Any]:
    """解释一个 finding：规则结论、原始证据及缺失证据均明确分开。"""

    return _finding_view(report, finding_id)


def explain_event(report: AuditReport, event_id: str) -> dict[str, Any]:
    """解释一个原始事件及其参与的所有审计结论。"""

    event = report.event_by_id.get(event_id)
    if event is None:
        raise AuditInputError(f"未找到 event_id：{event_id}")
    related = [finding for finding in report.findings if event_id in finding.event_ids]
    return {
        "event": event.to_dict(),
        "findings": [_finding_view(report, finding.finding_id) for finding in related],
        "fact": "此事件来自报告保存的原始账本输入；finding 是基于策略的判定。",
        "unexplained": not related,
    }
