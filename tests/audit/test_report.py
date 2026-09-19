from __future__ import annotations

from decimal import Decimal

from agent_probe.audit import AuditableCall, AuditPolicy, AuditRule, RuleKind, Verdict, build_audit_report, explain_event, explain_finding
from agent_probe.events import EventResult, EventSource, EventType, new_event, new_run_id


def _event() -> object:
    return new_event(run_id=new_run_id(), event_type=EventType.FILE_WRITE, source=EventSource.SYNTHETIC,
        result=EventResult.OK, pid=1, tid=1, process_start_id=1, monotonic_ns=1, wall_time=1,
        payload={"fd": 3, "path": "/protected/a", "count": 1, "bytes_written": 1})


def test_report_retains_inputs_and_recomputes_identically() -> None:
    event = _event()
    policy = AuditPolicy(1, (AuditRule("protect", RuleKind.FORBIDDEN_WRITE, paths=("/protected",)),
        AuditRule("budget", RuleKind.COST_LIMIT, max_cost=Decimal("1"), currency="USD")))
    report = build_audit_report(policy, (event,), calls=(AuditableCall("req", event.run_id, agent="a", task_id="t", model="m", currency="USD", total_cost=Decimal("0.5"), cost_complete=True),))
    assert [item.verdict for item in report.findings] == [Verdict.VIOLATION, Verdict.PASS]
    assert report.recompute().to_dict() == report.to_dict()
    assert report.summary()["by_agent_task_model"][0]["cost_by_currency"] == {"USD": "0.5"}


def test_explain_preserves_raw_event_and_evidence_gap() -> None:
    event = _event()
    policy = AuditPolicy(1, (AuditRule("budget", RuleKind.COST_LIMIT, max_cost=Decimal("1"), currency="USD"),))
    report = build_audit_report(policy, (event,))
    finding = report.findings[0]
    assert explain_finding(report, finding.finding_id)["classification"] == "evidence_gap"
    assert explain_event(report, event.event_id)["unexplained"] is True
