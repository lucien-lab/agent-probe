from __future__ import annotations

import pytest

from agent_probe.audit import AuditFinding, AuditInputError, Verdict


def test_finding_id_is_stable_when_event_input_order_changes() -> None:
    first = AuditFinding.create(
        rule_id="protect-source", verdict="violation", summary="写入受保护目录",
        event_ids=("event-b", "event-a", "event-a"), evidence={"path": "/src/a.py"},
    )
    second = AuditFinding.create(
        rule_id="protect-source", verdict=Verdict.VIOLATION, summary="不同展示文字不参与证据 ID",
        event_ids=("event-a", "event-b"), evidence={"path": "/src/a.py"},
    )

    assert first.finding_id == second.finding_id
    assert first.event_ids == ("event-a", "event-b")


def test_insufficient_evidence_is_a_first_class_verdict() -> None:
    finding = AuditFinding.create(
        rule_id="read-secrets", verdict="insufficient_evidence", summary="read 事件没有路径",
        evidence={"missing": ["payload.path"]},
    )

    assert finding.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert finding.to_dict()["verdict"] == "insufficient_evidence"


def test_manually_supplied_id_must_match_normalized_evidence() -> None:
    with pytest.raises(AuditInputError, match="finding_id"):
        AuditFinding(
            finding_id="finding-not-real", rule_id="x", verdict="pass", summary="ok",
            event_ids=("event-a",), evidence={},
        )
