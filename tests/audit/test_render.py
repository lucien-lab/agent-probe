from __future__ import annotations

from agent_probe.audit import AuditPolicy, AuditRule, RuleKind, build_audit_report, render_html, render_json, render_text
from agent_probe.events import EventResult, EventSource, EventType, new_event, new_run_id


def _report():
    event = new_event(run_id=new_run_id(), event_type=EventType.FILE_WRITE, source=EventSource.SYNTHETIC,
        result=EventResult.OK, pid=1, tid=1, process_start_id=1, monotonic_ns=1, wall_time=1,
        payload={"fd": 3, "path": "/protected/<script>", "count": 1, "bytes_written": 1})
    return build_audit_report(AuditPolicy(1, (AuditRule("protect", RuleKind.FORBIDDEN_WRITE, paths=("/protected",)),)), (event,))


def test_all_renderers_agree_on_finding_and_html_escapes_input() -> None:
    report = _report()
    finding_id = report.findings[0].finding_id
    assert finding_id in render_json(report)
    assert finding_id in render_text(report)
    page = render_html(report)
    assert finding_id in page
    assert "&lt;script&gt;" in page
    assert "/protected/<script>" not in page
