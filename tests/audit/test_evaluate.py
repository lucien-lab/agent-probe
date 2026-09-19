from __future__ import annotations

from agent_probe.audit import AuditRule, RuleKind, Verdict, evaluate_event_rule, path_matches
from agent_probe.events import EventResult, EventSource, EventType, new_event, new_run_id


def make_event(event_type, *, payload, result=EventResult.OK):
    return new_event(
        run_id=new_run_id(), event_type=event_type, payload=payload, result=result,
        source=EventSource.SYNTHETIC, pid=10, tid=10, process_start_id=1,
        monotonic_ns=1, wall_time=1,
    )


def test_protected_write_requires_actual_successful_mutation() -> None:
    rule = AuditRule(rule_id="protect-src", kind=RuleKind.FORBIDDEN_WRITE, paths=("/work/src",))
    opened = make_event(EventType.FILE_OPEN, payload={"path": "/work/src/a.py", "flags": 1, "fd": 3})
    zero_write = make_event(EventType.FILE_WRITE, payload={"fd": 3, "path": "/work/src/a.py", "count": 5, "bytes_written": 0})
    actual = make_event(EventType.FILE_WRITE, payload={"fd": 3, "path": "/work/src/a.py", "count": 5, "bytes_written": 5})

    findings = evaluate_event_rule(rule, (opened, zero_write, actual))
    assert [item.verdict for item in findings] == [Verdict.VIOLATION]
    assert findings[0].event_ids == (actual.event_id,)


def test_read_unknown_and_directory_boundary_are_not_collapsed() -> None:
    rule = AuditRule(rule_id="secret-read", kind="sensitive_read", paths=("/work/secret",))
    sibling = make_event(EventType.FILE_READ, payload={"fd": 3, "path": "/work/secrets/a", "count": 2, "bytes_read": 2})
    unknown = make_event(EventType.FILE_READ, result=EventResult.UNKNOWN,
        payload={"fd": 3, "path": "/work/secret/a", "count": 2, "bytes_read": 2})

    findings = evaluate_event_rule(rule, (sibling, unknown))
    assert [item.verdict for item in findings] == [Verdict.INSUFFICIENT_EVIDENCE]
    assert path_matches("/work/secret/a", "/work/secret")
    assert not path_matches("/work/secrets/a", "/work/secret")


def test_destination_allowlist_accepts_cidr_and_reports_unknown() -> None:
    rule = AuditRule(rule_id="network", kind="destination_allowlist", allowed_destinations=("10.0.0.0/8",))
    allowed = make_event(EventType.NET_CONNECT, payload={"family": "inet", "protocol": "tcp", "dest_addr": "10.1.2.3", "dest_port": 443, "local_port": 1})
    blocked = make_event(EventType.NET_SEND, payload={"family": "inet", "protocol": "udp", "dest_addr": "8.8.8.8", "dest_port": 53, "bytes_sent": 2})
    unknown = make_event(EventType.NET_CONNECT, result=EventResult.UNKNOWN,
        payload={"family": "inet", "protocol": "tcp", "dest_addr": "10.2.3.4", "dest_port": 443, "local_port": 1})

    findings = evaluate_event_rule(rule, (allowed, blocked, unknown))
    assert [item.verdict for item in findings] == [Verdict.VIOLATION, Verdict.INSUFFICIENT_EVIDENCE]
