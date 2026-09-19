"""基于原始 M2 事件的可重算规则求值。"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any

from agent_probe.events import Event, EventResult, EventType

from .findings import AuditFinding, Verdict
from .artifacts import AuditableCall
from .rules import AuditPolicy, AuditRule, RuleKind

__all__ = ["evaluate_events", "evaluate_event_rule", "evaluate_cost_rule", "path_matches"]


def path_matches(path: str, root: str) -> bool:
    """按路径段匹配而非字符串前缀；这是词法路径，未解析软链。"""
    normalized_root = root.rstrip("/") or "/"
    return path == normalized_root or path.startswith(normalized_root + "/")


def _event_paths(event: Event) -> tuple[str, ...]:
    payload = event.payload
    if event.event_type is EventType.FILE_RENAME:
        return tuple(value for value in (payload.get("old_path"), payload.get("new_path")) if isinstance(value, str))
    value = payload.get("path")
    return (value,) if isinstance(value, str) else ()


def _actual_write(event: Event) -> bool:
    if event.event_type is EventType.FILE_WRITE:
        return int(event.payload["bytes_written"]) > 0
    return event.event_type in (EventType.FILE_TRUNCATE, EventType.FILE_RENAME, EventType.FILE_UNLINK)


def _finding(rule: AuditRule, verdict: Verdict, summary: str, events: list[Event], **evidence: Any) -> AuditFinding:
    return AuditFinding.create(rule_id=rule.rule_id, verdict=verdict, summary=summary,
        event_ids=[event.event_id for event in events], evidence=evidence)


def _file_rule(rule: AuditRule, events: Iterable[Event], *, read: bool) -> tuple[AuditFinding, ...]:
    relevant = EventType.FILE_READ if read else None
    violations: list[Event] = []
    uncertain: list[Event] = []
    for event in events:
        if read and event.event_type is not relevant:
            continue
        if not read and event.event_type not in (EventType.FILE_WRITE, EventType.FILE_TRUNCATE, EventType.FILE_RENAME, EventType.FILE_UNLINK):
            continue
        paths = _event_paths(event)
        if not paths:
            uncertain.append(event)
            continue
        if not any(path_matches(path, root) for path in paths for root in rule.paths):
            continue
        if event.result is EventResult.UNKNOWN:
            uncertain.append(event)
        elif event.result is EventResult.OK and (read and int(event.payload["bytes_read"]) > 0 or not read and _actual_write(event)):
            violations.append(event)
    noun = "读取" if read else "修改"
    findings: list[AuditFinding] = []
    if violations:
        findings.append(_finding(rule, Verdict.VIOLATION, f"观测到受策略保护路径的实际{noun}", violations,
            paths=list(rule.paths), fact="result=ok 且实际字节/变更语义成立", path_resolution="lexical_only"))
    if uncertain:
        findings.append(_finding(rule, Verdict.INSUFFICIENT_EVIDENCE, f"无法确认受保护路径是否实际{noun}", uncertain,
            paths=list(rule.paths), missing="路径或返回结果未被完整采集", path_resolution="lexical_only"))
    if not findings:
        findings.append(_finding(rule, Verdict.PASS, f"未观测到受保护路径的实际{noun}", [],
            paths=list(rule.paths), scope="仅限输入事件与词法路径匹配"))
    return tuple(findings)


def _destination_allowed(destination: str, allowed: tuple[str, ...]) -> bool:
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        return destination.lower().rstrip(".") in {item.lower().rstrip(".") for item in allowed}
    for item in allowed:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def _network_rule(rule: AuditRule, events: Iterable[Event]) -> tuple[AuditFinding, ...]:
    violations: list[Event] = []
    uncertain: list[Event] = []
    for event in events:
        if event.event_type not in (EventType.NET_CONNECT, EventType.NET_SEND):
            continue
        destination = event.payload.get("dest_addr")
        if not isinstance(destination, str):
            uncertain.append(event)
        elif event.result is EventResult.UNKNOWN:
            uncertain.append(event)
        elif not _destination_allowed(destination, rule.allowed_destinations):
            violations.append(event)
    findings: list[AuditFinding] = []
    if violations:
        findings.append(_finding(rule, Verdict.VIOLATION, "观测到非白名单目的地址连接尝试", violations,
            allowed_destinations=list(rule.allowed_destinations), fact="已观测 net.connect/net.send，包含失败尝试"))
    if uncertain:
        findings.append(_finding(rule, Verdict.INSUFFICIENT_EVIDENCE, "网络目的地址或结果未完整采集", uncertain,
            allowed_destinations=list(rule.allowed_destinations)))
    if not findings:
        findings.append(_finding(rule, Verdict.PASS, "所有已知网络目的地址均在白名单内", [],
            allowed_destinations=list(rule.allowed_destinations)))
    return tuple(findings)


def evaluate_event_rule(rule: AuditRule, events: Iterable[Event]) -> tuple[AuditFinding, ...]:
    if rule.kind is RuleKind.FORBIDDEN_WRITE:
        return _file_rule(rule, events, read=False)
    if rule.kind is RuleKind.SENSITIVE_READ:
        return _file_rule(rule, events, read=True)
    if rule.kind is RuleKind.DESTINATION_ALLOWLIST:
        return _network_rule(rule, events)
    return (_finding(rule, Verdict.INSUFFICIENT_EVIDENCE, "成本规则需要可审计调用 artifact", [],
        missing="M4 calls artifact 未提供"),)


def evaluate_cost_rule(rule: AuditRule, calls: Iterable[AuditableCall] | None) -> tuple[AuditFinding, ...]:
    if rule.kind is not RuleKind.COST_LIMIT:
        raise ValueError("evaluate_cost_rule 仅接受 cost_limit 规则")
    if calls is None:
        return (_finding(rule, Verdict.INSUFFICIENT_EVIDENCE, "未提供可审计调用记录", [], missing="calls artifact"),)
    applicable = [call for call in calls if call.currency == rule.currency]
    if not applicable:
        return (_finding(rule, Verdict.INSUFFICIENT_EVIDENCE, "没有与规则币种匹配的调用记录", [], currency=rule.currency),)
    known = sum((call.total_cost or 0 for call in applicable), start=0)
    incomplete = [call for call in applicable if not call.cost_complete or call.total_cost is None]
    ids = [call.physical_request_id for call in applicable]
    if known > rule.max_cost:  # type: ignore[operator]
        return (_finding(rule, Verdict.VIOLATION, "已知费用下界超过策略上限", [],
            call_ids=ids, known_total=str(known), max_cost=str(rule.max_cost), currency=rule.currency,
            incomplete_call_ids=[call.physical_request_id for call in incomplete]),)
    if incomplete:
        return (_finding(rule, Verdict.INSUFFICIENT_EVIDENCE, "费用不完整，无法确认未超限", [],
            call_ids=ids, known_total=str(known), max_cost=str(rule.max_cost), currency=rule.currency,
            unknown_reasons={call.physical_request_id: list(call.unknown_reasons) for call in incomplete}),)
    return (_finding(rule, Verdict.PASS, "完整估算费用未超过策略上限", [],
        call_ids=ids, total_cost=str(known), max_cost=str(rule.max_cost), currency=rule.currency),)


def evaluate_events(policy: AuditPolicy, events: Iterable[Event]) -> tuple[AuditFinding, ...]:
    frozen = tuple(events)
    return tuple(finding for rule in policy.rules for finding in evaluate_event_rule(rule, frozen))
