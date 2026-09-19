"""纯函数式 M4 报告渲染：JSON、文本和无外部依赖的静态 HTML。"""

from __future__ import annotations

import html
import json
from typing import Literal

from .report import AuditReport

__all__ = ["render_html", "render_json", "render_report", "render_text"]


def render_json(report: AuditReport, *, include_inputs: bool = True) -> str:
    return json.dumps(report.to_dict(include_inputs=include_inputs), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def render_text(report: AuditReport) -> str:
    summary = report.summary()
    counts = summary["findings_by_verdict"]
    lines = [
        f"agent-probe audit report · runs: {', '.join(summary['runs']) or '<none>'}",
        f"events={summary['event_count']} calls={summary['call_count']} "
        f"pass={counts['pass']} violation={counts['violation']} "
        f"insufficient_evidence={counts['insufficient_evidence']}",
    ]
    for finding in report.findings:
        evidence = ", ".join(finding.event_ids) or "no direct event"
        lines.append(f"[{finding.verdict.value}] {finding.rule_id} {finding.finding_id}: {finding.summary} ({evidence})")
    quality = summary["data_quality"]
    if quality["unknown_event_ids"]:
        lines.append("data quality: unknown event results=" + ", ".join(quality["unknown_event_ids"]))
    if not quality["calls_artifact_provided"]:
        lines.append("data quality: calls artifact absent; cost-rule passes are not implied")
    return "\n".join(lines) + "\n"


def _tag(value: object) -> str:
    return html.escape(str(value), quote=True)


def render_html(report: AuditReport) -> str:
    """生成自包含 HTML；所有原始字段先转义，故账本内容不能注入页面。"""

    summary = report.summary()
    counts = summary["findings_by_verdict"]
    finding_rows = "\n".join(
        "<tr id=\"{id}\"><td>{verdict}</td><td>{rule}</td><td>{summary}</td><td>{events}</td></tr>".format(
            id=_tag(finding.finding_id), verdict=_tag(finding.verdict.value), rule=_tag(finding.rule_id),
            summary=_tag(finding.summary),
            events=" ".join(f'<a href="#event-{_tag(event_id)}">{_tag(event_id)}</a>' for event_id in finding.event_ids) or "—",
        ) for finding in report.findings
    )
    event_rows = "\n".join(
        "<tr id=\"event-{id}\"><td>{id}</td><td>{typ}</td><td>{result}</td><td><pre>{payload}</pre></td></tr>".format(
            id=_tag(event.event_id), typ=_tag(event.event_type.value), result=_tag(event.result.value),
            payload=_tag(json.dumps(event.to_dict()["payload"], ensure_ascii=False, sort_keys=True)),
        ) for event in report.events
    )
    body = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>agent-probe audit report</title>
<style>body{{font:14px system-ui,sans-serif;margin:2rem;color:#18212f}} table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #cbd5e1;padding:.45rem;text-align:left;vertical-align:top}}th{{background:#eef2ff}}pre{{margin:0;white-space:pre-wrap;word-break:break-word}}.violation{{color:#b91c1c}}.insufficient_evidence{{color:#a16207}}</style></head>
<body><h1>agent-probe 审计报告</h1>
<p>事件 {summary['event_count']} · 调用 {summary['call_count']} · pass {counts['pass']} · <span class="violation">violation {counts['violation']}</span> · <span class="insufficient_evidence">insufficient evidence {counts['insufficient_evidence']}</span></p>
<p>runs: {_tag(', '.join(summary['runs']) or '<none>')}；ledger digest: {_tag(summary['data_quality']['ledger_digest'] or '<not supplied>')}</p>
<h2>规则结论</h2><table><thead><tr><th>Verdict</th><th>Rule</th><th>Summary</th><th>Evidence events</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>原始事件时间线（账本顺序）</h2><table><thead><tr><th>Event ID</th><th>Type</th><th>Result</th><th>Payload</th></tr></thead><tbody>{event_rows}</tbody></table>
</body></html>"""
    return body


def render_report(report: AuditReport, format: Literal["json", "text", "html"] = "text") -> str:
    if format == "json":
        return render_json(report)
    if format == "text":
        return render_text(report)
    if format == "html":
        return render_html(report)
    raise ValueError(f"不支持的报告格式：{format}")
