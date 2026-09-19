"""M4 审计规则、可解释结论与报告。"""

from .errors import AuditError, AuditInputError, RuleLoadError, RuleSchemaError
from .findings import AuditFinding, Verdict, stable_finding_id
from .rules import AuditPolicy, AuditRule, RuleKind, load_policy, parse_yaml_rules, policy_from_mapping
from .evaluate import evaluate_cost_rule, evaluate_event_rule, evaluate_events, path_matches
from .artifacts import AuditableCall, CallsArtifact, load_calls_artifact
from .report import AUDIT_REPORT_VERSION, AuditReport, audit_ledger, build_audit_report
from .explain import explain_event, explain_finding
from .render import render_html, render_json, render_report, render_text

__all__ = [
    "AuditError",
    "AuditInputError",
    "RuleLoadError",
    "RuleSchemaError",
    "AuditFinding",
    "Verdict",
    "stable_finding_id",
    "AuditPolicy",
    "AuditRule",
    "RuleKind",
    "load_policy",
    "parse_yaml_rules",
    "policy_from_mapping",
    "evaluate_event_rule",
    "evaluate_cost_rule",
    "evaluate_events",
    "path_matches",
    "AuditableCall",
    "CallsArtifact",
    "load_calls_artifact",
    "AUDIT_REPORT_VERSION",
    "AuditReport",
    "build_audit_report",
    "audit_ledger",
    "explain_event",
    "explain_finding",
    "render_json",
    "render_text",
    "render_html",
    "render_report",
]
