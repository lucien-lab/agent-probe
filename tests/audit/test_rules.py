from __future__ import annotations

from decimal import Decimal

import pytest

from agent_probe.audit import (
    AuditPolicy,
    AuditRule,
    RuleKind,
    RuleLoadError,
    RuleSchemaError,
    parse_yaml_rules,
    policy_from_mapping,
)


def test_policy_parses_normal_indented_yaml_with_comments() -> None:
    policy = policy_from_mapping(parse_yaml_rules("""
schema_version: 1 # policy contract
rules:
  - id: source-write
    kind: forbidden_write
    paths:
      - /workspace/src
  - id: approved-network
    kind: destination_allowlist
    allowed_destinations:
      - 10.0.0.0/8
      - 'api.example.test'
  - id: budget
    kind: cost_limit
    max_cost: 1.25
    currency: USD
"""))

    assert policy.schema_version == 1
    assert policy.rules[0].paths == ("/workspace/src",)
    assert policy.rules[1].allowed_destinations == ("10.0.0.0/8", "api.example.test")
    assert policy.rules[2].max_cost == Decimal("1.25")


def test_rule_schema_rejects_missing_kind_specific_fields() -> None:
    with pytest.raises(RuleSchemaError, match="paths"):
        AuditRule(rule_id="no-write", kind=RuleKind.FORBIDDEN_WRITE)

    with pytest.raises(RuleSchemaError, match="重复"):
        AuditPolicy(
            schema_version=1,
            rules=(
                AuditRule(rule_id="same", kind="sensitive_read", paths=("/secret",)),
                AuditRule(rule_id="same", kind="sensitive_read", paths=("/other",)),
            ),
        )


def test_yaml_reader_rejects_unsupported_complex_yaml_instead_of_misreading() -> None:
    with pytest.raises(RuleLoadError, match="rules 必须使用缩进列表"):
        parse_yaml_rules("schema_version: 1\nrules: &all\n  - id: x\n")


def test_policy_rejects_unknown_rule_fields() -> None:
    with pytest.raises(RuleSchemaError, match="未知字段"):
        policy_from_mapping({
            "schema_version": 1,
            "rules": [{"id": "x", "kind": "sensitive_read", "paths": ["/secret"], "oops": True}],
        })
