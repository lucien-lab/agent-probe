from __future__ import annotations

from decimal import Decimal

from agent_probe.audit import AuditableCall, AuditRule, CallsArtifact, Verdict, evaluate_cost_rule


def _call(cost: str | None, *, complete: bool = True) -> AuditableCall:
    return AuditableCall(physical_request_id="call-1", run_id="run-1", currency="USD",
                         total_cost=None if cost is None else Decimal(cost), cost_complete=complete,
                         unknown_reasons=() if complete else ("usage_missing",))


def test_cost_rule_requires_complete_data_before_passing() -> None:
    rule = AuditRule(rule_id="budget", kind="cost_limit", max_cost=Decimal("1.00"), currency="USD")
    assert evaluate_cost_rule(rule, (_call("1.00"),))[0].verdict is Verdict.PASS
    assert evaluate_cost_rule(rule, (_call(None, complete=False),))[0].verdict is Verdict.INSUFFICIENT_EVIDENCE


def test_cost_lower_bound_can_prove_violation_despite_missing_cost() -> None:
    rule = AuditRule(rule_id="budget", kind="cost_limit", max_cost=Decimal("1.00"), currency="USD")
    expensive = _call("1.01")
    unknown = AuditableCall(physical_request_id="call-2", run_id="run-1", currency="USD", cost_complete=False)
    assert evaluate_cost_rule(rule, (expensive, unknown))[0].verdict is Verdict.VIOLATION


def test_calls_artifact_round_trips_without_request_content() -> None:
    artifact = CallsArtifact(run_id="run-1", calls=(_call("0.25"),))
    rebuilt = CallsArtifact.from_dict(__import__("json").loads(artifact.to_json()))
    assert rebuilt.to_dict() == artifact.to_dict()
    assert "request" not in __import__("json").loads(artifact.to_json())["calls"][0]
