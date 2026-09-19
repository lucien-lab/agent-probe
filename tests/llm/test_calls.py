"""逻辑/物理标识、显式重试关系与去重计账测试。"""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from agent_probe.llm.calls import (
    AccountingLedger,
    CallIdentity,
    LlmCallRecord,
    RetryCycleError,
    RetryEvidence,
    RetryRegistry,
)
from agent_probe.llm.common import Direction
from agent_probe.llm.completion import analyze_payload
from agent_probe.llm.http1 import Http1Parser
from agent_probe.llm.messages import HttpRequest, HttpResponse
from agent_probe.llm.pricing import DEFAULT_PRICE_TABLE, estimate_cost
from agent_probe.llm.usage import UsageStatus

from llm.fixtures import http_request, http_response, openai_json_body

REQUEST = Direction.CLIENT_TO_SERVER
RESPONSE = Direction.SERVER_TO_CLIENT


def parse(direction: Direction, wire: bytes):
    parser = Http1Parser(direction)
    messages = list(parser.feed(wire).messages)
    messages.extend(parser.finish().messages)
    assert len(messages) == 1
    return messages[0]


def make_record(
    physical_id: str,
    *,
    body: bytes | None = None,
    with_response: bool = True,
    with_cost: bool = True,
    index: int = 1,
) -> LlmCallRecord:
    request = parse(REQUEST, http_request(body=b"{}"))
    assert isinstance(request, HttpRequest)
    response: HttpResponse | None = None
    if with_response:
        wire = http_response(
            openai_json_body() if body is None else body,
            headers=(("Content-Type", "application/json"),),
        )
        response = parse(RESPONSE, wire)
        assert isinstance(response, HttpResponse)
    analysis = analyze_payload(response) if response is not None else None
    cost = None
    if with_cost and analysis is not None:
        cost = estimate_cost(
            usage=analysis.usage.usage,
            usage_status=analysis.usage.status,
            price_table=DEFAULT_PRICE_TABLE,
        )
    return LlmCallRecord(
        identity=CallIdentity(physical_request_id=physical_id, logical_call_id=physical_id),
        connection_id="conn-1",
        request=request,
        response=response,
        analysis=analysis,
        cost=cost,
    )


# ----------------------------------------------------------------------
# 标识
# ----------------------------------------------------------------------


def test_default_identity_does_not_guess_retries() -> None:
    identity = CallIdentity(physical_request_id="p1", logical_call_id="p1")
    assert identity.attempt_index == 1
    assert identity.retry_of is None
    assert identity.retry_evidence is RetryEvidence.NONE
    assert identity.is_retry is False
    record = identity.to_record()
    assert record["retry_evidence"] == "none"
    assert json.loads(json.dumps(record))["physical_request_id"] == "p1"


def test_unlinked_requests_keep_separate_logical_ids() -> None:
    registry = RetryRegistry()
    first = registry.resolve("p1")
    second = registry.resolve("p2")
    assert first.logical_call_id == "p1"
    assert second.logical_call_id == "p2"
    assert not first.is_retry and not second.is_retry


def test_explicit_retry_link_is_resolved() -> None:
    registry = RetryRegistry()
    registry.link_retry(
        physical_request_id="p2", retry_of="p1", reason="502 from upstream"
    )
    identity = registry.resolve("p2")
    assert identity.logical_call_id == "p1"
    assert identity.attempt_index == 2
    assert identity.retry_of == "p1"
    assert identity.retry_reason == "502 from upstream"
    assert identity.retry_evidence is RetryEvidence.EXPLICIT_CALLER
    assert identity.is_retry


def test_retry_chain_produces_monotonic_attempt_indexes() -> None:
    registry = RetryRegistry()
    registry.link_retry(physical_request_id="p2", retry_of="p1", reason="timeout")
    registry.link_retry(
        physical_request_id="p3",
        retry_of="p2",
        reason="rate limited",
        evidence=RetryEvidence.APPLICATION_MARKER,
    )
    assert registry.chain("p3") == ("p1", "p2", "p3")
    third = registry.resolve("p3")
    assert third.attempt_index == 3
    assert third.retry_of == "p2"
    assert third.logical_call_id == "p1"
    assert third.retry_evidence is RetryEvidence.APPLICATION_MARKER
    first = registry.resolve("p1")
    assert first.attempt_index == 1
    assert first.logical_call_id == "p1"


def test_declared_logical_call_wins_over_chain_root() -> None:
    registry = RetryRegistry()
    registry.link_retry(physical_request_id="p2", retry_of="p1", reason="retry")
    registry.declare_logical_call("p2", "logical-42")
    assert registry.resolve("p2").logical_call_id == "logical-42"
    assert registry.resolve("p1").logical_call_id == "logical-42"


def test_cycle_in_retry_links_is_detected() -> None:
    registry = RetryRegistry()
    registry.link_retry(physical_request_id="p1", retry_of="p2", reason="a")
    registry.link_retry(physical_request_id="p2", retry_of="p1", reason="b")
    with pytest.raises(RetryCycleError):
        registry.resolve("p1")


def test_invalid_retry_declarations_are_rejected() -> None:
    registry = RetryRegistry()
    with pytest.raises(ValueError):
        registry.link_retry(physical_request_id="p1", retry_of="p1", reason="self")
    with pytest.raises(ValueError):
        registry.link_retry(physical_request_id="p1", retry_of="p0", reason="")
    with pytest.raises(ValueError):
        registry.link_retry(
            physical_request_id="p1",
            retry_of="p0",
            reason="no evidence",
            evidence=RetryEvidence.NONE,
        )
    with pytest.raises(ValueError):
        registry.declare_logical_call("", "x")


def test_there_is_no_timing_based_retry_inference_api() -> None:
    # 防回归：不允许出现"按时间/相似度自动推断重试"的入口。
    public = {name for name in dir(RetryRegistry) if not name.startswith("_")}
    assert public == {
        "resolve",
        "chain",
        "component",
        "link_retry",
        "declare_logical_call",
        "linked_physical_request_ids",
    }


def test_branching_retries_share_one_logical_call() -> None:
    registry = RetryRegistry()
    registry.link_retry(physical_request_id="p2", retry_of="p1", reason="timeout")
    registry.link_retry(physical_request_id="p3", retry_of="p1", reason="timeout")
    registry.declare_logical_call("p3", "logical-7")
    assert registry.component("p1") == ("p1", "p2", "p3")
    for node in ("p1", "p2", "p3"):
        assert registry.resolve(node).logical_call_id == "logical-7"
    assert registry.resolve("p2").attempt_index == 2
    assert registry.resolve("p3").attempt_index == 2


def test_identical_records_are_not_auto_linked() -> None:
    ledger = AccountingLedger()
    ledger.record(make_record("p1"))
    ledger.record(make_record("p2"))
    summary = ledger.summary()
    assert summary.logical_calls == 2
    assert summary.retried_physical_requests == 0


# ----------------------------------------------------------------------
# 账本
# ----------------------------------------------------------------------


def test_duplicate_physical_request_is_not_double_counted() -> None:
    ledger = AccountingLedger()
    assert ledger.record(make_record("p1")) is True
    assert ledger.record(make_record("p1")) is False
    summary = ledger.summary()
    assert summary.physical_requests == 1
    assert summary.duplicate_physical_requests == 1
    assert summary.input_tokens == 120


def test_ledger_applies_the_retry_registry() -> None:
    registry = RetryRegistry()
    registry.link_retry(physical_request_id="p2", retry_of="p1", reason="retry")
    ledger = AccountingLedger(retry_registry=registry)
    ledger.record(make_record("p1"))
    ledger.record(make_record("p2"))
    summary = ledger.summary()
    assert summary.physical_requests == 2
    assert summary.logical_calls == 1
    assert summary.retried_physical_requests == 1
    assert [record.identity.attempt_index for record in ledger.records] == [1, 2]
    assert summary.total_tokens == 300  # 两次物理请求都计费


def test_summary_sums_only_observed_fields() -> None:
    ledger = AccountingLedger()
    ledger.record(make_record("p1"))
    ledger.record(make_record("p2", body=b'{"model":"gpt-4o-mini","choices":[]}'))
    summary = ledger.summary()
    assert summary.usage_present == 1
    assert summary.usage_absent == 1
    assert summary.input_tokens == 120
    assert summary.output_tokens == 30
    assert summary.cache_read_tokens is None
    assert summary.reasoning_tokens is None


def test_summary_cost_is_incomplete_when_any_record_is_unpriced() -> None:
    ledger = AccountingLedger()
    ledger.record(make_record("p1"))
    ledger.record(make_record("p2", with_response=False, with_cost=False))
    summary = ledger.summary()
    assert summary.estimated_cost is not None  # 仅作为下界
    assert summary.cost_complete is False
    assert summary.unpriced_physical_requests == 1
    assert summary.currency == "USD"


def test_summary_records_truncation_and_usage_gaps() -> None:
    ledger = AccountingLedger()
    ledger.record(make_record("p1"))
    truncated_body = openai_json_body()
    truncated_record = LlmCallRecord(
        identity=CallIdentity("p2", "p2"),
        connection_id="conn-1",
        request=parse(REQUEST, http_request()),
        response=parse(
            RESPONSE,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9000\r\n\r\n"
            + truncated_body,
        ),
    )
    ledger.record(truncated_record)
    # 未附 analysis 时 usage 状态未知，不算进 usage 计数
    ledger.record(make_record("p3", body=b'{"model":"gpt-4o-mini","choices":[]}'))
    summary = ledger.summary()
    assert summary.physical_requests == 3
    assert summary.usage_present == 1
    assert summary.usage_absent == 1
    assert summary.usage_not_captured == 0


def test_summary_groups_by_model() -> None:
    ledger = AccountingLedger()
    ledger.record(make_record("p1"))
    ledger.record(
        make_record(
            "p2",
            body=openai_json_body(model="gpt-4o", prompt_tokens=10, completion_tokens=1),
        )
    )
    summary = ledger.summary()
    assert [entry.model for entry in summary.by_model] == ["gpt-4o", "gpt-4o-mini"]
    mini = summary.by_model[1]
    assert mini.physical_requests == 1
    assert mini.input_tokens == 120
    gpt4o = summary.by_model[0]
    assert gpt4o.input_tokens == 10
    assert gpt4o.estimated_cost == Decimal("0.000035")


def test_summary_of_empty_ledger_is_all_none() -> None:
    summary = AccountingLedger().summary()
    assert summary.physical_requests == 0
    assert summary.input_tokens is None
    assert summary.estimated_cost is None
    assert summary.cost_complete is False
    assert summary.by_model == ()


def test_summary_record_is_json_safe() -> None:
    ledger = AccountingLedger()
    ledger.record(make_record("p1"))
    record = ledger.summary().to_record()
    assert json.loads(json.dumps(record))["physical_requests"] == 1
    assert isinstance(record["estimated_cost"], str)


def test_unpaired_request_has_no_usage_and_no_cost() -> None:
    ledger = AccountingLedger()
    ledger.record(make_record("p1", with_response=False, with_cost=False))
    summary = ledger.summary()
    assert summary.requests_without_response == 1
    assert summary.usage_present == 0
    assert summary.usage_not_captured == 0
    assert summary.estimated_cost is None


def test_record_requires_request_or_response() -> None:
    with pytest.raises(ValueError):
        LlmCallRecord(identity=CallIdentity("p1", "p1"), connection_id="c1")


def test_with_identity_and_with_cost_replace_frozen_fields() -> None:
    record = make_record("p1")
    replaced = record.with_identity(CallIdentity("p1", "logical-1", attempt_index=2, retry_of="p0"))
    assert replaced.identity.logical_call_id == "logical-1"
    assert record.identity.logical_call_id == "p1"
    assert replaced.cost is record.cost


def test_usage_status_helper_returns_not_captured_for_truncated_response() -> None:
    request = parse(REQUEST, http_request())
    response = parse(
        RESPONSE,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 900\r\n\r\n{",
    )
    analysis = analyze_payload(response)
    assert analysis.usage.status is UsageStatus.NOT_CAPTURED
    record = LlmCallRecord(
        identity=CallIdentity("p1", "p1"), connection_id="c1", request=request, response=response, analysis=analysis
    )
    assert record.is_transport_truncated
    assert record.usage is not None and record.usage.status is UsageStatus.NOT_CAPTURED
