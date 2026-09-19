"""连接级重建的端到端回放测试（全部离线字节夹具）。"""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from agent_probe.llm.calls import AccountingLedger, RetryEvidence, RetryRegistry
from agent_probe.llm.common import Direction
from agent_probe.llm.completion import ContentKind, StreamCompletion
from agent_probe.llm.diagnostics import DiagnosticCode
from agent_probe.llm.limits import ParserLimits
from agent_probe.llm.pricing import DEFAULT_PRICE_TABLE, PriceTable
from agent_probe.llm.reconstruct import (
    ConnectionReconstructor,
    MultiConnectionReconstructor,
    connection_id_for,
)
from agent_probe.llm.usage import UsageStatus

from llm.fixtures import (
    anthropic_sse_body,
    byte_chunks,
    http_request,
    http_response,
    openai_json_body,
    openai_sse_body,
)

CLIENT = Direction.CLIENT_TO_SERVER
SERVER = Direction.SERVER_TO_CLIENT


def chat_request(body: bytes = b'{"model":"gpt-4o-mini","stream":false}') -> bytes:
    return http_request(body=body)


def chat_response(body: bytes, *, content_type: str = "application/json") -> bytes:
    return http_response(body, headers=(("Content-Type", content_type),))


def drive(reconstructor: ConnectionReconstructor, pairs: list[tuple[Direction, bytes]], *, size: int = 1) -> None:
    for direction, wire in pairs:
        for index in range(0, len(wire), size):
            reconstructor.feed(direction, wire[index : index + size])


# ----------------------------------------------------------------------
# 单次往返
# ----------------------------------------------------------------------


def test_single_exchange_produces_one_record_with_usage_and_cost() -> None:
    reconstructor = ConnectionReconstructor("conn-1", price_table=DEFAULT_PRICE_TABLE)
    drive(reconstructor, [(CLIENT, chat_request()), (SERVER, chat_response(openai_json_body()))])

    assert len(reconstructor.records) == 1
    record = reconstructor.records[0]
    assert record.physical_request_id == "conn-1:req:1"
    assert record.logical_call_id == "conn-1:req:1"
    assert record.request_index == 1
    assert record.response_index == 1
    assert record.method == "POST"
    assert record.target == "/v1/chat/completions"
    assert record.status_code == 200
    assert record.is_paired
    assert record.model == "gpt-4o-mini"
    assert record.usage is not None and record.usage.status is UsageStatus.PRESENT
    assert record.completion is not None
    assert record.completion.completion is StreamCompletion.COMPLETE
    assert record.cost is not None and record.cost.complete
    assert record.cost.total_cost == Decimal("0.000036")
    assert not record.is_transport_truncated


def test_no_price_table_means_no_cost() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    drive(reconstructor, [(CLIENT, chat_request()), (SERVER, chat_response(openai_json_body()))])
    assert reconstructor.records[0].cost is None


def test_byte_by_byte_exchange() -> None:
    reconstructor = ConnectionReconstructor("conn-1", price_table=DEFAULT_PRICE_TABLE)
    request = chat_request()
    response = chat_response(openai_json_body())
    for direction, wire in ((CLIENT, request), (SERVER, response)):
        for byte in byte_chunks(wire):
            reconstructor.feed(direction, byte)
    record = reconstructor.records[0]
    assert record.usage is not None and record.usage.usage is not None
    assert record.usage.usage.input_tokens == 120


def test_sse_streaming_exchange() -> None:
    reconstructor = ConnectionReconstructor("conn-1", price_table=DEFAULT_PRICE_TABLE)
    drive(
        reconstructor,
        [
            (CLIENT, chat_request(b'{"model":"gpt-4o-mini","stream":true}')),
            (SERVER, chat_response(openai_sse_body(), content_type="text/event-stream")),
        ],
    )
    record = reconstructor.records[0]
    assert record.analysis is not None
    assert record.analysis.content_kind is ContentKind.SSE
    assert record.analysis.sse_finish is not None and record.analysis.sse_finish.saw_done
    assert record.completion is not None and record.completion.saw_done
    assert record.usage is not None and record.usage.usage is not None
    assert record.usage.usage.output_tokens == 30
    assert record.cost is not None and record.cost.complete


def test_gzipped_sse_exchange() -> None:
    reconstructor = ConnectionReconstructor("conn-1", price_table=DEFAULT_PRICE_TABLE)
    body = openai_sse_body()
    wire = http_response(
        body, encoding="gzip", headers=(("Content-Type", "text/event-stream"),)
    )
    drive(reconstructor, [(CLIENT, chat_request()), (SERVER, wire)], size=7)
    assert reconstructor.records[0].usage is not None
    assert reconstructor.records[0].usage.status is UsageStatus.PRESENT


def test_chunked_exchange_with_anthropic_cache_details() -> None:
    reconstructor = ConnectionReconstructor("conn-1", price_table=DEFAULT_PRICE_TABLE)
    wire = http_response(
        anthropic_sse_body(),
        framing="chunked",
        chunk_size=11,
        headers=(("Content-Type", "text/event-stream"),),
    )
    drive(reconstructor, [(CLIENT, chat_request()), (SERVER, wire)], size=3)
    record = reconstructor.records[0]
    assert record.usage is not None and record.usage.usage is not None
    usage = record.usage.usage
    assert (usage.input_tokens, usage.output_tokens) == (200, 40)
    assert usage.cache_read_included_in_input is False
    assert record.cost is not None and record.cost.complete


# ----------------------------------------------------------------------
# 连接复用
# ----------------------------------------------------------------------


def test_connection_reuse_produces_records_in_order() -> None:
    reconstructor = ConnectionReconstructor("conn-1", price_table=DEFAULT_PRICE_TABLE)
    pairs = []
    for index in (1, 2, 3):
        pairs.append((CLIENT, chat_request(b'{"n":%d}' % index)))
        pairs.append((SERVER, chat_response(openai_json_body(prompt_tokens=index))))
    drive(reconstructor, pairs, size=5)

    records = reconstructor.records
    assert [record.request_index for record in records] == [1, 2, 3]
    assert [record.response_index for record in records] == [1, 2, 3]
    assert [record.physical_request_id for record in records] == [
        "conn-1:req:1",
        "conn-1:req:2",
        "conn-1:req:3",
    ]
    assert [record.usage.usage.input_tokens for record in records if record.usage] == [1, 2, 3]
    assert reconstructor.pending_request_count == 0


def test_interleaved_pipelined_exchange_keeps_pairing() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    request = chat_request()
    response = chat_response(openai_json_body())
    # 请求 1 → 请求 2 → 响应 1 → 响应 2（流水线）
    drive(
        reconstructor,
        [
            (CLIENT, request),
            (CLIENT, request),
            (SERVER, response),
            (SERVER, response),
        ],
        size=4,
    )
    records = reconstructor.records
    assert len(records) == 2
    assert [record.response_index for record in records] == [1, 2]
    assert all(record.is_paired for record in records)


def test_multiple_connections_are_isolated() -> None:
    multi = MultiConnectionReconstructor(price_table=DEFAULT_PRICE_TABLE)
    request = chat_request()
    response = chat_response(openai_json_body())
    for _ in range(2):
        multi.feed(connection_id_for(1), CLIENT, request)
        multi.feed(connection_id_for(2), CLIENT, request)
        multi.feed(connection_id_for(1), SERVER, response)
        multi.feed(connection_id_for(2), SERVER, response)

    assert multi.connection_ids == ("conn-1", "conn-2")
    by_connection: dict[str, list[int]] = {}
    for record in multi.records:
        by_connection.setdefault(record.connection_id, []).append(record.response_index or 0)
    assert by_connection == {"conn-1": [1, 2], "conn-2": [1, 2]}
    assert len(multi.records) == 4


def test_connection_id_for_is_deterministic() -> None:
    assert connection_id_for(1) == "conn-1"
    assert connection_id_for(42) == "conn-42"
    with pytest.raises(ValueError):
        connection_id_for(0)


# ----------------------------------------------------------------------
# 配对缺口
# ----------------------------------------------------------------------


def test_response_without_request_is_reported_and_recorded() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    reconstructor.feed(SERVER, chat_response(openai_json_body()))
    record = reconstructor.records[0]
    assert record.request is None
    assert record.response is not None
    assert record.physical_request_id == "conn-1:unmatched-response:1"
    assert DiagnosticCode.RESPONSE_WITHOUT_REQUEST in {
        diagnostic.code for diagnostic in record.diagnostics
    }


def test_request_without_response_is_reported_at_finish() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    reconstructor.feed(CLIENT, chat_request())
    assert reconstructor.pending_request_count == 1
    batch = reconstructor.finish()
    assert len(batch.records) == 1
    record = batch.records[0]
    assert record.response is None
    assert record.analysis is None
    assert record.usage is None
    assert DiagnosticCode.REQUEST_WITHOUT_RESPONSE in {
        diagnostic.code for diagnostic in record.diagnostics
    }


def test_truncated_response_keeps_capture_gap_visible() -> None:
    reconstructor = ConnectionReconstructor(
        "conn-1", limits=ParserLimits(max_body_bytes=8), price_table=DEFAULT_PRICE_TABLE
    )
    reconstructor.feed(CLIENT, chat_request())
    reconstructor.feed(SERVER, chat_response(openai_json_body()))
    record = reconstructor.records[0]
    assert record.response is not None and not record.response.payload_complete
    assert record.usage is not None and record.usage.status is UsageStatus.NOT_CAPTURED
    assert record.cost is not None and record.cost.total_cost is None
    assert record.cost.unknown_reasons[0].value == "usage_not_captured"


def test_informational_response_does_not_consume_the_pairing() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    reconstructor.feed(CLIENT, chat_request())
    reconstructor.feed(SERVER, b"HTTP/1.1 100 Continue\r\n\r\n")
    assert reconstructor.records == ()
    reconstructor.feed(SERVER, chat_response(openai_json_body()))
    record = reconstructor.records[0]
    assert record.status_code == 200
    assert record.request is not None


# ----------------------------------------------------------------------
# 重试与计账
# ----------------------------------------------------------------------


def test_explicit_retry_is_grouped_into_one_logical_call() -> None:
    registry = RetryRegistry()
    registry.link_retry(
        physical_request_id="conn-1:req:2",
        retry_of="conn-1:req:1",
        reason="provider returned 429",
        evidence=RetryEvidence.APPLICATION_MARKER,
    )
    reconstructor = ConnectionReconstructor(
        "conn-1", price_table=DEFAULT_PRICE_TABLE, retry_registry=registry
    )
    drive(
        reconstructor,
        [
            (CLIENT, chat_request()),
            (SERVER, chat_response(openai_json_body())),
            (CLIENT, chat_request()),
            (SERVER, chat_response(openai_json_body())),
        ],
        size=8,
    )
    ledger = AccountingLedger(retry_registry=registry)
    ledger.extend(reconstructor.records)

    records = ledger.records
    assert [record.identity.attempt_index for record in records] == [1, 2]
    assert {record.logical_call_id for record in records} == {"conn-1:req:1"}
    assert records[1].identity.retry_of == "conn-1:req:1"
    assert records[1].identity.retry_evidence is RetryEvidence.APPLICATION_MARKER

    summary = ledger.summary()
    assert summary.physical_requests == 2
    assert summary.logical_calls == 1
    assert summary.retried_physical_requests == 1
    assert summary.total_tokens == 300
    assert summary.estimated_cost == Decimal("0.000072")


def test_records_without_retry_declaration_are_not_grouped() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    drive(
        reconstructor,
        [
            (CLIENT, chat_request()),
            (SERVER, chat_response(openai_json_body())),
            (CLIENT, chat_request()),
            (SERVER, chat_response(openai_json_body())),
        ],
    )
    ledger = AccountingLedger()
    ledger.extend(reconstructor.records)
    assert ledger.summary().logical_calls == 2
    assert ledger.summary().retried_physical_requests == 0


def test_ledger_deduplicates_records_from_repeated_replay() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    drive(reconstructor, [(CLIENT, chat_request()), (SERVER, chat_response(openai_json_body()))])
    record = reconstructor.records[0]
    ledger = AccountingLedger()
    assert ledger.record(record) is True
    assert ledger.record(record) is False
    summary = ledger.summary()
    assert summary.physical_requests == 1
    assert summary.duplicate_physical_requests == 1
    assert summary.input_tokens == 120


# ----------------------------------------------------------------------
# 门面行为
# ----------------------------------------------------------------------


def test_finish_is_idempotent_and_feed_after_finish_raises() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    reconstructor.finish()
    assert not reconstructor.finish().records
    with pytest.raises(RuntimeError):
        reconstructor.feed(CLIENT, chat_request())


def test_feed_rejects_unknown_direction() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    with pytest.raises(ValueError):
        reconstructor.feed("sideways", b"x")  # type: ignore[arg-type]


def test_connection_id_is_required() -> None:
    with pytest.raises(ValueError):
        ConnectionReconstructor("")


def test_multi_connection_close_returns_batches() -> None:
    multi = MultiConnectionReconstructor()
    multi.feed("conn-1", CLIENT, chat_request())
    multi.feed("conn-1", SERVER, chat_response(openai_json_body()))
    multi.feed("conn-2", CLIENT, chat_request())
    batches = multi.close_all()
    assert len(batches) == 2
    assert len(multi.records) == 2
    assert not multi.close("unknown").records


def test_record_view_is_json_safe_and_contains_no_bodies() -> None:
    reconstructor = ConnectionReconstructor("conn-1", price_table=DEFAULT_PRICE_TABLE)
    prompt = b'{"model":"gpt-4o-mini","messages":[{"content":"PROMPT-SECRET"}]}'
    reconstructor.feed(CLIENT, http_request(body=prompt))
    reconstructor.feed(SERVER, chat_response(openai_json_body()))
    record = reconstructor.records[0].to_record()
    serialized = json.dumps(record, ensure_ascii=False)
    assert "PROMPT-SECRET" not in serialized
    assert "Hello" not in serialized
    assert record["request"]["payload_available"] is True
    assert record["paired"] is True


def test_parser_diagnostics_are_attached_to_the_record() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    reconstructor.feed(CLIENT, chat_request())
    wire = http_response(
        b'{}', headers=(("Content-Type", "application/json"),)
    )
    reconstructor.feed(SERVER, wire)
    codes = {diagnostic.code for diagnostic in reconstructor.records[0].diagnostics}
    assert DiagnosticCode.USAGE_ABSENT in codes


def test_unparseable_body_diagnostics_reach_the_record() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    reconstructor.feed(CLIENT, chat_request())
    reconstructor.feed(SERVER, chat_response(b"not-json"))
    codes = {diagnostic.code for diagnostic in reconstructor.records[0].diagnostics}
    assert DiagnosticCode.USAGE_UNPARSEABLE in codes


def test_custom_price_table_is_used_for_estimation() -> None:
    from datetime import date as _date

    from agent_probe.llm.pricing import ModelPrice, PricingUnit

    table = PriceTable(
        version="custom-1",
        effective_date=_date(2026, 5, 1),
        unit=PricingUnit.PER_MILLION_TOKENS,
        currency="EUR",
        verified=True,
        entries=(ModelPrice("gpt-4o-mini", "1", "2"),),
    )
    reconstructor = ConnectionReconstructor("conn-1", price_table=table)
    drive(reconstructor, [(CLIENT, chat_request()), (SERVER, chat_response(openai_json_body()))])
    cost = reconstructor.records[0].cost
    assert cost is not None
    assert cost.currency == "EUR"
    assert cost.price_table_version == "custom-1"
