"""provider-neutral usage 提取测试：缺失为 ``None``、不填零、状态可区分。"""

from __future__ import annotations

import json

import pytest

from agent_probe.llm.common import Direction
from agent_probe.llm.http1 import Http1Parser
from agent_probe.llm.messages import HttpResponse
from agent_probe.llm.sse import SseParser
from agent_probe.llm.usage import (
    UsageStatus,
    extract_usage_from_json,
    extract_usage_from_json_object,
    extract_usage_from_message,
    extract_usage_from_sse_events,
)

from llm.fixtures import (
    anthropic_json_body,
    anthropic_sse_body,
    http_response,
    openai_json_body,
    openai_sse_body,
    raw_response,
)

RESPONSE = Direction.SERVER_TO_CLIENT


def parse_response(wire: bytes) -> HttpResponse:
    parser = Http1Parser(RESPONSE)
    messages = list(parser.feed(wire).messages)
    messages.extend(parser.finish().messages)
    assert len(messages) == 1
    message = messages[0]
    assert isinstance(message, HttpResponse)
    return message


def sse_events(body: bytes):
    parser = SseParser()
    events = list(parser.feed(body))
    finish = parser.finish()
    events.extend(finish.events)
    return tuple(events), finish


# ----------------------------------------------------------------------
# JSON
# ----------------------------------------------------------------------


def test_openai_json_usage_is_extracted_field_by_field() -> None:
    extraction = extract_usage_from_json(openai_json_body(prompt_tokens=120, completion_tokens=30))
    assert extraction.status is UsageStatus.PRESENT
    usage = extraction.usage
    assert usage is not None
    assert usage.model == "gpt-4o-mini"
    assert usage.input_tokens == 120
    assert usage.output_tokens == 30
    assert usage.total_tokens == 150
    assert usage.cache_read_tokens is None
    assert usage.reasoning_tokens is None
    assert usage.provider == "openai"
    assert usage.fields_reported == frozenset({"input_tokens", "output_tokens", "total_tokens"})
    assert usage.raw["prompt_tokens"] == 120
    assert extraction.model_name == "gpt-4o-mini"


def test_missing_usage_is_absent_and_never_zero() -> None:
    body = b'{"model":"gpt-4o-mini","choices":[{"finish_reason":"stop"}]}'
    extraction = extract_usage_from_json(body)
    assert extraction.status is UsageStatus.ABSENT
    assert extraction.usage is None
    assert extraction.present is False
    assert "usage" in (extraction.detail or "")


def test_absent_usage_keys_are_none_not_zero() -> None:
    extraction = extract_usage_from_json(b'{"usage":{"prompt_tokens":5}}')
    usage = extraction.usage
    assert usage is not None
    assert usage.input_tokens == 5
    assert usage.output_tokens is None
    assert usage.total_tokens is None
    assert usage.cache_read_tokens is None


def test_explicit_zero_is_preserved_as_zero() -> None:
    extraction = extract_usage_from_json(
        b'{"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}'
    )
    usage = extraction.usage
    assert usage is not None
    assert usage.input_tokens == 0
    assert usage.output_tokens == 0
    assert usage.total_tokens == 0
    assert usage.is_empty is False


def test_empty_usage_object_is_absent() -> None:
    extraction = extract_usage_from_json(b'{"usage":{}}')
    assert extraction.status is UsageStatus.ABSENT
    assert extraction.usage is None


def test_unparseable_json_is_reported_as_unparseable() -> None:
    extraction = extract_usage_from_json(b'{"usage":{"prompt_tokens":')
    assert extraction.status is UsageStatus.UNPARSEABLE
    assert extraction.usage is None


def test_non_object_json_is_unparseable() -> None:
    assert extract_usage_from_json(b"[1,2,3]").status is UsageStatus.UNPARSEABLE


def test_empty_body_is_unparseable() -> None:
    assert extract_usage_from_json(b"   ").status is UsageStatus.UNPARSEABLE


def test_non_utf8_body_is_unparseable() -> None:
    assert extract_usage_from_json(b"\xff\xfe\x00").status is UsageStatus.UNPARSEABLE


def test_cached_tokens_from_prompt_details_are_marked_included() -> None:
    extraction = extract_usage_from_json(openai_json_body(cached_tokens=40))
    usage = extraction.usage
    assert usage is not None
    assert usage.cache_read_tokens == 40
    assert usage.cache_read_included_in_input is True
    assert "cache_read_tokens" in usage.fields_reported


def test_reasoning_tokens_are_marked_included_in_output() -> None:
    extraction = extract_usage_from_json(openai_json_body(reasoning_tokens=12))
    usage = extraction.usage
    assert usage is not None
    assert usage.reasoning_tokens == 12
    assert usage.reasoning_included_in_output is True


def test_responses_api_style_aliases_are_supported() -> None:
    body = (
        b'{"model":"gpt-4.1","usage":{"input_tokens":10,"output_tokens":4,'
        b'"total_tokens":14,"input_tokens_details":{"cached_tokens":3}}}'
    )
    usage = extract_usage_from_json(body).usage
    assert usage is not None
    assert usage.input_tokens == 10
    assert usage.output_tokens == 4
    assert usage.cache_read_tokens == 3
    assert usage.cache_read_included_in_input is True


def test_anthropic_cache_details_are_not_included_in_input() -> None:
    body = anthropic_json_body(input_tokens=200, output_tokens=40, cache_read=15, cache_creation=5)
    usage = extract_usage_from_json(body).usage
    assert usage is not None
    assert usage.input_tokens == 200
    assert usage.cache_read_tokens == 15
    assert usage.cache_write_tokens == 5
    assert usage.cache_read_included_in_input is False
    assert usage.cache_write_included_in_input is False
    assert usage.provider == "anthropic"


def test_string_and_float_integer_values_are_accepted() -> None:
    extraction = extract_usage_from_json(
        b'{"usage":{"prompt_tokens":"12","completion_tokens":8.0,"total_tokens":20}}'
    )
    usage = extraction.usage
    assert usage is not None
    assert usage.input_tokens == 12
    assert usage.output_tokens == 8


def test_boolean_values_are_not_treated_as_counts() -> None:
    extraction = extract_usage_from_json(b'{"usage":{"prompt_tokens":true}}')
    usage = extraction.usage
    assert usage is not None
    assert usage.input_tokens is None


def test_json_object_input_and_mapping_are_equivalent() -> None:
    payload = json.loads(openai_json_body().decode())
    assert extract_usage_from_json_object(payload).to_record() == extract_usage_from_json(
        openai_json_body()
    ).to_record()


def test_usage_record_does_not_leak_prompt_text() -> None:
    body = b'{"model":"m","messages":[{"content":"SECRET PROMPT"}],"usage":{"prompt_tokens":1}}'
    record = extract_usage_from_json(body).to_record()
    assert "SECRET PROMPT" not in json.dumps(record)


# ----------------------------------------------------------------------
# SSE
# ----------------------------------------------------------------------


def test_openai_sse_usage_from_final_chunk() -> None:
    events, _ = sse_events(openai_sse_body(prompt_tokens=11, completion_tokens=3))
    extraction = extract_usage_from_sse_events(events)
    assert extraction.status is UsageStatus.PRESENT
    usage = extraction.usage
    assert usage is not None
    assert usage.input_tokens == 11
    assert usage.output_tokens == 3
    assert usage.total_tokens == 14
    assert usage.model == "gpt-4o-mini"


def test_openai_sse_without_include_usage_is_absent() -> None:
    events, _ = sse_events(openai_sse_body(include_usage=False))
    extraction = extract_usage_from_sse_events(events)
    assert extraction.status is UsageStatus.ABSENT
    assert extraction.usage is None
    assert extraction.model == "gpt-4o-mini"


def test_sse_truncated_without_usage_is_not_captured() -> None:
    events, finish = sse_events(openai_sse_body(include_usage=False, sentinel=False))
    extraction = extract_usage_from_sse_events(events, truncated=True)
    assert extraction.status is UsageStatus.NOT_CAPTURED
    assert finish.saw_done is False


def test_anthropic_sse_merges_message_start_and_delta() -> None:
    events, _ = sse_events(anthropic_sse_body(input_tokens=200, output_tokens=40))
    extraction = extract_usage_from_sse_events(events)
    usage = extraction.usage
    assert usage is not None
    assert usage.input_tokens == 200
    assert usage.output_tokens == 40
    assert usage.cache_read_tokens == 12
    assert usage.cache_write_tokens == 8
    assert usage.cache_read_included_in_input is False
    assert usage.model == "claude-3-5-sonnet-20241022"


def test_sse_all_unparseable_json_events_are_unparseable() -> None:
    parser = SseParser()
    events = list(parser.feed(b"data: {broken\n\ndata: {also broken\n\n"))
    events.extend(parser.finish().events)
    extraction = extract_usage_from_sse_events(events)
    assert extraction.status is UsageStatus.UNPARSEABLE


def test_done_sentinel_is_not_parsed_as_json() -> None:
    events, _ = sse_events(b"data: [DONE]\n\n")
    extraction = extract_usage_from_sse_events(events)
    assert extraction.status is UsageStatus.ABSENT


# ----------------------------------------------------------------------
# 消息级分派
# ----------------------------------------------------------------------


def test_message_level_json_extraction() -> None:
    wire = http_response(
        openai_json_body(), headers=(("Content-Type", "application/json"),)
    )
    extraction = extract_usage_from_message(parse_response(wire))
    assert extraction.status is UsageStatus.PRESENT
    assert extraction.usage is not None and extraction.usage.input_tokens == 120


def test_message_level_sse_extraction() -> None:
    wire = http_response(
        openai_sse_body(), headers=(("Content-Type", "text/event-stream"),)
    )
    extraction = extract_usage_from_message(parse_response(wire))
    assert extraction.status is UsageStatus.PRESENT
    assert extraction.usage is not None and extraction.usage.output_tokens == 30


def test_message_level_sse_content_type_with_charset() -> None:
    wire = http_response(
        openai_sse_body(), headers=(("Content-Type", "text/event-stream; charset=utf-8"),)
    )
    extraction = extract_usage_from_message(parse_response(wire))
    assert extraction.status is UsageStatus.PRESENT


def test_unsupported_encoding_yields_not_captured() -> None:
    wire = raw_response(b"\x00raw", headers=(("Content-Encoding", "br"),))
    message = parse_response(wire)
    assert message.payload is None
    extraction = extract_usage_from_message(message)
    assert extraction.status is UsageStatus.NOT_CAPTURED
    assert extraction.usage is None


def test_truncated_json_body_is_not_captured_not_unparseable() -> None:
    body = openai_json_body()
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n" + body[:50]
    message = parse_response(wire)
    assert not message.complete
    extraction = extract_usage_from_message(message, truncated=True)
    assert extraction.status is UsageStatus.NOT_CAPTURED


def test_truncated_sse_body_still_yields_present_usage_if_it_arrived() -> None:
    body = openai_sse_body()
    wire = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 5000\r\n\r\n" + body
    message = parse_response(wire)
    assert not message.complete
    extraction = extract_usage_from_message(message, truncated=True)
    assert extraction.status is UsageStatus.PRESENT


@pytest.mark.parametrize(
    "status",
    [UsageStatus.ABSENT, UsageStatus.UNPARSEABLE, UsageStatus.NOT_CAPTURED],
)
def test_usage_status_records_are_json_safe(status: UsageStatus) -> None:
    from agent_probe.llm.usage import UsageExtraction

    record = UsageExtraction(status=status, detail="x").to_record()
    assert record["status"] == status.value
    assert record["usage"] is None
    assert json.loads(json.dumps(record))["status"] == status.value
