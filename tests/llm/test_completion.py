"""完整性（传输层）与停止原因（提供方语义）分离的测试。

核心论断：``finish_reason`` 不是 ``stop`` **不等于**断流；只有字节流层面缺少
终止证据（提前 EOF / 截断 / 未分帧残留）才算 ``TRUNCATED``。
"""

from __future__ import annotations

import json

import pytest

from agent_probe.llm.common import Direction
from agent_probe.llm.completion import (
    ContentKind,
    StopKind,
    StreamCompletion,
    analyze_payload,
    classify_stop,
)
from agent_probe.llm.http1 import Http1Parser
from agent_probe.llm.messages import HttpResponse
from agent_probe.llm.usage import UsageStatus

from llm.fixtures import anthropic_sse_body, http_response, openai_json_body, openai_sse_body, raw_response

RESPONSE = Direction.SERVER_TO_CLIENT


def parse_response(wire: bytes) -> HttpResponse:
    parser = Http1Parser(RESPONSE)
    messages = list(parser.feed(wire).messages)
    messages.extend(parser.finish().messages)
    assert len(messages) == 1
    message = messages[0]
    assert isinstance(message, HttpResponse)
    return message


def analyze(wire: bytes):
    return analyze_payload(parse_response(wire))


def json_response(**kwargs) -> bytes:
    return http_response(
        openai_json_body(**kwargs), headers=(("Content-Type", "application/json"),)
    )


def sse_response(body: bytes) -> bytes:
    return http_response(body, headers=(("Content-Type", "text/event-stream"),))


# ----------------------------------------------------------------------
# 停止原因分类
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("stop", StopKind.STOP),
        ("end_turn", StopKind.STOP),
        ("stop_sequence", StopKind.STOP),
        ("length", StopKind.LENGTH),
        ("max_tokens", StopKind.LENGTH),
        ("tool_calls", StopKind.TOOL_CALLS),
        ("tool_use", StopKind.TOOL_CALLS),
        ("function_call", StopKind.TOOL_CALLS),
        ("content_filter", StopKind.CONTENT_FILTER),
        ("safety", StopKind.CONTENT_FILTER),
        ("error", StopKind.ERROR),
        ("something_new", StopKind.OTHER),
        (None, StopKind.UNKNOWN),
        ("", StopKind.UNKNOWN),
    ],
)
def test_classify_stop(reason: str | None, expected: StopKind) -> None:
    assert classify_stop(reason) is expected


@pytest.mark.parametrize("reason", ["length", "content_filter", "tool_calls"])
def test_non_stop_finish_reason_is_complete_not_truncated(reason: str) -> None:
    analysis = analyze(json_response(finish_reason=reason))
    assert analysis.completion.completion is StreamCompletion.COMPLETE
    assert not analysis.completion.is_truncated
    assert analysis.completion.truncated_reasons == ()
    assert analysis.completion.finish_reasons == (reason,)
    assert analysis.completion.stop_kinds == (classify_stop(reason),)


# ----------------------------------------------------------------------
# JSON
# ----------------------------------------------------------------------


def test_json_response_with_finish_reason_is_complete() -> None:
    analysis = analyze(json_response())
    assert analysis.content_kind is ContentKind.JSON
    assert analysis.completion.completion is StreamCompletion.COMPLETE
    assert analysis.completion.finish_reasons == ("stop",)
    assert set(analysis.completion.terminal_evidence) == {"finish_reason", "http_message_complete"}
    assert analysis.usage.status is UsageStatus.PRESENT
    assert analysis.model == "gpt-4o-mini"


def test_json_response_without_finish_reason_is_still_complete() -> None:
    body = b'{"model":"m","usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}'
    analysis = analyze(http_response(body, headers=(("Content-Type", "application/json"),)))
    assert analysis.completion.completion is StreamCompletion.COMPLETE
    assert analysis.completion.finish_reasons == ()
    assert analysis.completion.terminal_evidence == ("http_message_complete",)


def test_truncated_json_response_is_truncated() -> None:
    body = openai_json_body()
    wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9999\r\n\r\n" + body
    analysis = analyze(wire)
    assert analysis.completion.completion is StreamCompletion.TRUNCATED
    assert analysis.completion.truncated_reasons
    # usage 可用性与"消息完整性"是两个独立维度：正文本身仍可完整解析为 JSON。
    assert analysis.usage.status is UsageStatus.PRESENT


def test_unparseable_complete_json_is_unknown_not_truncated() -> None:
    analysis = analyze(http_response(b"not json", headers=(("Content-Type", "application/json"),)))
    assert analysis.completion.completion is StreamCompletion.UNKNOWN
    assert not analysis.completion.is_truncated
    assert analysis.usage.status is UsageStatus.UNPARSEABLE


def test_empty_body_is_reported_as_empty() -> None:
    analysis = analyze(http_response(b"", headers=(("Content-Type", "application/json"),)))
    assert analysis.content_kind is ContentKind.EMPTY
    assert analysis.completion.completion is StreamCompletion.UNKNOWN
    assert analysis.usage.status is UsageStatus.UNPARSEABLE


def test_unavailable_payload_with_complete_message_is_unknown() -> None:
    analysis = analyze(raw_response(b"\x00", headers=(("Content-Encoding", "br"),)))
    assert analysis.content_kind is ContentKind.UNAVAILABLE
    assert analysis.completion.completion is StreamCompletion.UNKNOWN
    assert analysis.usage.status is UsageStatus.NOT_CAPTURED


def test_unavailable_payload_with_incomplete_message_is_truncated() -> None:
    wire = b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 100\r\n\r\n\x00"
    analysis = analyze(wire)
    assert analysis.content_kind is ContentKind.UNAVAILABLE
    assert analysis.completion.completion is StreamCompletion.TRUNCATED


# ----------------------------------------------------------------------
# SSE
# ----------------------------------------------------------------------


def test_sse_with_done_sentinel_is_complete() -> None:
    analysis = analyze(sse_response(openai_sse_body()))
    assert analysis.content_kind is ContentKind.SSE
    assert analysis.completion.completion is StreamCompletion.COMPLETE
    assert analysis.completion.saw_done is True
    assert "sse_done" in analysis.completion.terminal_evidence
    assert analysis.completion.finish_reasons == ("stop",)
    assert analysis.usage.status is UsageStatus.PRESENT
    assert analysis.sse_finish is not None and analysis.sse_finish.event_count == 5


def test_sse_with_finish_reason_but_no_done_is_complete() -> None:
    analysis = analyze(sse_response(openai_sse_body(sentinel=False)))
    assert analysis.completion.completion is StreamCompletion.COMPLETE
    assert analysis.completion.saw_done is False
    assert analysis.completion.terminal_evidence == ("finish_reason",)


def test_sse_clean_eof_without_any_terminal_evidence_is_unknown() -> None:
    body = openai_sse_body(chunks=(("partial", None),), include_usage=False, sentinel=False)
    analysis = analyze(sse_response(body))
    assert analysis.completion.completion is StreamCompletion.UNKNOWN
    assert not analysis.completion.is_truncated
    assert analysis.completion.truncated_reasons == ()


def test_sse_cut_mid_event_is_truncated() -> None:
    body = openai_sse_body()[:-4]  # 掐掉 [DONE]\n\n 的一部分
    wire = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 9999\r\n\r\n"
        + body
    )
    analysis = analyze(wire)
    assert analysis.completion.completion is StreamCompletion.TRUNCATED
    assert analysis.completion.truncated_reasons
    assert analysis.completion.finish_reasons == ("stop",)


def test_sse_cut_after_done_sentinel_still_complete() -> None:
    body = openai_sse_body()
    wire = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
        + f"Content-Length: {len(body) + 32}\r\n\r\n".encode()
        + body
    )
    analysis = analyze(wire)
    # 流自己的结束标记已到达：内容完整，但字节层不完整事实仍被记录。
    assert analysis.completion.completion is StreamCompletion.COMPLETE
    assert analysis.completion.saw_done
    assert analysis.completion.truncated_reasons
    assert analysis.usage.status is UsageStatus.PRESENT


def test_sse_truncated_stream_keeps_usage_if_it_arrived() -> None:
    body = openai_sse_body()  # usage chunk 在 [DONE] 之前
    wire = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 9999\r\n\r\n"
        + body
    )
    analysis = analyze(wire)
    assert analysis.completion.completion is StreamCompletion.COMPLETE
    assert analysis.completion.saw_done
    assert analysis.usage.status is UsageStatus.PRESENT


def test_anthropic_sse_message_stop_is_terminal_evidence() -> None:
    analysis = analyze(sse_response(anthropic_sse_body()))
    assert analysis.completion.completion is StreamCompletion.COMPLETE
    assert "sse_terminal_event" in analysis.completion.terminal_evidence
    assert analysis.completion.finish_reasons == ("end_turn",)
    assert analysis.completion.stop_kinds == (StopKind.STOP,)
    assert analysis.usage.status is UsageStatus.PRESENT


def test_anthropic_sse_without_terminal_event_is_unknown() -> None:
    analysis = analyze(sse_response(anthropic_sse_body(terminal=False)))
    # 仍有 stop_reason 作为终止证据
    assert analysis.completion.completion is StreamCompletion.COMPLETE
    assert analysis.completion.finish_reasons == ("end_turn",)


def test_sse_analysis_record_is_json_safe_and_has_no_event_body() -> None:
    analysis = analyze(sse_response(openai_sse_body()))
    record = analysis.to_record()
    assert json.loads(json.dumps(record))["content_kind"] == "sse"
    assert "Hello" not in json.dumps(record)


def test_gzip_sse_response_is_analyzed() -> None:
    body = openai_sse_body()
    wire = http_response(
        body, encoding="gzip", headers=(("Content-Type", "text/event-stream"),)
    )
    analysis = analyze(wire)
    assert analysis.completion.completion is StreamCompletion.COMPLETE
    assert analysis.usage.status is UsageStatus.PRESENT
