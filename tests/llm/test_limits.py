"""上限配置验证与超限诊断测试（"限制连接缓存、单请求内容和解压大小"）。"""

from __future__ import annotations

import pytest

from agent_probe.llm.common import Direction
from agent_probe.llm.diagnostics import DiagnosticCode
from agent_probe.llm.http1 import Http1Parser, ParserState
from agent_probe.llm.limits import ParserLimits, SseLimits

RESPONSE = Direction.SERVER_TO_CLIENT
REQUEST = Direction.CLIENT_TO_SERVER


def run(parser: Http1Parser, wire: bytes):
    batch = parser.feed(wire)
    messages = list(batch.messages)
    diagnostics = list(batch.diagnostics)
    finish = parser.finish()
    messages.extend(finish.messages)
    diagnostics.extend(finish.diagnostics)
    return messages, diagnostics


@pytest.mark.parametrize(
    "field",
    [
        "max_start_line_bytes",
        "max_header_bytes",
        "max_headers",
        "max_body_bytes",
        "max_decompressed_bytes",
        "max_chunk_line_bytes",
        "max_trailer_bytes",
        "max_pending_requests",
    ],
)
@pytest.mark.parametrize("value", [0, -1, True])
def test_parser_limits_reject_non_positive_values(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        ParserLimits(**{field: value})


@pytest.mark.parametrize("field", ["max_event_bytes", "max_data_lines"])
@pytest.mark.parametrize("value", [0, -5, False])
def test_sse_limits_reject_non_positive_values(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        SseLimits(**{field: value})


def test_default_limits_are_finite_and_ordered() -> None:
    limits = ParserLimits()
    assert 0 < limits.max_header_bytes
    assert limits.max_body_bytes > 0
    assert limits.max_decompressed_bytes > limits.max_body_bytes
    assert 0 < limits.max_chunk_line_bytes <= limits.max_header_bytes


def test_start_line_too_large_is_fatal() -> None:
    wire = b"GET /" + b"a" * 200 + b" HTTP/1.1\r\nHost: x\r\n\r\n"
    parser = Http1Parser(REQUEST, limits=ParserLimits(max_start_line_bytes=32))
    messages, diagnostics = run(parser, wire)
    assert messages == []
    assert DiagnosticCode.START_LINE_TOO_LARGE in {d.code for d in diagnostics}
    assert parser.state is ParserState.FAILED


def test_chunk_line_too_large_is_fatal() -> None:
    wire = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        + b"3" + b" " * 100 + b"\r\nabc\r\n0\r\n\r\n"
    )
    parser = Http1Parser(RESPONSE, limits=ParserLimits(max_chunk_line_bytes=16))
    messages, diagnostics = run(parser, wire)
    assert DiagnosticCode.CHUNK_LINE_TOO_LARGE in {d.code for d in diagnostics}
    assert parser.failed
    assert all(not message.complete for message in messages)


def test_trailer_too_large_is_fatal() -> None:
    wire = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"
        + b"X-T: " + b"v" * 200 + b"\r\n\r\n"
    )
    parser = Http1Parser(RESPONSE, limits=ParserLimits(max_trailer_bytes=32))
    messages, diagnostics = run(parser, wire)
    assert DiagnosticCode.TRAILER_TOO_LARGE in {d.code for d in diagnostics}
    assert parser.failed


def test_gzip_bomb_is_bounded_by_decompressed_limit() -> None:
    # 1 MiB 的零字节压缩后极小；解压上限必须挡住它。
    from llm.fixtures import gzip_bytes, raw_response

    payload = gzip_bytes(b"\x00" * (1024 * 1024))
    assert len(payload) < 4096
    wire = raw_response(payload, headers=(("Content-Encoding", "gzip"),))
    parser = Http1Parser(RESPONSE, limits=ParserLimits(max_decompressed_bytes=4096))
    messages, diagnostics = run(parser, wire)
    assert len(messages) == 1
    assert messages[0].complete
    assert not messages[0].payload_complete
    assert messages[0].payload is not None and len(messages[0].payload) == 4096
    assert DiagnosticCode.DECOMPRESSED_TOO_LARGE in {d.code for d in diagnostics}


def test_pending_request_context_is_bounded_by_limit() -> None:
    parser = Http1Parser(RESPONSE, limits=ParserLimits(max_pending_requests=1))
    parser.register_request("POST")
    parser.register_request("POST")
    assert parser.dropped_request_contexts == 1
