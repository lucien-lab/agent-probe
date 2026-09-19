"""HTTP/1.1 增量解析器的确定性回放测试。

每个"任意分片"用例都会对同一份字节跑多种分片方式（逐字节、所有单点切分、
固定块长），断言产出完全一致——这是"按连接方向喂入任意分片"的核心保证。
"""

from __future__ import annotations

import pytest

from agent_probe.llm.common import BodyFraming, Direction, MessageKind
from agent_probe.llm.diagnostics import DiagnosticCode, Severity
from agent_probe.llm.http1 import HTTP2_CONNECTION_PREFACE, Http1Parser, ParserState
from agent_probe.llm.limits import ParserLimits
from agent_probe.llm.messages import HeaderRedactionPolicy, HttpRequest, HttpResponse

from llm.fixtures import (
    all_splits,
    byte_chunks,
    chunked_body,
    fixed_chunks,
    gzip_bytes,
    http_request,
    http_response,
    openai_json_body,
    openai_sse_body,
    raw_response,
)

RESPONSE = Direction.SERVER_TO_CLIENT
REQUEST = Direction.CLIENT_TO_SERVER


def run(parser: Http1Parser, chunks: list[bytes]) -> tuple[list[object], list[object]]:
    messages: list[object] = []
    diagnostics: list[object] = []
    for chunk in chunks:
        batch = parser.feed(chunk)
        messages.extend(batch.messages)
        diagnostics.extend(batch.diagnostics)
    batch = parser.finish()
    messages.extend(batch.messages)
    diagnostics.extend(batch.diagnostics)
    return messages, diagnostics


def replay_all_splits(
    data: bytes,
    *,
    direction: Direction = RESPONSE,
    limits: ParserLimits | None = None,
    redaction: HeaderRedactionPolicy | None = None,
) -> list[tuple[list[object], list[object]]]:
    results = []
    for chunks in all_splits(data):
        parser = Http1Parser(direction, limits=limits, redaction=redaction)
        results.append(run(parser, chunks))
    return results


def errors(diagnostics: list[object]) -> list[object]:
    return [d for d in diagnostics if d.severity is Severity.ERROR]


def codes(diagnostics: list[object]) -> set[DiagnosticCode]:
    return {d.code for d in diagnostics}


# ----------------------------------------------------------------------
# 基本重建 + 任意分片
# ----------------------------------------------------------------------


def test_content_length_response_reassembles_under_any_split() -> None:
    body = openai_json_body()
    wire = http_response(body, headers=(("Content-Type", "application/json"),))

    results = replay_all_splits(wire)
    assert len(results) == len(all_splits(wire))
    for messages, diagnostics in results:
        assert len(messages) == 1
        message = messages[0]
        assert isinstance(message, HttpResponse)
        assert message.complete
        assert message.kind is MessageKind.RESPONSE
        assert message.status_code == 200
        assert message.reason_phrase == "OK"
        assert message.version == "HTTP/1.1"
        assert message.body_framing is BodyFraming.CONTENT_LENGTH
        assert message.payload == body
        assert message.payload_complete
        assert message.body_bytes == len(body)
        assert not errors(diagnostics)


def test_request_reassembles_under_any_split() -> None:
    wire = http_request(body=b'{"model":"gpt-4o-mini"}')
    for messages, diagnostics in replay_all_splits(wire, direction=REQUEST):
        assert len(messages) == 1
        message = messages[0]
        assert isinstance(message, HttpRequest)
        assert message.method == "POST"
        assert message.target == "/v1/chat/completions"
        assert message.payload == b'{"model":"gpt-4o-mini"}'
        assert not errors(diagnostics)


def test_byte_by_byte_feeds_do_not_emit_partial_messages() -> None:
    body = openai_json_body()
    wire = http_response(body)
    parser = Http1Parser(RESPONSE)
    emitted = 0
    for index, chunk in enumerate(byte_chunks(wire)):
        batch = parser.feed(chunk)
        emitted += len(batch.messages)
        if index < len(wire) - 1:
            assert not batch.messages, f"在第 {index} 字节过早产出消息"
    assert emitted == 1


def test_empty_feed_is_a_noop() -> None:
    parser = Http1Parser(RESPONSE)
    assert not parser.feed(b"").messages
    wire = http_response(b"x")
    messages, _ = run(parser, [wire])
    assert len(messages) == 1


# ----------------------------------------------------------------------
# chunked
# ----------------------------------------------------------------------


def test_chunked_response_reassembles_under_any_split() -> None:
    body = openai_json_body()
    wire = http_response(body, framing="chunked", chunk_size=9)

    for messages, diagnostics in replay_all_splits(wire):
        assert len(messages) == 1
        message = messages[0]
        assert isinstance(message, HttpResponse)
        assert message.body_framing is BodyFraming.CHUNKED
        assert message.complete
        assert message.payload == body
        assert not errors(diagnostics)


def test_chunked_with_extensions_and_trailer() -> None:
    body = b"hello chunked world"
    wire = http_response(
        body,
        framing="chunked",
        chunk_size=4,
        chunk_extensions=True,
        trailer=(("X-Checksum", "abc"),),
    )
    for messages, diagnostics in replay_all_splits(wire):
        assert len(messages) == 1
        assert messages[0].payload == body
        assert messages[0].complete
        assert not errors(diagnostics)


def test_chunked_trailer_without_final_crlf_is_premature_eof() -> None:
    body = b"abc"
    wire = http_response(body, framing="chunked", chunk_size=3, trailer=(("X-T", "1"),))
    truncated_wire = wire[:-2]  # 去掉 trailer 结束的空行
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [truncated_wire])
    assert len(messages) == 1
    assert not messages[0].complete
    assert messages[0].incomplete_reason == DiagnosticCode.PREMATURE_EOF.value
    assert DiagnosticCode.PREMATURE_EOF in codes(diagnostics)


def test_zero_chunk_terminates_body_without_extra_data() -> None:
    wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].payload == b""
    assert messages[0].complete
    assert not errors(diagnostics)


# ----------------------------------------------------------------------
# gzip
# ----------------------------------------------------------------------


def test_gzip_response_reassembles_under_any_split() -> None:
    body = openai_json_body()
    wire = http_response(body, encoding="gzip", headers=(("Content-Type", "application/json"),))

    for messages, diagnostics in replay_all_splits(wire):
        assert len(messages) == 1
        message = messages[0]
        assert isinstance(message, HttpResponse)
        assert message.content_encoding == "gzip"
        assert message.payload == body
        assert message.payload_decoded
        assert message.payload_complete
        assert not errors(diagnostics)


def test_gzip_over_chunked() -> None:
    body = openai_json_body()
    wire = http_response(body, encoding="gzip", framing="chunked", chunk_size=6)
    for messages, diagnostics in replay_all_splits(wire):
        assert messages[0].payload == body
        assert not errors(diagnostics)


def test_gzip_truncated_payload_is_flagged() -> None:
    body = openai_json_body()
    compressed = gzip_bytes(body)
    wire = raw_response(
        compressed[: len(compressed) // 2], headers=(("Content-Encoding", "gzip"),)
    )
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].complete  # 分帧完整
    assert not messages[0].payload_complete  # 但正文不可用
    assert DiagnosticCode.GZIP_TRUNCATED in codes(diagnostics)


def test_gzip_corrupt_payload_is_flagged() -> None:
    payload = b"\x1f\x8b\x08\x00garbage-body"
    wire = raw_response(payload, headers=(("Content-Encoding", "gzip"),))
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert DiagnosticCode.GZIP_DECODE_ERROR in codes(diagnostics)
    assert not messages[0].payload_complete


def test_gzip_trailing_garbage_is_reported_but_not_fatal() -> None:
    body = b"hello"
    compressed = gzip_bytes(body) + b"EXTRA"
    wire = raw_response(compressed, headers=(("Content-Encoding", "gzip"),))
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert messages[0].payload == body
    assert messages[0].payload_complete
    assert DiagnosticCode.GZIP_TRAILING_DATA in codes(diagnostics)


# ----------------------------------------------------------------------
# 连接复用
# ----------------------------------------------------------------------


def test_connection_reuse_emits_messages_in_order() -> None:
    bodies = [openai_json_body(prompt_tokens=index, completion_tokens=index) for index in (1, 2, 3)]
    wire = b"".join(
        http_response(body, headers=(("Content-Type", "application/json"),)) for body in bodies
    )

    for messages, diagnostics in replay_all_splits(wire):
        assert len(messages) == 3
        assert [message.message_index for message in messages] == [1, 2, 3]
        assert [message.payload for message in messages] == bodies
        assert all(message.complete for message in messages)
        assert not errors(diagnostics)


def test_connection_reuse_with_chunked_and_content_length_mixed() -> None:
    first = http_response(b'{"a":1}', framing="content_length", headers=(("Content-Type", "application/json"),))
    second = http_response(b'{"b":2}', framing="chunked", chunk_size=3, headers=(("Content-Type", "application/json"),))
    third = http_response(b'{"c":3}', encoding="gzip", headers=(("Content-Type", "application/json"),))
    wire = first + second + third
    for messages, diagnostics in replay_all_splits(wire):
        assert [message.payload for message in messages] == [b'{"a":1}', b'{"b":2}', b'{"c":3}']
        assert not errors(diagnostics)


def test_requests_and_responses_interleaved_byte_by_byte() -> None:
    request_parser = Http1Parser(REQUEST)
    response_parser = Http1Parser(RESPONSE)
    requests = [http_request(body=b'{"n":%d}' % index) for index in (1, 2)]
    responses = [http_response(openai_json_body(prompt_tokens=index)) for index in (1, 2)]

    seen_requests: list[object] = []
    seen_responses: list[object] = []
    for index in range(2):
        for chunk in byte_chunks(requests[index]):
            seen_requests.extend(request_parser.feed(chunk).messages)
        for chunk in byte_chunks(responses[index]):
            seen_responses.extend(response_parser.feed(chunk).messages)
    seen_requests.extend(request_parser.finish().messages)
    seen_responses.extend(response_parser.finish().messages)

    assert [m.message_index for m in seen_requests] == [1, 2]
    assert [m.message_index for m in seen_responses] == [1, 2]
    assert [m.payload for m in seen_responses] == [openai_json_body(prompt_tokens=i) for i in (1, 2)]


def test_bytes_after_connection_close_are_reported() -> None:
    wire = http_response(b"a", framing="content_length", headers=(("Connection", "close"),))
    wire += http_response(b"b", framing="content_length")
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 2
    assert parser.expects_close
    assert DiagnosticCode.MESSAGE_AFTER_CONNECTION_CLOSE in codes(diagnostics)


# ----------------------------------------------------------------------
# 不支持 / 异常
# ----------------------------------------------------------------------


def test_http2_preface_is_fatal_and_emits_no_message() -> None:
    parser = Http1Parser(REQUEST)
    messages, diagnostics = run(parser, [HTTP2_CONNECTION_PREFACE])
    assert messages == []
    assert parser.failed
    assert DiagnosticCode.HTTP2_PREFACE in codes(diagnostics)
    assert parser.failure is not None and parser.failure.fatal


def test_http2_preface_detected_after_partial_prefix() -> None:
    parser = Http1Parser(REQUEST)
    batch = parser.feed(HTTP2_CONNECTION_PREFACE[:5])
    assert not batch.messages
    batch = parser.feed(HTTP2_CONNECTION_PREFACE[5:])
    assert DiagnosticCode.HTTP2_PREFACE in {d.code for d in batch.diagnostics}


def test_brotli_content_encoding_is_reported_and_framing_continues() -> None:
    wire = http_response(
        b"\x00binary",
        headers=(("Content-Encoding", "br"), ("Content-Type", "application/json")),
    )
    wire += http_response(b'{"ok":1}', headers=(("Content-Type", "application/json"),))
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 2
    assert messages[0].content_encoding == "br"
    assert messages[0].payload is None
    assert not messages[0].payload_decoded
    assert messages[0].complete
    assert DiagnosticCode.UNSUPPORTED_CONTENT_ENCODING in codes(diagnostics)
    assert messages[1].payload == b'{"ok":1}'


def test_unsupported_http_version_is_fatal() -> None:
    wire = b"HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert messages == []
    assert DiagnosticCode.UNSUPPORTED_HTTP_VERSION in codes(diagnostics)


def test_http10_response_is_tolerated_and_annotated() -> None:
    wire = http_response(b"body", version="HTTP/1.0", framing="close")
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].version == "HTTP/1.0"
    assert messages[0].connection_close
    assert DiagnosticCode.HTTP10_MESSAGE in codes(diagnostics)


def test_header_section_too_large_is_fatal() -> None:
    parser = Http1Parser(RESPONSE, limits=ParserLimits(max_header_bytes=64))
    messages, diagnostics = run(parser, [b"HTTP/1.1 200 OK\r\n" + b"X-Pad: " + b"a" * 200 + b"\r\n\r\n"])
    assert messages == []
    assert DiagnosticCode.HEADER_SECTION_TOO_LARGE in codes(diagnostics)
    assert parser.state is ParserState.FAILED


def test_too_many_headers_is_fatal() -> None:
    wire = b"HTTP/1.1 200 OK\r\n" + b"".join(b"X-H: 1\r\n" for _ in range(10)) + b"\r\n"
    parser = Http1Parser(RESPONSE, limits=ParserLimits(max_headers=3))
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert not messages[0].complete
    assert messages[0].incomplete_reason == DiagnosticCode.TOO_MANY_HEADERS.value
    assert DiagnosticCode.TOO_MANY_HEADERS in codes(diagnostics)


def test_malformed_header_emits_partial_message_and_fails() -> None:
    wire = b"HTTP/1.1 200 OK\r\nBroken-Header\r\nContent-Length: 0\r\n\r\n"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert not messages[0].complete
    assert messages[0].payload is None
    assert DiagnosticCode.MALFORMED_HEADER in codes(diagnostics)


def test_obsolete_line_folding_is_joined_and_reported() -> None:
    wire = b"HTTP/1.1 200 OK\r\nX-Long: first\r\n  second\r\nContent-Length: 0\r\n\r\n"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert messages[0].header("x-long") == "first second"
    assert DiagnosticCode.OBSOLETE_LINE_FOLDING in codes(diagnostics)


def test_body_too_large_is_bounded_and_flagged() -> None:
    body = b"x" * 500
    wire = http_response(body, framing="content_length")
    parser = Http1Parser(RESPONSE, limits=ParserLimits(max_body_bytes=100))
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    message = messages[0]
    assert message.complete  # 分帧仍然完整
    assert message.payload is not None and len(message.payload) == 100
    assert message.payload_truncated
    assert not message.payload_complete
    assert DiagnosticCode.BODY_TOO_LARGE in codes(diagnostics)


def test_decompressed_too_large_is_bounded_and_flagged() -> None:
    body = b"A" * 100_000
    wire = http_response(body, encoding="gzip")
    parser = Http1Parser(RESPONSE, limits=ParserLimits(max_decompressed_bytes=1024))
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].payload is not None
    assert len(messages[0].payload) == 1024
    assert messages[0].payload_truncated
    assert DiagnosticCode.DECOMPRESSED_TOO_LARGE in codes(diagnostics)


def test_invalid_chunk_size_is_fatal() -> None:
    wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert DiagnosticCode.INVALID_CHUNK_SIZE in codes(diagnostics)
    assert parser.failed
    assert all(m.incomplete_reason == DiagnosticCode.INVALID_CHUNK_SIZE.value for m in messages)


def test_malformed_chunk_terminator_is_fatal() -> None:
    wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert DiagnosticCode.MALFORMED_CHUNK in codes(diagnostics)
    assert parser.failed
    assert len(messages) == 1 and not messages[0].complete


def test_premature_eof_in_fixed_body() -> None:
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    message = messages[0]
    assert not message.complete
    assert message.incomplete_reason == DiagnosticCode.PREMATURE_EOF.value
    assert message.payload == b"abc"
    assert not message.payload_complete
    assert DiagnosticCode.PREMATURE_EOF in codes(diagnostics)


def test_premature_eof_in_chunk_data() -> None:
    wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert not messages[0].complete
    assert DiagnosticCode.PREMATURE_EOF in codes(diagnostics)


def test_premature_eof_inside_unterminated_header_block() -> None:
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [b"HTTP/1.1 200 OK\r\nContent-Type: application/json"])
    assert len(messages) == 1
    assert not messages[0].complete
    assert messages[0].status_code == 200
    assert DiagnosticCode.PREMATURE_EOF in codes(diagnostics)


def test_clean_eof_with_no_pending_data_emits_nothing() -> None:
    parser = Http1Parser(RESPONSE)
    assert run(parser, []) == ([], [])
    assert parser.messages_completed == 0


def test_malformed_content_length_is_fatal() -> None:
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert messages == []
    assert DiagnosticCode.MALFORMED_CONTENT_LENGTH in codes(diagnostics)


def test_conflicting_content_lengths_are_fatal() -> None:
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert DiagnosticCode.MALFORMED_CONTENT_LENGTH in codes(diagnostics)


def test_chunked_and_content_length_together_is_flagged() -> None:
    body = b"payload"
    wire = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\n"
        + chunked_body(body)
    )
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].payload == body
    assert messages[0].body_framing is BodyFraming.CHUNKED
    assert DiagnosticCode.CONFLICTING_FRAMING in codes(diagnostics)


def test_unsupported_transfer_encoding_is_reported_and_payload_unavailable() -> None:
    body = b"payload"
    wire = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
        + chunked_body(body)
    )
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].complete  # chunked 分帧仍然完整
    assert messages[0].payload is None  # 但正文仍未解开 transfer-coding
    assert messages[0].body_framing is BodyFraming.CHUNKED
    assert DiagnosticCode.UNSUPPORTED_TRANSFER_ENCODING in codes(diagnostics)


def test_chunked_not_last_emits_partial_message_and_fails() -> None:
    wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert not messages[0].complete
    assert DiagnosticCode.UNSUPPORTED_TRANSFER_ENCODING in codes(diagnostics)
    assert parser.failed


def test_gzip_transfer_encoding_is_unsupported() -> None:
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: gzip\r\n\r\nxxxx"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].payload is None
    assert DiagnosticCode.UNSUPPORTED_TRANSFER_ENCODING in codes(diagnostics)


def test_malformed_start_line() -> None:
    parser = Http1Parser(REQUEST)
    messages, diagnostics = run(parser, [b"GET /only-two-parts\r\n\r\n"])
    assert messages == []
    assert DiagnosticCode.MALFORMED_START_LINE in codes(diagnostics)


def test_bare_lf_headers_are_tolerated() -> None:
    wire = b"HTTP/1.1 200 OK\nContent-Length: 2\n\nhi"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].payload == b"hi"
    assert messages[0].complete
    assert not errors(diagnostics)


def test_leading_empty_lines_between_messages_are_skipped() -> None:
    wire = http_response(b"a") + b"\r\n" + http_response(b"b")
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert [m.payload for m in messages] == [b"a", b"b"]
    assert not errors(diagnostics)


# ----------------------------------------------------------------------
# 分帧语义
# ----------------------------------------------------------------------


@pytest.mark.parametrize("status", [204, 304])
def test_status_without_body_ignores_trailing_content_length(status: int) -> None:
    wire = f"HTTP/1.1 {status} No Content\r\nContent-Length: 100\r\n\r\n".encode()
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].payload == b""
    assert messages[0].complete
    assert not errors(diagnostics)


def test_head_response_has_no_body_when_request_method_registered() -> None:
    parser = Http1Parser(RESPONSE)
    parser.register_request("HEAD")
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    messages, _ = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].request_method == "HEAD"
    assert messages[0].payload == b""


def test_informational_response_then_final_response() -> None:
    parser = Http1Parser(RESPONSE)
    parser.register_request("POST")
    wire = b"HTTP/1.1 100 Continue\r\n\r\n" + http_response(openai_json_body())
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 2
    assert messages[0].is_informational and messages[0].status_code == 100
    assert messages[1].status_code == 200
    assert messages[1].request_method == "POST"
    assert not errors(diagnostics)


def test_connect_tunnel_is_reported_and_stops_parsing() -> None:
    parser = Http1Parser(RESPONSE)
    parser.register_request("CONNECT")
    wire = b"HTTP/1.1 200 Connection established\r\n\r\nRAW-TUNNEL-BYTES"
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].complete
    assert DiagnosticCode.CONNECT_TUNNEL_UNSUPPORTED in codes(diagnostics)
    assert parser.failed


def test_close_delimited_body_completes_at_eof() -> None:
    wire = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nclose-delimited"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].body_framing is BodyFraming.CLOSE_DELIMITED
    assert messages[0].payload == b"close-delimited"
    assert messages[0].complete
    assert not errors(diagnostics)


def test_response_without_content_length_and_without_close_is_ambiguous() -> None:
    wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    parser = Http1Parser(RESPONSE)
    messages, diagnostics = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].body_framing is BodyFraming.CLOSE_DELIMITED
    assert DiagnosticCode.BODY_FRAMING_AMBIGUOUS in codes(diagnostics)


def test_request_without_content_length_has_no_body() -> None:
    wire = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n"
    parser = Http1Parser(REQUEST)
    messages, _ = run(parser, [wire])
    assert len(messages) == 1
    assert messages[0].body_framing is BodyFraming.NONE
    assert messages[0].payload == b""


def test_request_with_chunked_body() -> None:
    body = b'{"model":"gpt-4o-mini"}'
    wire = http_request(body=body, framing="chunked", chunk_size=4)
    for messages, diagnostics in replay_all_splits(wire, direction=REQUEST):
        assert len(messages) == 1
        assert messages[0].payload == body
        assert not errors(diagnostics)


def test_crlf_split_across_feeds_at_chunk_boundary() -> None:
    body = b"abc"
    wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n" + body + b"\r\n0\r\n\r\n"
    parser = Http1Parser(RESPONSE)
    index = wire.index(b"abc") + 3
    messages, _ = run(parser, [wire[: index + 1], wire[index + 1 :]])
    assert len(messages) == 1
    assert messages[0].payload == body


# ----------------------------------------------------------------------
# 脱敏
# ----------------------------------------------------------------------


def test_sensitive_headers_are_redacted_in_the_message_model() -> None:
    wire = http_request(
        headers=(
            ("Authorization", "Bearer sk-live-1234567890"),
            ("OpenAI-Organization", "org-1"),
        )
    )
    parser = Http1Parser(REQUEST)
    messages, _ = run(parser, [wire])
    message = messages[0]
    assert message.header("authorization") == "<redacted>"
    assert message.redacted_header_names == ("authorization",)
    assert message.header("openai-organization") == "org-1"
    assert "sk-live-1234567890" not in str(message.to_record())


def test_sensitive_target_query_params_are_redacted() -> None:
    wire = http_request(
        target="/v1beta/models/gemini-pro:generateContent?key=AIzaSecret&alt=json",
        body=None,
        method="POST",
    )
    parser = Http1Parser(REQUEST)
    messages, _ = run(parser, [wire])
    message = messages[0]
    assert "AIzaSecret" not in message.target
    assert message.target.endswith("key=<redacted>&alt=json")
    assert message.redacted_query_params == ("key",)


def test_custom_redaction_policy_can_be_disabled_explicitly() -> None:
    policy = HeaderRedactionPolicy(sensitive_headers=frozenset(), sensitive_substrings=())
    wire = http_request(headers=(("Authorization", "Bearer visible"),))
    parser = Http1Parser(REQUEST, redaction=policy)
    messages, _ = run(parser, [wire])
    assert messages[0].header("authorization") == "Bearer visible"


def test_registering_request_context_is_bounded() -> None:
    parser = Http1Parser(RESPONSE, limits=ParserLimits(max_pending_requests=2))
    for _ in range(5):
        parser.register_request("POST")
    assert parser.dropped_request_contexts == 3


# ----------------------------------------------------------------------
# 有界性 / 状态
# ----------------------------------------------------------------------


def test_feed_after_finish_raises() -> None:
    parser = Http1Parser(RESPONSE)
    parser.finish()
    with pytest.raises(RuntimeError):
        parser.feed(b"HTTP/1.1 200 OK\r\n\r\n")


def test_finish_is_idempotent() -> None:
    parser = Http1Parser(RESPONSE)
    run(parser, [http_response(b"x")])
    assert not parser.finish().messages


def test_feed_after_fatal_failure_returns_empty_without_duplicate_diagnostics() -> None:
    parser = Http1Parser(RESPONSE)
    first = parser.feed(b"HTTP/2.0 200 OK\r\n\r\n")
    assert DiagnosticCode.UNSUPPORTED_HTTP_VERSION in {d.code for d in first.diagnostics}
    second = parser.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    assert not second.messages
    assert not second.diagnostics


def test_feed_rejects_non_bytes() -> None:
    parser = Http1Parser(RESPONSE)
    with pytest.raises(TypeError):
        parser.feed("HTTP/1.1 200 OK\r\n\r\n")  # type: ignore[arg-type]


def test_memoryview_and_bytearray_are_accepted() -> None:
    wire = http_response(b"ok")
    parser = Http1Parser(RESPONSE)
    messages, _ = run(parser, [memoryview(wire), bytearray()])
    assert len(messages) == 1
    assert messages[0].payload == b"ok"


def test_stream_offsets_are_monotonic_across_reused_connection() -> None:
    wire = http_response(b"a") + http_response(b"bb" * 50)
    parser = Http1Parser(RESPONSE)
    messages, _ = run(parser, fixed_chunks(wire, 11))
    assert messages[0].stream_start_offset == 0
    assert messages[0].stream_end_offset == messages[1].stream_start_offset
    assert messages[1].stream_end_offset == len(wire)


def test_sse_content_type_payload_is_preserved_byte_exact() -> None:
    body = openai_sse_body()
    wire = http_response(body, headers=(("Content-Type", "text/event-stream"),))
    for messages, _ in replay_all_splits(wire):
        assert messages[0].payload == body
