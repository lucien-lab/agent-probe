"""SSE 分帧的确定性回放测试。"""

from __future__ import annotations

import pytest

from agent_probe.llm.diagnostics import DiagnosticCode
from agent_probe.llm.limits import SseLimits
from agent_probe.llm.sse import DONE_SENTINEL, SseParser

from llm.fixtures import all_splits, byte_chunks, openai_sse_body

STREAM = (
    b": keep-alive comment\r\n"
    b"event: content_block_delta\r\n"
    b"id: 7\r\n"
    b"retry: 2000\r\n"
    b"data: line one\r\n"
    b"data: line two\r\n"
    b"\r\n"
    b"data: single\r\n"
    b"\r\n"
    b"data: [DONE]\r\n"
    b"\r\n"
)


def drain(parser: SseParser, chunks: list[bytes]) -> tuple[list[object], object]:
    events: list[object] = []
    for chunk in chunks:
        events.extend(parser.feed(chunk))
    finish = parser.finish()
    events.extend(finish.events)
    return events, finish


def test_multiline_event_and_fields_under_any_split() -> None:
    for chunks in all_splits(STREAM):
        parser = SseParser()
        events, finish = drain(parser, chunks)
        assert len(events) == 3, chunks
        first = events[0]
        assert first.event == "content_block_delta"
        assert first.id == "7"
        assert first.retry == 2000
        assert first.data == "line one\nline two"
        assert first.data_lines == ("line one", "line two")
        assert events[1].data == "single"
        assert events[1].event is None
        assert events[2].is_done
        assert events[2].data == DONE_SENTINEL
        assert finish.saw_done
        assert not finish.truncated
        assert finish.event_count == 3


def test_byte_by_byte_never_dispatches_early() -> None:
    parser = SseParser()
    dispatched = 0
    for byte in byte_chunks(STREAM):
        dispatched += len(parser.feed(byte))
    finish = parser.finish()
    assert dispatched == 3
    assert finish.saw_done


def test_comments_and_unknown_fields_are_ignored() -> None:
    parser = SseParser()
    events, _ = drain(parser, [b": comment\ndata: a\nunknown-field: x\nid: 1\n\n"])
    assert len(events) == 1
    assert events[0].data == "a"
    assert events[0].id == "1"


def test_empty_data_does_not_dispatch_but_resets_event_name() -> None:
    parser = SseParser()
    events, _ = drain(parser, [b"event: foo\n\nevent: bar\ndata: x\n\n"])
    assert len(events) == 1
    assert events[0].event == "bar"


def test_lf_only_and_cr_only_line_terminators() -> None:
    parser = SseParser()
    events, _ = drain(parser, [b"data: a\ndata: b\rdata: c\r\n\n"])
    assert [event.data for event in events] == ["a\nb\nc"]


def test_trailing_cr_at_eof_terminates_the_line_but_does_not_dispatch() -> None:
    parser = SseParser()
    events, finish = drain(parser, [b"data: x\r"])
    # 裸 CR 就是合法行终止符：行已被识别，但没有空行，事件仍属未分帧。
    assert events == []
    assert finish.pending_bytes == 0
    assert finish.pending_data_lines == 1
    assert finish.truncated


def test_bom_is_stripped() -> None:
    parser = SseParser()
    events, _ = drain(parser, [b"\xef\xbb\xbfdata: x\n\n"])
    assert len(events) == 1
    assert events[0].data == "x"


def test_data_value_keeps_leading_space_rules_and_inner_colons() -> None:
    parser = SseParser()
    events, _ = drain(parser, [b"data:  two spaces\n\ndata:{\"a\":1}\n\n"])
    assert events[0].data == " two spaces"
    assert events[1].data == '{"a":1}'


def test_id_with_nul_is_ignored() -> None:
    parser = SseParser()
    events, _ = drain(parser, [b"id: bad\x00id\ndata: x\n\n"])
    assert events[0].id is None


def test_last_event_id_persists_across_events() -> None:
    parser = SseParser()
    events, _ = drain(parser, [b"id: 42\ndata: a\n\ndata: b\n\n"])
    assert events[0].id == "42"
    assert events[1].id == "42"
    assert parser.last_event_id == "42"


def test_non_numeric_retry_is_ignored() -> None:
    parser = SseParser()
    events, _ = drain(parser, [b"retry: soon\ndata: x\n\n"])
    assert events[0].retry is None


def test_truncated_stream_with_pending_event_is_reported() -> None:
    parser = SseParser()
    events, finish = drain(parser, [b"data: complete\n\ndata: partial"])
    assert [event.data for event in events] == ["complete"]
    assert finish.truncated
    assert finish.pending_bytes == len(b"data: partial")
    assert DiagnosticCode.SSE_TRUNCATED in {d.code for d in finish.diagnostics}
    assert DiagnosticCode.SSE_MISSING_DONE in {d.code for d in finish.diagnostics}


def test_missing_done_but_cleanly_framed_stream() -> None:
    parser = SseParser()
    events, finish = drain(parser, [b"data: only\n\n"])
    assert len(events) == 1
    assert not finish.truncated
    assert not finish.saw_done
    assert DiagnosticCode.SSE_MISSING_DONE in {d.code for d in finish.diagnostics}


def test_event_too_large_stops_parsing() -> None:
    parser = SseParser(SseLimits(max_event_bytes=16, max_data_lines=64))
    events, finish = drain(parser, [b"data: " + b"x" * 100 + b"\n\n"])
    assert not events
    assert parser.failed
    assert finish.truncated
    assert DiagnosticCode.SSE_EVENT_TOO_LARGE in {d.code for d in parser.diagnostics}


def test_too_many_data_lines_stops_parsing() -> None:
    parser = SseParser(SseLimits(max_event_bytes=10_000, max_data_lines=3))
    payload = b"".join(b"data: %d\n" % index for index in range(10)) + b"\n"
    events, _ = drain(parser, [payload])
    assert not events
    assert parser.failed


def test_openai_fixture_stream_is_framed() -> None:
    body = openai_sse_body()
    parser = SseParser()
    events, finish = drain(parser, byte_chunks(body))
    assert finish.saw_done
    assert not finish.truncated
    assert events[-1].is_done
    assert len(events) == 5  # 3 个 delta + 1 个 usage chunk + [DONE]


def test_feed_after_finish_raises() -> None:
    parser = SseParser()
    parser.finish()
    with pytest.raises(RuntimeError):
        parser.feed(b"data: x\n\n")


def test_finish_is_idempotent_and_feeds_accept_str() -> None:
    parser = SseParser()
    events = parser.feed("data: x\n\n")
    assert len(events) == 1
    first = parser.finish()
    second = parser.finish()
    assert first.saw_done is second.saw_done
    assert second.events == ()


def test_feed_rejects_non_bytes() -> None:
    parser = SseParser()
    with pytest.raises(TypeError):
        parser.feed(123)  # type: ignore[arg-type]
