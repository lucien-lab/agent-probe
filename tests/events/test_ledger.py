"""JSONL 权威日志：写入、完整性校验、恢复与生命周期。"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from agent_probe.events import (
    ENVELOPE_VERSION,
    MAX_LINE_BYTES,
    ConcurrentWriterError,
    EventType,
    EventValidationError,
    FsyncPolicy,
    IssueKind,
    JsonlEventLedger,
    LedgerClosedError,
    LedgerRecord,
    OutOfOrderEventError,
    TruncatedLedgerError,
    UnknownFieldPolicy,
    build_envelope_line,
    canonical_json,
    compute_checksum,
    event_from_dict,
    iter_events,
    iter_records,
    ledger_digest,
    scan_ledger,
)

RawLine = Callable[..., bytes]


def _write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)


# --------------------------------------------------------------------------- #
# 基本写入 / round-trip
# --------------------------------------------------------------------------- #


def test_append_writes_one_complete_line_per_event(ledger_path: Path, make_event: Any) -> None:
    events = [
        make_event(EventType.PROCESS_FORK),
        make_event(EventType.FILE_OPEN),
        make_event(EventType.NET_CONNECT),
    ]
    with JsonlEventLedger(ledger_path) as ledger:
        records = ledger.append_many(events)

    assert [record.line_no for record in records] == [1, 2, 3]
    assert [record.offset for record in records] == sorted(r.offset for r in records)
    raw = ledger_path.read_bytes()
    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 3
    assert len(raw) == records[-1].offset + records[-1].byte_length


def test_ledger_roundtrip_preserves_events(ledger_path: Path, make_event: Any) -> None:
    events = [make_event(event_type) for event_type in EventType]
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append_many(events)

    result = scan_ledger(ledger_path)
    assert result.issues == ()
    assert result.records and tuple(r.event for r in result.records) == tuple(events)
    assert result.lines_total == len(events)
    assert result.lines_skipped == 0


def test_envelope_contains_version_length_and_checksum(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        record = ledger.append(make_event())

    envelope = json.loads(ledger_path.read_text("utf-8").strip())
    assert envelope["v"] == ENVELOPE_VERSION
    assert set(envelope) == {"v", "len", "checksum", "event"}
    body = canonical_json(envelope["event"]).encode("utf-8")
    assert envelope["len"] == len(body)
    assert envelope["checksum"] == compute_checksum(body)
    assert record.checksum == envelope["checksum"]


def test_record_checksum_matches_scan(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        written = ledger.append(make_event())
    scanned = scan_ledger(ledger_path).records[0]
    assert scanned.checksum == written.checksum
    assert scanned.event == written.event


def test_iter_events_streams_in_append_order(ledger_path: Path, make_event: Any) -> None:
    events = [make_event(seq=i) for i in range(5)]
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append_many(events)
    assert tuple(iter_events(ledger_path)) == tuple(events)


def test_iter_records_reports_issues_without_scanning_into_memory(
    ledger_path: Path, make_event: Any
) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event())
    with ledger_path.open("ab") as handle:
        handle.write(b'{"v":1,"len":1,"checksum":"sha256:x","event"')  # 截断尾行

    issues: list[Any] = []
    records = list(iter_records(ledger_path, issues=issues))
    assert len(records) == 1
    assert [issue.kind for issue in issues] == [IssueKind.TRUNCATED_TAIL]


def test_scan_missing_file_raises_or_returns_empty(tmp_path: Path) -> None:
    missing = tmp_path / "nope.jsonl"
    with pytest.raises(FileNotFoundError):
        scan_ledger(missing)
    assert scan_ledger(missing, missing_ok=True).records == ()
    assert tuple(iter_events(missing, missing_ok=True)) == ()


# --------------------------------------------------------------------------- #
# fsync 策略
# --------------------------------------------------------------------------- #


def test_fsync_always_syncs_every_event(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path, fsync_policy=FsyncPolicy.ALWAYS) as ledger:
        for index in range(3):
            ledger.append(make_event(seq=index))
        assert ledger.stats.fsyncs == 3
        assert ledger.stats.pending_lines == 0


def test_fsync_batch_only_syncs_on_threshold_and_flush(
    ledger_path: Path, make_event: Any
) -> None:
    ledger = JsonlEventLedger(ledger_path, fsync_policy=FsyncPolicy.BATCH, fsync_every_lines=2)
    with ledger:
        ledger.append(make_event(seq=0))
        assert ledger.stats.fsyncs == 0
        assert ledger.stats.pending_lines == 1
        ledger.append(make_event(seq=1))
        assert ledger.stats.fsyncs == 1
        ledger.flush()
        assert ledger.stats.fsyncs == 2
        synced = ledger.stats.fsyncs
        ledger.sync()
        assert ledger.stats.fsyncs == synced + 1


def test_fsync_never_does_not_sync_even_on_close(ledger_path: Path, make_event: Any) -> None:
    ledger = JsonlEventLedger(ledger_path, fsync_policy=FsyncPolicy.NEVER)
    with ledger:
        ledger.append(make_event())
        ledger.flush()
        assert ledger.stats.fsyncs == 0
    assert ledger.stats.fsyncs == 0
    assert scan_ledger(ledger_path).lines_total == 1


def test_invalid_fsync_batch_size_rejected(ledger_path: Path) -> None:
    with pytest.raises(ValueError):
        JsonlEventLedger(ledger_path, fsync_every_lines=0)


def test_close_is_idempotent(ledger_path: Path, make_event: Any) -> None:
    ledger = JsonlEventLedger(ledger_path)
    ledger.append(make_event())
    ledger.close()
    ledger.close()
    assert ledger.closed is True


# --------------------------------------------------------------------------- #
# 生命周期：关闭后拒写、异常不吞
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("operation", ["append", "append_many", "flush", "sync", "verify"])
def test_writes_after_close_are_rejected(
    ledger_path: Path, make_event: Any, operation: str
) -> None:
    ledger = JsonlEventLedger(ledger_path)
    ledger.close()
    with pytest.raises(LedgerClosedError):
        if operation == "append":
            ledger.append(make_event())
        elif operation == "append_many":
            ledger.append_many([make_event()])
        elif operation == "sync":
            ledger.sync()
        else:
            getattr(ledger, operation)()


def test_context_manager_closes_and_propagates_exceptions(
    ledger_path: Path, make_event: Any
) -> None:
    ledger = JsonlEventLedger(ledger_path)
    with pytest.raises(RuntimeError, match="boom"):
        with ledger:
            ledger.append(make_event())
            raise RuntimeError("boom")
    assert ledger.closed is True
    assert scan_ledger(ledger_path).lines_total == 1


def test_exit_does_not_swallow_exceptions(ledger_path: Path) -> None:
    ledger = JsonlEventLedger(ledger_path)
    assert ledger.__exit__(RuntimeError, RuntimeError("x"), None) is False


# --------------------------------------------------------------------------- #
# 并发写入者
# --------------------------------------------------------------------------- #


def test_second_writer_same_process_is_rejected(ledger_path: Path, make_event: Any) -> None:
    first = JsonlEventLedger(ledger_path)
    try:
        with pytest.raises(ConcurrentWriterError, match="同一进程"):
            JsonlEventLedger(ledger_path)
    finally:
        first.close()

    with JsonlEventLedger(ledger_path) as reopened:
        reopened.append(make_event())
    assert scan_ledger(ledger_path).lines_total == 1


def test_lock_file_exists_while_open_and_writer_can_be_disabled(
    ledger_path: Path, make_event: Any
) -> None:
    ledger = JsonlEventLedger(ledger_path)
    try:
        assert (ledger_path.parent / (ledger_path.name + ".lock")).exists()
    finally:
        ledger.close()

    # lock=False 明知有风险：调用方自行保证单写入者。
    with JsonlEventLedger(ledger_path, lock=False) as unlocked:
        unlocked.append(make_event())
    assert scan_ledger(ledger_path).lines_total == 1


_CHILD_HOLDER = """
import pathlib, sys, time
from agent_probe.events import JsonlEventLedger

ledger_path, ready = sys.argv[1], sys.argv[2]
ledger = JsonlEventLedger(ledger_path)
pathlib.Path(ready).write_text("ready", encoding="utf-8")
time.sleep(60)
ledger.close()
"""


def test_cross_process_writer_is_rejected(ledger_path: Path, make_event: Any) -> None:
    """跨进程互斥：同一 JSONL 不支持并发写入，由 flock 显式拒绝。"""

    import os
    import subprocess
    import sys
    import time

    src_dir = Path(__file__).resolve().parents[2] / "src"
    sentinel = ledger_path.parent / "child-ready"
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(src_dir) if not existing else str(src_dir) + os.pathsep + existing
    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD_HOLDER, str(ledger_path), str(sentinel)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 30
        while not sentinel.exists():
            if child.poll() is not None:
                stdout, stderr = child.communicate()
                pytest.fail(f"子进程提前退出：{stdout} / {stderr}")
            if time.monotonic() > deadline:
                pytest.fail("子进程未能在 30 秒内取得账本写锁")
            time.sleep(0.05)

        with pytest.raises(ConcurrentWriterError, match="其他进程"):
            JsonlEventLedger(ledger_path)
    finally:
        child.terminate()
        child.wait(timeout=30)
        if child.stdout is not None:
            child.stdout.close()
        if child.stderr is not None:
            child.stderr.close()

    # 子进程退出后锁被释放，本进程可以正常接管。
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event())
    assert scan_ledger(ledger_path).lines_total == 1


# --------------------------------------------------------------------------- #
# 尾部截断与修复
# --------------------------------------------------------------------------- #


def test_truncated_tail_is_detected_and_earlier_events_survive(
    ledger_path: Path, make_event: Any
) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append_many([make_event(seq=0), make_event(seq=1)])
    with ledger_path.open("ab") as handle:
        handle.write(b'{"v":1,"len":42,"checksum":"sha256:deadbeef","event":{"schema_')

    result = scan_ledger(ledger_path)
    assert len(result.records) == 2
    assert result.truncated_tail is True
    assert result.issue_counts[str(IssueKind.TRUNCATED_TAIL)] == 1
    assert result.lines_skipped == 1


def test_appending_to_truncated_file_is_refused_by_default(
    ledger_path: Path, make_event: Any
) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event())
    partial = b'{"v":1,"len":1'
    with ledger_path.open("ab") as handle:
        handle.write(partial)
    size_before = ledger_path.stat().st_size

    with pytest.raises(TruncatedLedgerError, match="不完整行"):
        JsonlEventLedger(ledger_path)
    assert ledger_path.stat().st_size == size_before  # 拒绝时不修改文件


def test_truncate_tail_repair_makes_file_appendable(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        original = ledger.append(make_event(seq=0))
    partial = b'{"v":1,"len":1'
    with ledger_path.open("ab") as handle:
        handle.write(partial)

    with JsonlEventLedger(ledger_path, truncate_tail=True) as repaired:
        assert repaired.stats.tail_repaired_bytes == len(partial)
        repaired.append(make_event(seq=1))
        assert repaired.stats.lines_written == 2

    result = scan_ledger(ledger_path)
    assert [record.event.seq for record in result.records] == [0, 1]
    assert result.records[0].checksum == original.checksum
    assert result.issues == ()


# --------------------------------------------------------------------------- #
# 完整性检测：校验错、重复、schema、乱序、坏行
# --------------------------------------------------------------------------- #


def test_checksum_mismatch_is_detected_and_line_skipped(
    ledger_path: Path, make_event: Any
) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append_many([make_event(seq=0), make_event(seq=1)])

    lines = ledger_path.read_bytes().splitlines(keepends=True)
    envelope = json.loads(lines[0])
    envelope["event"]["pid"] = 999999  # 改动内容但保持 JSON 合法
    lines[0] = canonical_json(envelope).encode("utf-8") + b"\n"
    _write_bytes(ledger_path, b"".join(lines))

    result = scan_ledger(ledger_path)
    assert len(result.records) == 1
    assert result.records[0].event.seq == 1
    assert result.issue_counts[str(IssueKind.CHECKSUM_MISMATCH)] == 1
    assert result.issues[0].event_id == envelope["event"]["event_id"]


def test_declared_length_mismatch_is_treated_as_integrity_error(
    ledger_path: Path, make_event: Any
) -> None:
    event = make_event()
    raw, _checksum, _length = build_envelope_line(event)
    envelope = json.loads(raw)
    envelope["len"] = envelope["len"] + 1
    _write_bytes(ledger_path, canonical_json(envelope).encode("utf-8") + b"\n")

    result = scan_ledger(ledger_path)
    assert result.records == ()
    assert result.issue_counts[str(IssueKind.CHECKSUM_MISMATCH)] == 1


def test_non_canonical_bytes_are_detected_as_checksum_error(
    ledger_path: Path, make_event: Any
) -> None:
    event = make_event()
    pretty = json.dumps(event.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
    body = pretty.encode("utf-8")
    envelope = {
        "v": ENVELOPE_VERSION,
        "len": len(body),
        "checksum": compute_checksum(body),
        "event": event.to_dict(),
    }
    _write_bytes(ledger_path, canonical_json(envelope).encode("utf-8") + b"\n")

    # 校验值是按规范化字节算的：非规范化字节即使语义相同也必须被判为不一致。
    result = scan_ledger(ledger_path)
    assert result.records == ()
    assert result.issue_counts[str(IssueKind.CHECKSUM_MISMATCH)] == 1


def test_duplicate_event_id_keeps_first_and_reports(
    ledger_path: Path, make_event: Any
) -> None:
    event = make_event(seq=0)
    other = make_event(seq=1)
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(event)
        ledger.append(event)  # 崩溃后重试写入
        ledger.append(other)

    result = scan_ledger(ledger_path)
    assert [record.event.seq for record in result.records] == [0, 1]
    assert result.duplicate_event_ids == (event.event_id,)
    assert result.issues[0].kind is IssueKind.DUPLICATE_EVENT_ID


def test_unsupported_schema_version_is_reported(
    ledger_path: Path, make_event: Any, raw_line: RawLine
) -> None:
    data = make_event().to_dict()
    data["schema_version"] = 2
    _write_bytes(ledger_path, raw_line(data))

    result = scan_ledger(ledger_path)
    assert result.records == ()
    assert result.issue_counts[str(IssueKind.SCHEMA_UNSUPPORTED)] == 1


def test_unsupported_envelope_version_is_reported(
    ledger_path: Path, make_event: Any, raw_line: RawLine
) -> None:
    _write_bytes(ledger_path, raw_line(make_event().to_dict(), envelope_version=2))
    result = scan_ledger(ledger_path)
    assert result.records == ()
    assert result.issue_counts[str(IssueKind.ENVELOPE_INVALID)] == 1


def test_event_failing_validation_is_reported(
    ledger_path: Path, make_event: Any, raw_line: RawLine
) -> None:
    data = make_event().to_dict()
    data["payload"] = {"path": "/a", "flags": 0, "unknown_key": 1}
    _write_bytes(ledger_path, raw_line(data))

    result = scan_ledger(ledger_path)
    assert result.records == ()
    assert result.issue_counts[str(IssueKind.EVENT_INVALID)] == 1


def test_malformed_json_line_is_reported(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event(seq=0))
    with ledger_path.open("ab") as handle:
        handle.write(b"this is not json\n")
    with JsonlEventLedger(ledger_path) as appended:  # 追加合法行验证可继续
        appended.append(make_event(seq=1))

    result = scan_ledger(ledger_path)
    assert [record.event.seq for record in result.records] == [0, 1]
    assert result.issue_counts[str(IssueKind.MALFORMED_LINE)] == 1


def test_oversized_line_is_reported_and_resynchronized(
    ledger_path: Path, make_event: Any
) -> None:
    _write_bytes(ledger_path, b"a" * (MAX_LINE_BYTES + 10) + b"\n")
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event())

    result = scan_ledger(ledger_path)
    assert len(result.records) == 1
    assert result.issue_counts[str(IssueKind.OVERSIZED_LINE)] == 1


def test_blank_lines_are_skipped_without_issues(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event())
    raw = ledger_path.read_bytes()
    _write_bytes(ledger_path, b"\n" + raw + b"\n   \n")

    result = scan_ledger(ledger_path)
    assert len(result.records) == 1
    assert result.issues == ()
    assert result.lines_total == 4
    assert result.lines_skipped == 3


def test_non_utf8_line_is_reported(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event())
    with ledger_path.open("ab") as handle:
        handle.write(b'{"v":1,"event":\xff\xfe}\n')

    result = scan_ledger(ledger_path)
    assert len(result.records) == 1
    assert result.issue_counts[str(IssueKind.MALFORMED_LINE)] == 1


def test_non_object_envelope_is_reported(ledger_path: Path) -> None:
    _write_bytes(ledger_path, b'["not","an","object"]\n')
    result = scan_ledger(ledger_path)
    assert result.issues[0].kind is IssueKind.ENVELOPE_INVALID


def test_out_of_order_within_same_stream_is_flagged_but_kept(
    ledger_path: Path, make_event: Any
) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event(monotonic_ns=200, seq=0))
        ledger.append(make_event(monotonic_ns=100, seq=1))

    result = scan_ledger(ledger_path)
    assert len(result.records) == 2
    assert result.issue_counts[str(IssueKind.OUT_OF_ORDER)] == 1
    assert result.kinds_causing_skips() == ()


def test_out_of_order_across_streams_is_not_flagged(
    ledger_path: Path, make_event: Any, other_run_id: str
) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event(monotonic_ns=200, seq=0))
        ledger.append(make_event(monotonic_ns=100, seq=0, source="userspace"))
        ledger.append(make_event(monotonic_ns=50, seq=0, run=other_run_id))

    assert scan_ledger(ledger_path).issues == ()


def test_strict_order_rejects_out_of_order_write(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path, strict_order=True) as ledger:
        ledger.append(make_event(monotonic_ns=200))
        with pytest.raises(OutOfOrderEventError, match="strict_order"):
            ledger.append(make_event(monotonic_ns=100))
        assert ledger.stats.out_of_order_lines == 1
        assert ledger.stats.lines_written == 1
    assert scan_ledger(ledger_path).lines_total == 1


def test_non_strict_writer_counts_out_of_order_lines(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event(monotonic_ns=200))
        ledger.append(make_event(monotonic_ns=100))
        assert ledger.stats.out_of_order_lines == 1
    assert scan_ledger(ledger_path).lines_total == 2


# --------------------------------------------------------------------------- #
# 复用、校验与不可变性
# --------------------------------------------------------------------------- #


def test_reopening_continues_line_numbering(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as first:
        first.append(make_event(seq=0))
    with JsonlEventLedger(ledger_path) as second:
        record = second.append(make_event(seq=1))
        assert record.line_no == 2
        assert second.stats.lines_written == 2
        assert record.offset > 0


def test_verify_is_read_only(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event())
        ledger.flush()  # 先把缓冲推给 OS，否则 before 会读到空文件
        before = ledger_path.read_bytes()
        result = ledger.verify()
        assert len(result.records) == 1
        assert ledger_path.read_bytes() == before


def test_verify_reports_corruption_without_repairing(
    ledger_path: Path, make_event: Any
) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event(seq=0))
    with ledger_path.open("ab") as handle:
        handle.write(b"not-json\n")
    before = ledger_path.read_bytes()

    with JsonlEventLedger(ledger_path) as ledger:
        result = ledger.verify()
        assert result.issue_counts[str(IssueKind.MALFORMED_LINE)] == 1
        assert ledger_path.read_bytes() == before  # verify 不修改文件
    assert ledger_path.read_bytes() == before


def test_ledger_digest_is_stable_across_rescans(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append_many([make_event(seq=i) for i in range(4)])
    first = scan_ledger(ledger_path)
    second = scan_ledger(ledger_path)
    assert ledger_digest(first.records) == ledger_digest(second.records)


def test_ledger_digest_changes_when_content_changes(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event(seq=0))
    before = ledger_digest(scan_ledger(ledger_path).records)
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event(seq=1))
    assert ledger_digest(scan_ledger(ledger_path).records) != before


def test_ledger_file_bytes_are_deterministic(ledger_path: Path, make_event: Any) -> None:
    events = [make_event(seq=i) for i in range(3)]
    other_path = ledger_path.parent / "copy.jsonl"
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append_many(events)
    with JsonlEventLedger(other_path) as ledger:
        ledger.append_many(events)
    assert ledger_path.read_bytes() == other_path.read_bytes()


def test_append_rejects_non_event(ledger_path: Path) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        with pytest.raises(EventValidationError):
            ledger.append("not an event")  # type: ignore[arg-type]


def test_preserve_policy_roundtrips_unknown_fields_through_ledger(
    ledger_path: Path, make_event: Any, raw_line: RawLine
) -> None:
    data = make_event().to_dict()
    data["future_header"] = {"v": 1}
    data["payload"]["future_payload_field"] = [1, 2]
    _write_bytes(ledger_path, raw_line(data))

    rejected = scan_ledger(ledger_path)
    assert rejected.records == ()
    assert rejected.issue_counts[str(IssueKind.EVENT_INVALID)] == 1

    preserved = scan_ledger(ledger_path, policy=UnknownFieldPolicy.PRESERVE)
    assert len(preserved.records) == 1
    restored = preserved.records[0].event
    assert restored.extra == {"future_header": {"v": 1}}
    assert restored.to_dict()["payload"]["future_payload_field"] == [1, 2]
    assert preserved.records[0].checksum == compute_checksum(canonical_json(data).encode())


def test_writer_appends_preserved_unknown_fields_and_verify_reads_them_back(
    ledger_path: Path, make_event: Any
) -> None:
    """前向兼容闭环：写入保留未知字段的事件，能在同一策略下读回。"""

    data = make_event().to_dict()
    data["future_header"] = 7
    data["payload"]["future_payload"] = {"nested": True}
    event = event_from_dict(data, policy=UnknownFieldPolicy.PRESERVE)

    with JsonlEventLedger(ledger_path, policy=UnknownFieldPolicy.PRESERVE) as ledger:
        ledger.append(event)
        assert ledger.verify().issues == ()
        assert ledger.stats.lines_written == 1

    result = scan_ledger(ledger_path, policy=UnknownFieldPolicy.PRESERVE)
    assert tuple(record.event for record in result.records) == (event,)
    assert result.records[0].event.to_dict()["future_header"] == 7

    # 用默认 REJECT 策略读同一份账本必须报错，而不是静默忽略未知字段。
    strict = scan_ledger(ledger_path)
    assert strict.issue_counts[str(IssueKind.EVENT_INVALID)] == 1


def test_stats_snapshot_fields(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append_many([make_event(seq=0), make_event(seq=1)])
        stats = ledger.stats
        assert stats.lines_written == 2
        assert stats.bytes_written == ledger_path.stat().st_size
        assert stats.last_offset == stats.bytes_written
        assert stats.tail_repaired_bytes == 0
        assert stats.closed is False
    assert ledger.stats.closed is True


def test_record_is_a_ledger_record(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        record = ledger.append(make_event())
    assert isinstance(record, LedgerRecord)
    assert record.byte_length > 0
    assert record.checksum.startswith("sha256:")


def test_created_parent_directories(tmp_path: Path, make_event: Any) -> None:
    nested = tmp_path / "runs" / "001" / "events.jsonl"
    with JsonlEventLedger(nested) as ledger:
        ledger.append(make_event())
    assert nested.exists()
    assert scan_ledger(nested).lines_total == 1


def test_scan_result_helpers(ledger_path: Path, make_event: Any, raw_line: RawLine) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event(seq=0))
    with ledger_path.open("ab") as handle:
        handle.write(b"{}\n")

    result = scan_ledger(ledger_path)
    assert result.has_issues is True
    assert result.truncated_tail is False
    assert isinstance(result.issue_counts, Mapping)
    assert result.bytes_total == ledger_path.stat().st_size


def test_issue_kinds_causing_skips_lists_dedup(ledger_path: Path, make_event: Any) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event(seq=0))
    with ledger_path.open("ab") as handle:
        handle.write(b"junk\njunk2\n")

    result = scan_ledger(ledger_path)
    assert result.kinds_causing_skips() == (IssueKind.MALFORMED_LINE,)


def test_ledger_stats_and_attributes(ledger_path: Path) -> None:
    ledger = JsonlEventLedger(ledger_path)
    try:
        assert ledger.path == ledger_path
        assert ledger.closed is False
        assert "JsonlEventLedger" in repr(ledger)
    finally:
        ledger.close()


def test_multiple_runs_in_one_ledger(ledger_path: Path, make_event: Any, other_run_id: str) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(make_event(seq=0))
        ledger.append(make_event(seq=0, run=other_run_id))
    result = scan_ledger(ledger_path)
    assert {record.event.run_id for record in result.records} == {
        make_event(seq=0).run_id,
        other_run_id,
    }
    assert result.issues == ()
