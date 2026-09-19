"""SQLite 派生索引：查询、事务回滚、幂等重建与一致性。"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agent_probe.events import (
    Event,
    EventResult,
    EventType,
    IndexClosedError,
    IndexConflictError,
    IndexReadError,
    IndexWriteError,
    JsonlEventLedger,
    SqliteIndex,
    ledger_digest,
    scan_ledger,
    verify_against_ledger,
)

RawLine = Callable[..., bytes]


def _populate(ledger_path: Path, events: list[Event]) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append_many(events)


def _file_write(
    make_event: Any,
    *,
    event_id: str,
    bytes_written: int,
    run_id: str | None = None,
) -> Event:
    """构造内容可完全复现的 FILE_WRITE 事件（固定 ID 与时间）。

    时间戳必须显式固定，否则"同 ID 同 payload"的两条事件仍会因
    ``monotonic_ns``/``wall_time`` 不同而属于不同内容——这正是冲突检测要区分的。
    """

    return make_event(
        EventType.FILE_WRITE,
        payload={
            "fd": 4,
            "path": "/w/a.txt",
            "count": 5,
            "bytes_written": bytes_written,
        },
        event_id=event_id,
        monotonic_ns=1_000,
        wall_time=2_000,
        run=run_id,
    )


# --------------------------------------------------------------------------- #
# 基本写入与查询
# --------------------------------------------------------------------------- #


def test_index_records_and_query_by_run(tmp_path: Path, make_event: Any, run_id: str) -> None:
    events = [make_event(seq=i) for i in range(3)]
    path = tmp_path / "idx.sqlite"
    with SqliteIndex(path) as index:
        batch = index.index_events(events)
        assert (batch.submitted, batch.inserted, batch.duplicates) == (3, 3, 0)
        assert index.count() == 3
        assert index.count(run_id=run_id) == 3
        assert index.count(run_id="11111111-1111-4111-8111-111111111111") == 0
        restored = index.events_for_run(run_id)
        assert restored == tuple(events)


def test_query_by_event_type_and_result(make_event: Any) -> None:
    failed = make_event(EventType.FILE_OPEN, result=EventResult.ERROR, error_code=13)
    unknown = make_event(EventType.FILE_OPEN, result=EventResult.UNKNOWN)
    other = make_event(EventType.FILE_READ)
    with SqliteIndex(":memory:") as index:
        index.index_events([failed, unknown, other])
        assert index.events_of_type(EventType.FILE_OPEN) == (failed, unknown)
        assert index.count(event_types=[EventType.FILE_OPEN], result=EventResult.ERROR) == 1
        assert index.query(result=EventResult.UNKNOWN) == (unknown,)
        assert index.count(event_types=[]) == 0


def test_query_by_time_range_on_both_clocks(make_event: Any) -> None:
    first = make_event(monotonic_ns=100, wall_time=1_000)
    second = make_event(monotonic_ns=200, wall_time=2_000)
    third = make_event(monotonic_ns=300, wall_time=3_000)
    with SqliteIndex(":memory:") as index:
        index.index_events([first, second, third])
        assert index.events_in_time_range(150, 250) == (second,)
        assert index.events_in_time_range(2_000, 3_000, time_field="wall_time") == (
            second,
            third,
        )
        with pytest.raises(ValueError, match="time_field"):
            index.query(since_ns=0, time_field="created_at")


def test_query_by_process_includes_start_id(make_event: Any) -> None:
    old = make_event(pid=99, process_start_id=1)
    new = make_event(pid=99, process_start_id=2)
    with SqliteIndex(":memory:") as index:
        index.index_events([old, new])
        assert index.events_for_process(99) == (old, new)
        assert index.events_for_process(99, 2) == (new,)
        assert index.query(pid=99, process_start_id=1) == (old,)


def test_query_pagination_and_ordering(make_event: Any) -> None:
    events = [make_event(seq=i) for i in range(5)]
    with SqliteIndex(":memory:") as index:
        index.index_events(events)
        assert index.query(limit=2) == tuple(events[:2])
        assert index.query(limit=2, offset=2) == tuple(events[2:4])
        assert index.query(offset=3) == tuple(events[3:])
        with pytest.raises(ValueError, match="limit"):
            index.query(limit=0)
        with pytest.raises(ValueError, match="offset"):
            index.query(offset=-1)


def test_query_preserves_ledger_order_for_scanned_records(
    tmp_path: Path, make_event: Any
) -> None:
    events = [make_event(monotonic_ns=1000 - i * 10, seq=i) for i in range(4)]
    ledger_path = tmp_path / "events.jsonl"
    _populate(ledger_path, events)

    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index.rebuild(scan_ledger(ledger_path).records)
        assert index.query() == tuple(events)  # 权威顺序 = 追加顺序，而非时间顺序
        assert index.query(source="ebpf") == tuple(events)
        assert index.query(source="userspace") == ()


def test_index_roundtrip_preserves_unknown_fields_under_preserve_policy(
    tmp_path: Path, make_event: Any, raw_line: RawLine
) -> None:
    data = make_event().to_dict()
    data["future_header"] = "kept"
    data["payload"]["future_payload"] = [1, 2, 3]
    ledger_path = tmp_path / "events.jsonl"
    ledger_path.write_bytes(raw_line(data))

    from agent_probe.events import UnknownFieldPolicy

    records = scan_ledger(ledger_path, policy=UnknownFieldPolicy.PRESERVE).records
    with SqliteIndex(":memory:") as index:
        index.index_records(records)
        restored = index.query()[0]
    assert restored.extra == {"future_header": "kept"}
    assert restored.to_dict()["payload"]["future_payload"] == [1, 2, 3]


# --------------------------------------------------------------------------- #
# 幂等与重建
# --------------------------------------------------------------------------- #


def test_duplicate_insert_is_idempotent(tmp_path: Path, make_event: Any) -> None:
    events = [make_event(seq=i) for i in range(3)]
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        first = index.index_events(events)
        second = index.index_events(events)
        assert first.inserted == 3
        assert second.inserted == 0
        assert second.duplicates == 3
        assert second.unchanged is True
        assert index.count() == 3


# --------------------------------------------------------------------------- #
# 幂等 vs 完整性冲突：只有 (event_id, 内容校验值) 都相同才算重复
# --------------------------------------------------------------------------- #


def test_same_event_id_and_content_is_an_idempotent_duplicate(
    make_event: Any, run_id: str
) -> None:
    event_id = "11111111-1111-4111-8111-111111111111"
    original = _file_write(make_event, event_id=event_id, bytes_written=5)
    # 全新构造、内容逐字节相同的第二条事件（含时间戳）。
    same = _file_write(make_event, event_id=event_id, bytes_written=5)
    assert same is not original
    assert same.to_json() == original.to_json()

    with SqliteIndex(":memory:") as index:
        first = index.index_events([original])
        second = index.index_events([same])
        assert first.inserted == 1 and first.duplicates == 0
        assert second.inserted == 0 and second.duplicates == 1
        assert second.unchanged is True
        assert index.count() == 1
        assert index.query() == (original,)


def test_same_batch_with_identical_repeats_inserts_once(make_event: Any) -> None:
    event_id = "22222222-2222-4222-8222-222222222222"
    first = _file_write(make_event, event_id=event_id, bytes_written=5)
    second = _file_write(make_event, event_id=event_id, bytes_written=5)

    with SqliteIndex(":memory:") as index:
        batch = index.index_events([first, second])
        assert (batch.submitted, batch.inserted, batch.duplicates) == (2, 1, 1)
        assert index.count() == 1


def test_same_event_id_with_different_content_raises_conflict(
    make_event: Any
) -> None:
    """同 event_id 但内容/校验值不同：不得静默保留旧内容，必须报错且回滚。"""

    event_id = "33333333-3333-4333-8333-333333333333"
    original = _file_write(make_event, event_id=event_id, bytes_written=5)
    conflicting = _file_write(make_event, event_id=event_id, bytes_written=999)
    assert original.event_id == conflicting.event_id
    assert original.to_json() != conflicting.to_json()

    with SqliteIndex(":memory:") as index:
        index.index_events([original])
        with pytest.raises(IndexConflictError) as excinfo:
            index.index_events([conflicting])

        message = str(excinfo.value)
        assert event_id in message
        assert "完整性冲突" in message
        # 只写不覆盖：库里仍是原来的那一份，且新内容没有落库。
        assert index.count() == 1
        stored = index.query()[0]
        assert stored == original
        assert stored.payload["bytes_written"] == 5
        # 专用异常仍然是 IndexWriteError，旧调用方的捕获逻辑不失效。
        assert isinstance(excinfo.value, IndexWriteError)


@pytest.mark.parametrize("reset", [False, True])
def test_batch_internal_conflict_rolls_back_whole_batch(
    make_event: Any, reset: bool
) -> None:
    """同一批里同一个 event_id 的两个不同版本必须被检测，且整批不落库。"""

    event_id = "44444444-4444-4444-8444-444444444444"
    first_version = _file_write(make_event, event_id=event_id, bytes_written=1)
    second_version = _file_write(make_event, event_id=event_id, bytes_written=2)

    with SqliteIndex(":memory:") as index:
        # 预置一行，用于验证 reset=True 时的清空也会被回滚。
        keeper = _file_write(
            make_event,
            event_id="55555555-5555-4555-8555-555555555555",
            bytes_written=7,
        )
        index.index_events([keeper])

        with pytest.raises(IndexConflictError, match="完整性冲突"):
            index.rebuild([first_version, second_version], reset=reset)

        assert index.count() == 1
        assert index.query() == (keeper,)
        assert index.verify_integrity().ok is True


def test_batch_conflict_prevents_other_new_events_from_landing(
    make_event: Any
) -> None:
    """批中任一冲突导致同批其他**合法新事件**也不落库（全有或全无）。"""

    event_id = "66666666-6666-4666-8666-666666666666"
    original = _file_write(make_event, event_id=event_id, bytes_written=5)
    conflicting = _file_write(make_event, event_id=event_id, bytes_written=6)
    new_before = _file_write(
        make_event,
        event_id="77777777-7777-4777-8777-777777777777",
        bytes_written=11,
    )
    new_after = _file_write(
        make_event,
        event_id="88888888-8888-4888-8888-888888888888",
        bytes_written=12,
    )

    with SqliteIndex(":memory:") as index:
        index.index_events([original])
        with pytest.raises(IndexConflictError):
            index.index_events([new_before, conflicting, new_after])

        assert index.count() == 1
        assert index.query() == (original,)
        assert index.count(event_types=[EventType.FILE_WRITE]) == 1


def test_conflict_detected_across_multiple_batches(make_event: Any) -> None:
    """先落库、再分多批写入不同内容：每一批都要被拦下。"""

    event_id = "99999999-9999-4999-8999-999999999999"
    with SqliteIndex(":memory:") as index:
        index.index_events([_file_write(make_event, event_id=event_id, bytes_written=1)])
        for attempt in (2, 3):
            with pytest.raises(IndexConflictError):
                index.index_events(
                    [_file_write(make_event, event_id=event_id, bytes_written=attempt)]
                )
        assert index.count() == 1
        assert index.query()[0].payload["bytes_written"] == 1


def test_reset_rebuild_accepts_changed_content_for_same_event_id(
    make_event: Any, tmp_path: Path
) -> None:
    """重建是"以这批输入为准"：reset=True 时不因库里旧内容不同而失败。"""

    event_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    old = _file_write(make_event, event_id=event_id, bytes_written=5)
    new = _file_write(make_event, event_id=event_id, bytes_written=999)

    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index.index_events([old])
        batch = index.rebuild([new], reset=True)
        assert (batch.inserted, batch.deleted) == (1, 1)
        assert index.query() == (new,)
        assert index.query()[0].payload["bytes_written"] == 999


def test_index_conflict_does_not_touch_authoritative_ledger(
    make_event: Any, tmp_path: Path
) -> None:
    """索引冲突不得回写/截断/修补 JSONL，也不得改变已有索引内容。"""

    event_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    ledger_path = tmp_path / "events.jsonl"
    original = _file_write(make_event, event_id=event_id, bytes_written=5)
    _populate(ledger_path, [original])
    ledger_bytes_before = ledger_path.read_bytes()
    ledger_digest_before = ledger_digest(scan_ledger(ledger_path).records)

    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index.rebuild(scan_ledger(ledger_path).records)
        index_digest_before = index.digest()

        conflicting = _file_write(make_event, event_id=event_id, bytes_written=999)
        with pytest.raises(IndexConflictError):
            index.index_records([conflicting])

        assert ledger_path.read_bytes() == ledger_bytes_before
        assert ledger_digest(scan_ledger(ledger_path).records) == ledger_digest_before
        assert scan_ledger(ledger_path).issues == ()
        assert index.digest() == index_digest_before
        assert index.count() == 1
        assert index.query() == (original,)
        assert verify_against_ledger(ledger_path, index).matches is True


def test_conflict_is_read_only_safe(tmp_path: Path, make_event: Any) -> None:
    """只读索引在写入前先拒写：不会因冲突检测而意外写库。"""

    index_path = tmp_path / "idx.sqlite"
    event_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    with SqliteIndex(index_path) as index:
        index.index_events([_file_write(make_event, event_id=event_id, bytes_written=1)])

    with SqliteIndex(index_path, read_only=True) as read_only:
        with pytest.raises(IndexWriteError, match="只读"):
            read_only.index_events(
                [_file_write(make_event, event_id=event_id, bytes_written=2)]
            )
        assert read_only.query()[0].payload["bytes_written"] == 1


def test_rebuild_is_idempotent(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _populate(ledger_path, [make_event(seq=i) for i in range(4)])
    records = scan_ledger(ledger_path).records

    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        first = index.rebuild(records)
        digest_after_first = index.digest()
        count_after_first = index.count()
        second = index.rebuild(records)
        assert first.inserted == 4 and first.deleted == 0
        assert second.inserted == 4 and second.deleted == 4
        assert index.count() == count_after_first == 4
        assert index.digest() == digest_after_first
        assert index.digest() == ledger_digest(records)


def test_rebuild_from_deleted_index_file(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _populate(ledger_path, [make_event(seq=i) for i in range(3)])
    index_path = tmp_path / "idx.sqlite"
    records = scan_ledger(ledger_path).records
    expected = ledger_digest(records)

    with SqliteIndex(index_path) as index:
        index.rebuild(records)
        first_digest = index.digest()
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(index_path) + suffix)
        if candidate.exists():
            candidate.unlink()
    assert not index_path.exists()

    with SqliteIndex(index_path) as rebuilt_index:
        assert rebuilt_index.count() == 0
        rebuilt_index.rebuild(scan_ledger(ledger_path).records)
        assert rebuilt_index.digest() == first_digest == expected


def test_rebuild_reset_true_clears_stale_rows(tmp_path: Path, make_event: Any) -> None:
    stale = make_event(EventType.FILE_OPEN)
    fresh = make_event(EventType.FILE_READ)
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index.index_events([stale])
        index.rebuild([fresh])
        assert index.query() == (fresh,)


def test_index_records_via_ledger_records_carries_offsets(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _populate(ledger_path, [make_event(seq=i) for i in range(2)])
    records = scan_ledger(ledger_path).records
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index.index_records(records)
        row = index._conn.execute(
            "SELECT ledger_line, ledger_offset FROM events ORDER BY id"
        ).fetchone()
    assert row["ledger_line"] == 1
    assert row["ledger_offset"] == records[0].offset


def test_index_rejects_non_event_items() -> None:
    with SqliteIndex(":memory:") as index:
        with pytest.raises(TypeError):
            index.index_events(["nope"])  # type: ignore[list-item]


# --------------------------------------------------------------------------- #
# 事务与故障语义
# --------------------------------------------------------------------------- #


def test_transaction_rolls_back_on_failure(tmp_path: Path, make_event: Any) -> None:
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index._conn.execute(
            "CREATE TRIGGER poison BEFORE INSERT ON events "
            "WHEN NEW.event_type = 'file.unlink' "
            "BEGIN SELECT RAISE(ABORT, 'poison'); END;"
        )
        events = [
            make_event(EventType.FILE_OPEN),
            make_event(EventType.FILE_UNLINK),
            make_event(EventType.FILE_READ),
        ]
        with pytest.raises(IndexWriteError, match="已回滚"):
            index.index_events(events)
        assert index.count() == 0  # 整批回滚，没有半成品
        assert index.verify_integrity().ok is True


def test_index_failure_does_not_touch_authoritative_ledger(
    tmp_path: Path, make_event: Any
) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _populate(ledger_path, [make_event(seq=i) for i in range(3)])
    before_bytes = ledger_path.read_bytes()
    before_digest = ledger_digest(scan_ledger(ledger_path).records)

    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index._conn.execute(
            "CREATE TRIGGER poison BEFORE INSERT ON events "
            "WHEN NEW.event_type = 'file.unlink' "
            "BEGIN SELECT RAISE(ABORT, 'poison'); END;"
        )
        with pytest.raises(IndexWriteError):
            index.rebuild([make_event(EventType.FILE_UNLINK)])

    assert ledger_path.read_bytes() == before_bytes
    assert ledger_digest(scan_ledger(ledger_path).records) == before_digest
    assert scan_ledger(ledger_path).issues == ()


def test_read_only_index_rejects_writes(tmp_path: Path, make_event: Any) -> None:
    index_path = tmp_path / "idx.sqlite"
    with SqliteIndex(index_path) as index:
        index.index_events([make_event()])

    with SqliteIndex(index_path, read_only=True) as read_only:
        assert read_only.read_only is True
        assert read_only.count() == 1
        with pytest.raises(IndexWriteError, match="只读"):
            read_only.index_events([make_event()])


def test_read_only_index_requires_existing_table(tmp_path: Path) -> None:
    with pytest.raises(IndexWriteError):
        SqliteIndex(tmp_path / "missing.sqlite", read_only=True)


def test_create_false_requires_existing_index(tmp_path: Path) -> None:
    with SqliteIndex(tmp_path / "idx.sqlite"):
        pass
    with pytest.raises(IndexWriteError, match="create=False"):
        SqliteIndex(tmp_path / "other.sqlite", create=False)


def test_index_closed_rejects_all_operations(tmp_path: Path, make_event: Any) -> None:
    index = SqliteIndex(tmp_path / "idx.sqlite")
    index.index_events([make_event()])
    index.close()
    index.close()
    assert index.closed is True
    for operation in (
        lambda: index.count(),
        lambda: index.query(),
        lambda: index.digest(),
        lambda: index.index_events([make_event()]),
        lambda: index.verify_integrity(),
    ):
        with pytest.raises(IndexClosedError):
            operation()


def test_index_context_manager_propagates_exceptions(tmp_path: Path) -> None:
    index = SqliteIndex(tmp_path / "idx.sqlite")
    with pytest.raises(RuntimeError, match="boom"):
        with index:
            raise RuntimeError("boom")
    assert index.closed is True


# --------------------------------------------------------------------------- #
# 自检与一致性
# --------------------------------------------------------------------------- #


def test_digest_detects_tampered_row(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _populate(ledger_path, [make_event(seq=i) for i in range(3)])
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index.rebuild(scan_ledger(ledger_path).records)
        assert verify_against_ledger(ledger_path, index).matches is True

        index._conn.execute("UPDATE events SET event_json = '{}' WHERE id = 2")
        report = verify_against_ledger(ledger_path, index)
        assert report.matches is False
        assert report.ledger_events == report.index_rows == 3
        integrity = index.verify_integrity()
        assert integrity.ok is False
        assert len(integrity.bad_event_ids) == 1
        with pytest.raises(IndexReadError):
            index.query(verify_checksums=True)


def test_query_without_checksum_verification_still_revalidates_event(
    tmp_path: Path, make_event: Any
) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _populate(ledger_path, [make_event()])
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index.rebuild(scan_ledger(ledger_path).records)
        index._conn.execute(
            "UPDATE events SET event_json = ? WHERE id = 1",
            ('{"schema_version":1,"event_id":"broken"}',),
        )
        with pytest.raises(IndexReadError, match="无法重建"):
            index.query()


def test_index_only_contains_valid_ledger_events(
    tmp_path: Path, make_event: Any, raw_line: RawLine
) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _populate(ledger_path, [make_event(seq=0), make_event(seq=1)])
    with ledger_path.open("ab") as handle:
        handle.write(b"garbage\n")
        handle.write(raw_line(make_event(seq=2).to_dict(), checksum="sha256:bad"))

    scan = scan_ledger(ledger_path)
    assert len(scan.records) == 2
    assert scan.has_issues is True
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index.rebuild(scan.records)
        assert index.count() == 2
        assert verify_against_ledger(ledger_path, index).matches is True


def test_index_meta_reports_schema_version(tmp_path: Path) -> None:
    from agent_probe.events import INDEX_SCHEMA_VERSION
    from agent_probe.events.index import index_meta

    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        assert index.meta()["index_schema_version"] == str(INDEX_SCHEMA_VERSION)
        assert index_meta(index) == index.meta()


def test_in_memory_index_reports_path() -> None:
    with SqliteIndex(":memory:") as index:
        assert index.path == ":memory:"
        assert index.read_only is False
        assert "SqliteIndex" in repr(index)


def test_index_persists_across_reopen(tmp_path: Path, make_event: Any) -> None:
    index_path = tmp_path / "idx.sqlite"
    event = make_event()
    with SqliteIndex(index_path) as index:
        index.index_events([event])
    with SqliteIndex(index_path) as reopened:
        assert reopened.query() == (event,)


def test_stored_checksums_match_digest_for_intact_index(
    tmp_path: Path, make_event: Any
) -> None:
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index.index_events([make_event(seq=0), make_event(seq=1)])
        stored = index.stored_checksums()
        assert len(stored) == 2
        for event_id, checksum in stored:
            assert event_id
            assert checksum.startswith("sha256:")
        integrity = index.verify_integrity()
        assert integrity.rows == 2
        assert integrity.ok is True
