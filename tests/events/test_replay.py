"""离线重放：顺序、确定性、幂等重建与一致性校验。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent_probe.events import (
    EventType,
    IssueKind,
    JsonlEventLedger,
    LossCounters,
    LossKind,
    SqliteIndex,
    ledger_digest,
    replay,
    replay_into_index,
    scan,
    verify_against_ledger,
)
from agent_probe.events.replay import iter_records


def _write_ledger(ledger_path: Path, events: list[Any]) -> None:
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append_many(events)


def test_scan_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "nope.jsonl"
    with pytest.raises(FileNotFoundError):
        scan(missing)
    assert scan(missing, missing_ok=True).records == ()


def test_replay_preserves_ledger_order(tmp_path: Path, make_event: Any) -> None:
    events = [make_event(monotonic_ns=1_000_000 - i * 1_000, seq=i) for i in range(5)]
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, events)

    result = replay(ledger_path)
    assert result.records and tuple(record.event for record in result.records) == tuple(events)
    assert result.event_count == 5
    assert result.digest == ledger_digest(scan(ledger_path).records)
    assert result.index is None


def test_replay_is_read_only_by_default(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, [make_event()])
    before = ledger_path.read_bytes()
    listing_before = sorted(p.name for p in tmp_path.iterdir())

    replay(ledger_path)

    assert sorted(p.name for p in tmp_path.iterdir()) == listing_before
    assert ledger_path.read_bytes() == before


def test_replay_is_deterministic(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, [make_event(seq=i) for i in range(4)])
    first = replay(ledger_path)
    second = replay(ledger_path)
    assert first.digest == second.digest
    assert first.event_count == second.event_count
    assert first.records == second.records


def test_replay_reports_issues_and_known_loss(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(
        ledger_path,
        [
            make_event(seq=0),
            make_event(EventType.QUALITY_RING_DROP, payload={"count": 4, "reason": "full"}),
            make_event(seq=5),
        ],
    )
    with ledger_path.open("ab") as handle:
        handle.write(b'{"v":1,"len":2,"checksum":"sha256:x","event":{')  # 截断尾行

    result = replay(ledger_path)
    snapshot = result.snapshot
    assert snapshot.loss[LossKind.RING_DROP] == 4
    assert snapshot.loss[LossKind.SEQUENCE_GAP] == 4  # seq 1 -> 5 空洞
    assert snapshot.issues[IssueKind.TRUNCATED_TAIL] == 1
    assert snapshot.lines_total == 4
    assert result.clean is False
    assert snapshot.probe_coverage_complete is False


def test_replay_clean_when_no_issues_and_no_loss(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, [make_event(seq=0), make_event(seq=1)])
    result = replay(ledger_path)
    assert result.clean is True
    assert result.snapshot.zero_known_loss is True


def test_replay_truncated_tail_is_excluded_deterministically(
    tmp_path: Path, make_event: Any
) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, [make_event(seq=0), make_event(seq=1)])
    with ledger_path.open("ab") as handle:
        handle.write(b'{"v":1,"len":9,"checksum":"sha256:y","event":{"a"')

    first = replay(ledger_path)
    second = replay(ledger_path)
    assert first.event_count == 2
    assert first.digest == second.digest
    assert first.scan.truncated_tail is True


def test_replay_into_index_is_idempotent(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    index_path = tmp_path / "idx.sqlite"
    events = [make_event(seq=i) for i in range(4)]
    _write_ledger(ledger_path, events)

    first = replay_into_index(ledger_path, index_path)
    assert first.index is not None
    assert first.index.inserted == 4 and first.index.deleted == 0

    second = replay_into_index(ledger_path, index_path)
    assert second.index is not None
    assert second.index.deleted == 4
    assert first.digest == second.digest

    with SqliteIndex(index_path) as index:
        assert index.count() == 4
        assert index.query() == tuple(events)
        assert index.digest() == first.digest
        assert verify_against_ledger(ledger_path, index).matches is True


def test_replay_into_open_index_does_not_close_it(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, [make_event()])
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        result = replay_into_index(ledger_path, index, reset=True)
        assert result.index is not None
        assert index.closed is False
        assert index.count() == 1


def test_replay_into_index_without_reset_appends(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, [make_event(seq=0)])
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        first = replay_into_index(ledger_path, index, reset=False)
        second = replay_into_index(ledger_path, index, reset=False)
        assert first.index is not None and second.index is not None
        assert first.index.inserted == 1
        assert second.index.inserted == 0 and second.index.duplicates == 1
        assert index.count() == 1


def test_replay_into_deleted_index_rebuilds_from_ledger(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    index_path = tmp_path / "idx.sqlite"
    _write_ledger(ledger_path, [make_event(seq=i) for i in range(3)])

    first = replay_into_index(ledger_path, index_path)
    index_path.unlink()
    for suffix in ("-wal", "-shm"):
        candidate = Path(str(index_path) + suffix)
        if candidate.exists():
            candidate.unlink()

    rebuilt = replay_into_index(ledger_path, index_path)
    assert rebuilt.digest == first.digest
    with SqliteIndex(index_path) as index:
        assert index.count() == 3


def test_verify_against_ledger_detects_missing_rows(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, [make_event(seq=i) for i in range(3)])
    with SqliteIndex(tmp_path / "idx.sqlite") as index:
        index.rebuild(scan(ledger_path).records)
        index._conn.execute("DELETE FROM events WHERE id = 3")
        report = verify_against_ledger(ledger_path, index)
        assert report.matches is False
        assert report.ledger_events == 3
        assert report.index_rows == 2
        assert report.to_dict()["matches"] is False


def test_replay_with_external_counters(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, [make_event(seq=0), make_event(seq=2)])
    counters = LossCounters()
    result = replay(ledger_path, counters=counters)
    assert result.snapshot.loss[LossKind.SEQUENCE_GAP] == 1
    assert counters.snapshot().events_observed == 2


def test_iter_records_streams_and_collects_issues(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, [make_event(seq=0)])
    with ledger_path.open("ab") as handle:
        handle.write(b"junk\n")

    issues: list[Any] = []
    records = list(iter_records(ledger_path, issues=issues))
    assert len(records) == 1
    assert [issue.kind for issue in issues] == [IssueKind.MALFORMED_LINE]

    other_issues: list[Any] = []
    assert list(iter_records(ledger_path, issues=other_issues)) == records
    assert other_issues == issues


def test_iter_records_missing_ok(tmp_path: Path) -> None:
    assert list(iter_records(tmp_path / "nope.jsonl", missing_ok=True)) == []
    with pytest.raises(FileNotFoundError):
        list(iter_records(tmp_path / "nope.jsonl"))


def test_replay_with_preserve_policy(tmp_path: Path, make_event: Any, raw_line: Any) -> None:
    from agent_probe.events import UnknownFieldPolicy

    data = make_event().to_dict()
    data["future"] = ["x"]
    ledger_path = tmp_path / "events.jsonl"
    ledger_path.write_bytes(raw_line(data))

    assert replay(ledger_path).event_count == 0
    preserved = replay(ledger_path, policy=UnknownFieldPolicy.PRESERVE)
    assert preserved.event_count == 1
    assert preserved.records[0].event.to_dict()["future"] == ["x"]


def test_replay_result_accessors(tmp_path: Path, make_event: Any) -> None:
    ledger_path = tmp_path / "events.jsonl"
    _write_ledger(ledger_path, [make_event(seq=0)])
    result = replay(ledger_path)
    assert result.event_count == 1
    assert result.records == result.scan.records
    assert result.scan.lines_valid == 1
