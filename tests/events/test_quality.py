"""丢失与数据质量计数：分类、快照、真值边界与线程安全。"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from agent_probe.events import (
    EventType,
    IssueKind,
    LossCounterError,
    LossCounters,
    LossKind,
    LossSnapshot,
)
from agent_probe.events.quality import COVERAGE_SCOPE


def test_loss_snapshot_zero_fills_all_kinds() -> None:
    snapshot = LossSnapshot()
    assert set(snapshot.loss) == set(LossKind)
    assert all(value == 0 for value in snapshot.loss.values())
    assert snapshot.known_transport_lost == 0
    assert snapshot.zero_known_loss is True
    # 零丢失只覆盖已知传输层。
    assert snapshot.coverage_scope == COVERAGE_SCOPE == "known_transport_layers_only"
    assert snapshot.probe_coverage_complete is False


@pytest.mark.parametrize(
    "event_type, field, amount",
    [
        (EventType.QUALITY_RING_DROP, "count", 2),
        (EventType.QUALITY_QUEUE_DROP, "count", 3),
        (EventType.QUALITY_STORAGE_DROP, "count", 4),
    ],
)
def test_drop_events_are_classified(
    make_event: Any, event_type: EventType, field: str, amount: int
) -> None:
    counters = LossCounters()
    counters.observe(make_event(event_type, payload={field: amount, "reason": "busy"}))
    snapshot = counters.snapshot()
    assert snapshot.known_transport_lost == amount
    assert snapshot.events_observed == 1
    assert snapshot.zero_known_loss is False


def test_sequence_gap_event_counts_missing(make_event: Any) -> None:
    counters = LossCounters()
    counters.observe(
        make_event(
            EventType.QUALITY_SEQUENCE_GAP,
            payload={
                "stream": "ebpf/ring0",
                "expected_seq": 10,
                "received_seq": 14,
                "missing": 4,
            },
        )
    )
    assert counters.snapshot().loss[LossKind.SEQUENCE_GAP] == 4


def test_sequence_gap_derived_from_seq_numbers(make_event: Any) -> None:
    counters = LossCounters()
    for seq in (0, 1, 2, 5, 6):
        counters.observe(make_event(seq=seq))
    snapshot = counters.snapshot()
    assert snapshot.loss[LossKind.SEQUENCE_GAP] == 2
    assert snapshot.events_observed == 5
    assert snapshot.sequence_regressions == 0


def test_seq_regression_is_not_counted_as_gap(make_event: Any) -> None:
    counters = LossCounters()
    for seq in (0, 1, 5, 3, 4):
        counters.observe(make_event(seq=seq))
    snapshot = counters.snapshot()
    assert snapshot.loss[LossKind.SEQUENCE_GAP] == 3  # 只统计 1 -> 5
    assert snapshot.sequence_regressions == 2  # 逆序 3、4


def test_sequence_tracking_is_per_run_and_source(
    make_event: Any, other_run_id: str
) -> None:
    counters = LossCounters()
    counters.observe(make_event(seq=0))
    counters.observe(make_event(seq=0, source="userspace"))  # 另一条流
    counters.observe(make_event(seq=0, run=other_run_id))  # 另一个 run
    counters.observe(make_event(seq=1))
    assert counters.snapshot().loss[LossKind.SEQUENCE_GAP] == 0


def test_sequence_tracking_can_be_disabled(make_event: Any) -> None:
    counters = LossCounters()
    for seq in (0, 9):
        counters.observe(make_event(seq=seq), track_sequence_gaps=False)
    assert counters.snapshot().loss[LossKind.SEQUENCE_GAP] == 0


def test_events_without_seq_are_not_tracked(make_event: Any) -> None:
    counters = LossCounters()
    counters.observe_all([make_event(), make_event()])
    assert counters.snapshot().loss[LossKind.SEQUENCE_GAP] == 0
    assert counters.snapshot().events_observed == 2


def test_counter_snapshot_event_merges_named_counters(make_event: Any) -> None:
    counters = LossCounters()
    counters.observe(
        make_event(
            EventType.QUALITY_COUNTER_SNAPSHOT,
            payload={"counters": {"ring_drop": 5, "user_queue_drop": 2}},
        )
    )
    snapshot = counters.snapshot()
    assert snapshot.loss[LossKind.RING_DROP] == 5
    assert snapshot.loss[LossKind.USER_QUEUE_DROP] == 2
    assert snapshot.known_transport_lost == 7


def test_counter_snapshot_rejects_unknown_counter_name(make_event: Any) -> None:
    counters = LossCounters()
    with pytest.raises(LossCounterError, match="未知的丢失分类"):
        counters.observe(
            make_event(EventType.QUALITY_COUNTER_SNAPSHOT, payload={"counters": {"nope": 1}})
        )


def test_record_loss_validates_input() -> None:
    counters = LossCounters()
    assert counters.record_loss(LossKind.RING_DROP, 3) == 3
    assert counters.record_loss("ring_drop", 2) == 5
    assert counters.record_loss(LossKind.RING_DROP, 0) == 5
    with pytest.raises(LossCounterError, match="正整数"):
        counters.record_loss(LossKind.RING_DROP, -1)
    with pytest.raises(LossCounterError, match="整数"):
        counters.record_loss(LossKind.RING_DROP, True)
    with pytest.raises(LossCounterError, match="未知的丢失分类"):
        counters.record_loss("disk_melt", 1)


def test_record_issue_and_add_issues() -> None:
    counters = LossCounters()
    assert counters.record_issue(IssueKind.CHECKSUM_MISMATCH) == 1
    counters.add_issues({IssueKind.MALFORMED_LINE: 2, "truncated_tail": 1})
    snapshot = counters.snapshot()
    assert snapshot.issues[IssueKind.CHECKSUM_MISMATCH] == 1
    assert snapshot.issues[IssueKind.MALFORMED_LINE] == 2
    assert snapshot.issues[IssueKind.TRUNCATED_TAIL] == 1
    assert snapshot.total_issues == 4
    with pytest.raises(LossCounterError, match="未知的完整性问题分类"):
        counters.record_issue("something_else")
    with pytest.raises(LossCounterError, match="映射"):
        counters.add_issues([("ring_drop", 1)])  # type: ignore[arg-type]


def test_snapshot_serialization_roundtrip() -> None:
    counters = LossCounters()
    counters.record_loss(LossKind.RING_DROP, 2)
    counters.record_issue(IssueKind.OUT_OF_ORDER, 3)
    counters.note_events_written(10)
    counters.note_lines_total(12)
    snapshot = counters.snapshot()

    data = snapshot.to_dict()
    assert data["loss"]["ring_drop"] == 2
    assert data["issues"]["out_of_order"] == 3
    assert data["known_transport_lost"] == 2
    assert data["zero_known_loss"] is False
    assert data["probe_coverage_complete"] is False

    restored = LossSnapshot.from_dict(data)
    assert restored.loss[LossKind.RING_DROP] == 2
    assert restored.issues[IssueKind.OUT_OF_ORDER] == 3
    assert restored.events_written == 10
    assert restored.lines_total == 12
    assert restored.zero_known_loss is False


def test_snapshot_rejects_bad_values() -> None:
    with pytest.raises(LossCounterError):
        LossSnapshot(loss={LossKind.RING_DROP: -1})
    with pytest.raises(LossCounterError):
        LossSnapshot(events_observed=-1)
    with pytest.raises(LossCounterError, match="未知的丢失分类"):
        LossSnapshot(loss={"mystery": 1})
    with pytest.raises(LossCounterError, match="必须是对象"):
        LossSnapshot.from_dict("nope")  # type: ignore[arg-type]


def test_snapshot_merge_sums_counters_but_stays_conservative() -> None:
    first = LossSnapshot(loss={LossKind.RING_DROP: 1}, events_observed=2)
    second = LossSnapshot(loss={LossKind.RING_DROP: 3}, events_observed=4)
    merged = first.merged(second)
    assert merged.loss[LossKind.RING_DROP] == 4
    assert merged.events_observed == 6
    assert merged.probe_coverage_complete is False
    assert merged.coverage_scope == COVERAGE_SCOPE


def test_snapshot_is_immutable() -> None:
    snapshot = LossSnapshot(loss={LossKind.RING_DROP: 1})
    with pytest.raises(TypeError):
        snapshot.loss[LossKind.RING_DROP] = 5  # type: ignore[index]


def test_counters_are_thread_safe() -> None:
    counters = LossCounters()

    def worker() -> None:
        for _ in range(250):
            counters.record_loss(LossKind.USER_QUEUE_DROP, 1)
            counters.record_issue(IssueKind.OUT_OF_ORDER, 1)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    snapshot = counters.snapshot()
    assert snapshot.loss[LossKind.USER_QUEUE_DROP] == 1000
    assert snapshot.issues[IssueKind.OUT_OF_ORDER] == 1000


def test_snapshot_override_of_written_and_lines_counts(make_event: Any) -> None:
    counters = LossCounters()
    counters.observe(make_event())
    snapshot = counters.snapshot(events_written=7, lines_total=9)
    assert snapshot.events_observed == 1
    assert snapshot.events_written == 7
    assert snapshot.lines_total == 9


def test_note_helpers_reject_negative_counts() -> None:
    counters = LossCounters()
    with pytest.raises(LossCounterError):
        counters.note_events_written(-1)
    with pytest.raises(LossCounterError):
        counters.note_lines_total(-1)
