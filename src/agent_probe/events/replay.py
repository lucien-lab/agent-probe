"""离线重放与一致性校验（M2 核心）。

重放的语义
----------

* **顺序**：严格按 JSONL 的追加顺序产出（*ledger order*）。这不是"全局时间顺序"：
  ``monotonic_ns`` 只在同一 boot 内可比，跨 CPU/跨来源都不能当全局排序键
  （见 ``docs/02-event-ledger.md``）。
* **确定性**：同一账本重复重放得到相同摘要；重复 ``event_id`` 只取首次出现，
  因此"崩溃后重试写入"不会重复计入索引。
* **不静默丢数据**：坏行会分类计入 :class:`~agent_probe.events.quality.LossSnapshot`
  的 ``issues``，而不是被静默跳过。
* **索引是派生物**：可删除后从 JSONL 重建；写索引失败只会抛异常，
  不会触及权威日志。
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .index import IndexBatchResult, SqliteIndex
from .ledger import (
    LedgerIssue,
    LedgerRecord,
    ScanResult,
    ledger_digest,
    scan_ledger,
)
from .model import UnknownFieldPolicy
from .quality import LossCounters, LossSnapshot

__all__ = [
    "ConsistencyReport",
    "ReplayResult",
    "scan",
    "iter_records",
    "replay",
    "replay_into_index",
    "verify_against_ledger",
]


def scan(
    path: str | Path,
    *,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    missing_ok: bool = False,
) -> ScanResult:
    """离线读取账本（``ledger.scan_ledger`` 的重放侧入口）。"""

    return scan_ledger(path, policy=policy, missing_ok=missing_ok)


def iter_records(
    path: str | Path,
    *,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    issues: list[LedgerIssue] | None = None,
    missing_ok: bool = False,
) -> Iterator[LedgerRecord]:
    """流式产出定位记录（``ledger.iter_records`` 的重放侧入口）。

    大账本不必整体载入内存；``issues`` 非 ``None`` 时收集完整性问题。
    """

    from .ledger import iter_records as _iter_records

    return _iter_records(path, policy=policy, issues=issues, missing_ok=missing_ok)


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """一次离线重放的结果摘要。"""

    scan: ScanResult
    snapshot: LossSnapshot
    digest: str
    index: IndexBatchResult | None = None

    @property
    def records(self) -> tuple[LedgerRecord, ...]:
        return self.scan.records

    @property
    def event_count(self) -> int:
        return len(self.scan.records)

    @property
    def clean(self) -> bool:
        """无完整性问题且已知传输层无丢失（**仍不代表探针覆盖完整**）。"""

        return not self.scan.has_issues and self.snapshot.zero_known_loss


def replay(
    ledger_path: str | Path,
    *,
    index: SqliteIndex | None = None,
    counters: LossCounters | None = None,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    reset_index: bool = False,
    missing_ok: bool = False,
) -> ReplayResult:
    """重放账本；可选写入派生索引。

    默认（``index=None``）为**只读**分析路径，不产生任何写入。
    """

    result = scan_ledger(ledger_path, policy=policy, missing_ok=missing_ok)
    active_counters = counters if counters is not None else LossCounters()
    active_counters.add_issues(result.issue_counts)
    active_counters.observe_all(result.events)
    active_counters.note_lines_total(result.lines_total)

    batch: IndexBatchResult | None = None
    if index is not None:
        if reset_index:
            batch = index.rebuild(result.records, reset=True)
        else:
            batch = index.index_records(result.records)

    return ReplayResult(
        scan=result,
        snapshot=active_counters.snapshot(),
        digest=ledger_digest(result.records),
        index=batch,
    )


def replay_into_index(
    ledger_path: str | Path,
    index: SqliteIndex | str | Path,
    *,
    counters: LossCounters | None = None,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    reset: bool = True,
    missing_ok: bool = False,
) -> ReplayResult:
    """把账本重放进 SQLite 索引（默认先清空，保证幂等重建）。

    ``index`` 可以是已打开的 :class:`SqliteIndex`（不会被关闭），
    也可以是路径（内部打开并在结束时关闭）。
    """

    if isinstance(index, SqliteIndex):
        return replay(
            ledger_path,
            index=index,
            counters=counters,
            policy=policy,
            reset_index=reset,
            missing_ok=missing_ok,
        )
    with SqliteIndex(index) as opened:
        return replay(
            ledger_path,
            index=opened,
            counters=counters,
            policy=policy,
            reset_index=reset,
            missing_ok=missing_ok,
        )


@dataclass(frozen=True, slots=True)
class ConsistencyReport:
    """索引与权威日志的一致性报告。"""

    ledger_events: int
    index_rows: int
    ledger_digest: str
    index_digest: str

    @property
    def matches(self) -> bool:
        return (
            self.ledger_events == self.index_rows
            and self.ledger_digest == self.index_digest
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ledger_events": self.ledger_events,
            "index_rows": self.index_rows,
            "ledger_digest": self.ledger_digest,
            "index_digest": self.index_digest,
            "matches": self.matches,
        }


def verify_against_ledger(
    ledger_path: str | Path,
    index: SqliteIndex,
    *,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    missing_ok: bool = False,
) -> ConsistencyReport:
    """比较索引与权威日志（**只读**：不修复、不重建）。

    不一致时调用方应删除索引并用 :func:`replay_into_index` 重建。
    """

    result = scan_ledger(ledger_path, policy=policy, missing_ok=missing_ok)
    return ConsistencyReport(
        ledger_events=len(result.records),
        index_rows=index.count(),
        ledger_digest=ledger_digest(result.records),
        index_digest=index.digest(),
    )
