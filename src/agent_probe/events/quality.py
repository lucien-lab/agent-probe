"""丢失与数据质量计数（M2）。

**真值边界（必须与指标一起引用）**

* 本模块的"零丢失"只覆盖**已知传输层**：``ring buffer → 用户态队列 → 磁盘``。
  它**不**代表探针覆盖完整：内核挂点缺失（如 mmap 写、io_uring）、
  未被 hook 的库、被过滤的语义，都不会出现在这里的任何计数中。
  因此快照永远携带 ``probe_coverage_complete = False``。
* 丢失分四类，互不合并：
  ``sequence_gap``（序号空洞）、``ring_drop``（内核 ring buffer 丢弃）、
  ``user_queue_drop``（用户态有界队列溢出）、``storage_drop``（持久化失败/拒绝）。
* 序号空洞有两条来源，生产者必须二选一，不能既逐条发 ``seq`` 又发
  ``quality.sequence_gap`` 事件，否则会重复计数：
  1. 事件头 ``seq`` 连续编号 —— 由本模块在 ``observe()`` 时推导；
  2. ``quality.sequence_gap`` 事件 —— 由探针显式声明一段空洞（含 ``stream`` 粒度）。
  ``seq`` 的流键是 ``(run_id, source)``：若采集器使用 per-CPU 序号，
  必须在探针内聚合后再编号，或改用显式 gap 事件并置 ``seq=None``。
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from .errors import LossCounterError
from .model import Event, EventType

__all__ = [
    "LossKind",
    "IssueKind",
    "LOSS_EVENT_TYPES",
    "LossSnapshot",
    "LossCounters",
]

_STR_TO_LOSS_KIND: Final[dict[str, "LossKind"]] = {}
_STR_TO_ISSUE_KIND: Final[dict[str, "IssueKind"]] = {}


class LossKind(StrEnum):
    """已知传输层的丢失分类。"""

    SEQUENCE_GAP = "sequence_gap"
    RING_DROP = "ring_drop"
    USER_QUEUE_DROP = "user_queue_drop"
    STORAGE_DROP = "storage_drop"


class IssueKind(StrEnum):
    """账本完整性问题分类（读到即记录，不等于事件被丢弃）。"""

    TRUNCATED_TAIL = "truncated_tail"
    MALFORMED_LINE = "malformed_line"
    OVERSIZED_LINE = "oversized_line"
    CHECKSUM_MISMATCH = "checksum_mismatch"
    SCHEMA_UNSUPPORTED = "schema_unsupported"
    EVENT_INVALID = "event_invalid"
    DUPLICATE_EVENT_ID = "duplicate_event_id"
    OUT_OF_ORDER = "out_of_order"
    ENVELOPE_INVALID = "envelope_invalid"


_STR_TO_LOSS_KIND.update({str(kind): kind for kind in LossKind})
_STR_TO_ISSUE_KIND.update({str(kind): kind for kind in IssueKind})


#: ``quality.*`` 事件到丢失分类的映射。
LOSS_EVENT_TYPES: Final[Mapping[EventType, LossKind]] = MappingProxyType(
    {
        EventType.QUALITY_SEQUENCE_GAP: LossKind.SEQUENCE_GAP,
        EventType.QUALITY_RING_DROP: LossKind.RING_DROP,
        EventType.QUALITY_QUEUE_DROP: LossKind.USER_QUEUE_DROP,
        EventType.QUALITY_STORAGE_DROP: LossKind.STORAGE_DROP,
    }
)

#: 快照中"零丢失"的覆盖范围声明（必须原样出现在报告里）。
COVERAGE_SCOPE: Final[str] = "known_transport_layers_only"


def _coerce_loss_kind(value: LossKind | str) -> LossKind:
    if isinstance(value, LossKind):
        return value
    if isinstance(value, str) and value in _STR_TO_LOSS_KIND:
        return _STR_TO_LOSS_KIND[value]
    allowed = ", ".join(str(kind) for kind in LossKind)
    raise LossCounterError(
        f"未知的丢失分类 {value!r}；允许值：{allowed}"
    )


def _coerce_issue_kind(value: IssueKind | str) -> IssueKind:
    if isinstance(value, IssueKind):
        return value
    if isinstance(value, str) and value in _STR_TO_ISSUE_KIND:
        return _STR_TO_ISSUE_KIND[value]
    allowed = ", ".join(str(kind) for kind in IssueKind)
    raise LossCounterError(f"未知的完整性问题分类 {value!r}；允许值：{allowed}")


def _check_count(count: int, *, allow_zero: bool) -> int:
    if isinstance(count, bool) or not isinstance(count, int):
        raise LossCounterError(f"计数必须是整数，实际为 {type(count).__name__}")
    if count < 0 or (count == 0 and not allow_zero):
        raise LossCounterError(f"计数必须为正整数，实际为 {count}")
    return count


@dataclass(frozen=True, slots=True)
class LossSnapshot:
    """某一时刻的数据质量快照。

    ``loss`` 覆盖全部 :class:`LossKind` 键（未发生的为 0）；
    ``issues`` 记录账本扫描发现的完整性问题计数。
    """

    loss: Mapping[LossKind, int] = field(default_factory=dict)
    issues: Mapping[IssueKind, int] = field(default_factory=dict)
    events_observed: int = 0
    events_written: int = 0
    lines_total: int = 0
    sequence_regressions: int = 0
    #: 零丢失声明的覆盖范围与是否代表完整探针覆盖；后者恒为 False。
    coverage_scope: str = COVERAGE_SCOPE
    probe_coverage_complete: bool = False

    def __post_init__(self) -> None:
        normalized_loss: dict[LossKind, int] = {kind: 0 for kind in LossKind}
        for key, value in self.loss.items():
            kind = _coerce_loss_kind(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise LossCounterError(f"丢失计数 {kind} 必须是非负整数，实际为 {value!r}")
            normalized_loss[kind] = value
        object.__setattr__(self, "loss", MappingProxyType(normalized_loss))

        normalized_issues: dict[IssueKind, int] = {}
        for key, value in self.issues.items():
            kind = _coerce_issue_kind(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise LossCounterError(f"问题计数 {kind} 必须是非负整数，实际为 {value!r}")
            if value:
                normalized_issues[kind] = value
        object.__setattr__(self, "issues", MappingProxyType(normalized_issues))

        for name in (
            "events_observed",
            "events_written",
            "lines_total",
            "sequence_regressions",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise LossCounterError(f"{name} 必须是非负整数，实际为 {value!r}")

    # -- 派生量 ------------------------------------------------------------- #

    @property
    def known_transport_lost(self) -> int:
        """已知传输层丢失总数（仅此一项可用于"零丢失"表述）。"""

        return sum(self.loss.values())

    @property
    def zero_known_loss(self) -> bool:
        """已知传输层是否无丢失；**不代表**探针覆盖完整。"""

        return self.known_transport_lost == 0

    @property
    def total_issues(self) -> int:
        return sum(self.issues.values())

    def merged(self, other: LossSnapshot) -> LossSnapshot:
        """合并两个快照（计数相加，覆盖范围声明保持保守）。"""

        loss = {kind: self.loss.get(kind, 0) + other.loss.get(kind, 0) for kind in LossKind}
        issues: dict[IssueKind, int] = dict(self.issues)
        for kind, value in other.issues.items():
            issues[kind] = issues.get(kind, 0) + value
        return LossSnapshot(
            loss=loss,
            issues=issues,
            events_observed=self.events_observed + other.events_observed,
            events_written=self.events_written + other.events_written,
            lines_total=self.lines_total + other.lines_total,
            sequence_regressions=self.sequence_regressions + other.sequence_regressions,
        )

    def to_dict(self) -> dict[str, Any]:
        """转成 JSON 友好字典（枚举键转字符串）。"""

        return {
            "loss": {str(kind): self.loss.get(kind, 0) for kind in LossKind},
            "issues": {str(kind): value for kind, value in sorted(
                ((str(k), v) for k, v in self.issues.items())
            )},
            "events_observed": self.events_observed,
            "events_written": self.events_written,
            "lines_total": self.lines_total,
            "sequence_regressions": self.sequence_regressions,
            "known_transport_lost": self.known_transport_lost,
            "zero_known_loss": self.zero_known_loss,
            "coverage_scope": self.coverage_scope,
            "probe_coverage_complete": self.probe_coverage_complete,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LossSnapshot:
        """从 :meth:`to_dict` 的输出恢复快照。"""

        if not isinstance(data, Mapping):
            raise LossCounterError(f"快照必须是对象，实际为 {type(data).__name__}")
        loss = data.get("loss", {}) or {}
        issues = data.get("issues", {}) or {}
        if not isinstance(loss, Mapping) or not isinstance(issues, Mapping):
            raise LossCounterError("快照的 loss/issues 必须是对象")
        return cls(
            loss=loss,
            issues=issues,
            events_observed=int(data.get("events_observed", 0)),
            events_written=int(data.get("events_written", 0)),
            lines_total=int(data.get("lines_total", 0)),
            sequence_regressions=int(data.get("sequence_regressions", 0)),
        )


class LossCounters:
    """线程安全的丢失/数据质量计数器。

    典型用法：采集循环对每条解析成功的事件调用 :meth:`observe`；
    传输层丢弃调用 :meth:`record_loss`；账本扫描结果用
    :meth:`add_issues` 并入；最后 :meth:`snapshot` 交给报告。
    """

    __slots__ = ("_lock", "_loss", "_issues", "_last_seq", "_observed", "_written", "_lines", "_regressions")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loss: dict[LossKind, int] = {kind: 0 for kind in LossKind}
        self._issues: dict[IssueKind, int] = {}
        self._last_seq: dict[tuple[str, str], int] = {}
        self._observed = 0
        self._written = 0
        self._lines = 0
        self._regressions = 0

    # -- 写入侧 ------------------------------------------------------------- #

    def record_loss(
        self,
        kind: LossKind | str,
        count: int = 1,
        *,
        reason: str | None = None,
        track_reason: bool = False,
    ) -> int:
        """登记一次已知传输层丢失，返回该分类的累计值。

        ``reason`` 只用于错误信息与可选记账（``track_reason``）；
        原因分类不是权威维度，需要细分时应使用 ``quality.*`` 事件的 payload。
        """

        resolved = _coerce_loss_kind(kind)
        amount = _check_count(count, allow_zero=True)
        with self._lock:
            if amount:
                self._loss[resolved] += amount
            return self._loss[resolved]

    def record_issue(self, kind: IssueKind | str, count: int = 1) -> int:
        """登记一次账本完整性问题计数。"""

        resolved = _coerce_issue_kind(kind)
        amount = _check_count(count, allow_zero=True)
        with self._lock:
            if amount:
                self._issues[resolved] = self._issues.get(resolved, 0) + amount
            return self._issues.get(resolved, 0)

    def add_issues(self, counts: Mapping[IssueKind | str, int]) -> None:
        """并入一批完整性问题计数（例如 ``ScanResult.issue_counts``）。"""

        if not isinstance(counts, Mapping):
            raise LossCounterError(
                f"issues 必须是映射，实际为 {type(counts).__name__}"
            )
        for kind, count in counts.items():
            self.record_issue(kind, count)

    def observe(self, event: Event, *, track_sequence_gaps: bool = True) -> None:
        """观察一条合法事件，更新计数与序号空洞统计。"""

        with self._lock:
            self._observed += 1
            loss_delta = self._loss_delta_for(event)
            for kind, amount in loss_delta.items():
                self._loss[kind] += amount
            if track_sequence_gaps and event.seq is not None:
                self._track_sequence(event)

    def observe_all(
        self, events: Iterable[Event], *, track_sequence_gaps: bool = True
    ) -> None:
        for event in events:
            self.observe(event, track_sequence_gaps=track_sequence_gaps)

    def note_events_written(self, count: int) -> None:
        """记账本写入器已写的行数（扫描/重放路径为 0）。"""

        amount = _check_count(count, allow_zero=True)
        with self._lock:
            self._written += amount

    def note_lines_total(self, lines: int) -> None:
        """记账本物理总行数（含被跳过的坏行）。"""

        amount = _check_count(lines, allow_zero=True)
        with self._lock:
            self._lines += amount

    # -- 内部 --------------------------------------------------------------- #

    def _loss_delta_for(self, event: Event) -> dict[LossKind, int]:
        """从 ``quality.*`` 事件推导丢失增量（调用方已持锁）。"""

        if event.event_type is EventType.QUALITY_SEQUENCE_GAP:
            return {LossKind.SEQUENCE_GAP: int(event.payload["missing"])}
        if event.event_type is EventType.QUALITY_RING_DROP:
            return {LossKind.RING_DROP: int(event.payload["count"])}
        if event.event_type is EventType.QUALITY_QUEUE_DROP:
            return {LossKind.USER_QUEUE_DROP: int(event.payload["count"])}
        if event.event_type is EventType.QUALITY_STORAGE_DROP:
            return {LossKind.STORAGE_DROP: int(event.payload["count"])}
        if event.event_type is EventType.QUALITY_COUNTER_SNAPSHOT:
            delta: dict[LossKind, int] = {}
            for key, value in event.payload["counters"].items():
                kind = _coerce_loss_kind(key)
                delta[kind] = delta.get(kind, 0) + int(value)
            return delta
        return {}

    def _track_sequence(self, event: Event) -> None:
        key = (event.run_id, str(event.source))
        seq = int(event.seq)
        previous = self._last_seq.get(key)
        if previous is None:
            self._last_seq[key] = seq
            return
        if seq > previous + 1:
            self._loss[LossKind.SEQUENCE_GAP] += seq - previous - 1
        elif seq <= previous:
            # 序号回退不是空洞：单独统计，避免把重复/乱序误报成丢失。
            self._regressions += 1
        if seq > previous:
            self._last_seq[key] = seq

    # -- 快照 --------------------------------------------------------------- #

    def snapshot(
        self,
        *,
        events_written: int | None = None,
        lines_total: int | None = None,
    ) -> LossSnapshot:
        """返回当前计数快照；可选覆盖写入行数与物理行数。"""

        with self._lock:
            return LossSnapshot(
                loss=dict(self._loss),
                issues=dict(self._issues),
                events_observed=self._observed,
                events_written=self._written if events_written is None else events_written,
                lines_total=self._lines if lines_total is None else lines_total,
                sequence_regressions=self._regressions,
            )
