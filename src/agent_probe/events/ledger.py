"""JSONL 权威事件日志（M2 核心）。

不变式
------

1. **一行一个完整事件**：每行是规范化 JSON 的"信封" ``{v,len,checksum,event}``，
   ``checksum`` 是 ``event`` 规范化字节的 SHA-256，``len`` 是同一字节长度。
2. **append-only**：本模块只追加、不就地改写。唯一允许的例外是显式请求的
   ``truncate_tail=True`` 尾部修复，且修复动作会被记录到写入统计里。
3. **权威性**：JSONL 是唯一真值；SQLite 索引（``index.py``）是可删除重建的派生物。
   索引失败不得回写、截断或修补本文件。
4. **失败可见**：截断尾行、校验错、重复 ``event_id``、不支持的 schema、
   乱序、坏 JSON、超长行都会被扫描分类报告，绝不静默跳过。

fsync 取舍见 ``docs/02-event-ledger.md``；简言之 ``ALWAYS``/``BATCH``/``NEVER``
三档分别对应"每条事件可承受崩溃"、"按批可承受崩溃（默认 128 行）"、
"性能优先、崩溃后可能丢尾部（仅用于测试/临时回放）"。

多写入者：同一路径**不支持**并发写入。写入者通过 ``<path>.lock`` 的
``flock(LOCK_EX|LOCK_NB)`` 互斥，并在进程内额外检测重复打开；
第二方会得到 :class:`ConcurrentWriterError` 而不是交错写入。
读取者不握锁，但因此可能看到写入中的半行——这会被识别为
``TRUNCATED_TAIL`` 而不是被当作有效事件。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

from .errors import (
    ConcurrentWriterError,
    EventTooLargeError,
    EventValidationError,
    LedgerClosedError,
    LedgerLockError,
    OutOfOrderEventError,
    TruncatedLedgerError,
)
from .model import (
    MAX_EVENT_BYTES,
    SUPPORTED_SCHEMA_VERSIONS,
    Event,
    UnknownFieldPolicy,
    canonical_json,
    event_from_dict,
    event_to_bytes,
    event_to_dict,
)
from .quality import IssueKind

try:  # pragma: no cover - 平台分支；Linux/macOS 均提供 fcntl
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "ENVELOPE_VERSION",
    "MAX_LINE_BYTES",
    "LOCK_SUFFIX",
    "DEFAULT_FSYNC_BATCH_LINES",
    "FsyncPolicy",
    "LedgerRecord",
    "LedgerIssue",
    "LedgerWriteStats",
    "ScanResult",
    "JsonlEventLedger",
    "build_envelope_line",
    "compute_checksum",
    "scan_ledger",
    "iter_events",
    "iter_records",
    "ledger_digest",
    "read_ledger_events",
]

#: 信封格式版本（与事件 ``schema_version`` 独立）。
ENVELOPE_VERSION: Final[int] = 1

#: 单行允许的最大物理字节数（事件上限 + 信封开销）。
MAX_LINE_BYTES: Final[int] = MAX_EVENT_BYTES + 4096

#: 写锁文件后缀。
LOCK_SUFFIX: Final[str] = ".lock"

#: ``BATCH`` 策略的默认 fsync 间隔（行）。
DEFAULT_FSYNC_BATCH_LINES: Final[int] = 128

#: 写入缓冲大小。
_BUFFER_BYTES: Final[int] = 64 * 1024

_CHECKSUM_ALGO: Final[str] = "sha256"

#: 进程内已打开的账本路径（防止同进程重复打开绕过 flock 语义差异）。
_INPROCESS_LOCKS: set[str] = set()
_INPROCESS_LOCK_GUARD = threading.Lock()


class FsyncPolicy(StrEnum):
    """持久化策略。"""

    ALWAYS = "always"
    BATCH = "batch"
    NEVER = "never"


def compute_checksum(payload: bytes) -> str:
    """返回 ``sha256:<hex>`` 形式的完整性校验值。"""

    digest = hashlib.sha256(payload).hexdigest()
    return f"{_CHECKSUM_ALGO}:{digest}"


def build_envelope_line(event: Event) -> tuple[bytes, str, int]:
    """构造一行账本字节。

    返回 ``(line_bytes, checksum, event_byte_length)``；``line_bytes`` 以 ``\\n`` 结尾。
    """

    body = event_to_bytes(event)
    checksum = compute_checksum(body)
    envelope = {
        "v": ENVELOPE_VERSION,
        "len": len(body),
        "checksum": checksum,
        "event": event_to_dict(event),
    }
    line = canonical_json(envelope).encode("utf-8") + b"\n"
    if len(line) > MAX_LINE_BYTES:
        raise EventTooLargeError(
            f"账本行长度为 {len(line)} 字节，超过上限 {MAX_LINE_BYTES}"
        )
    return line, checksum, len(body)


@dataclass(frozen=True, slots=True)
class LedgerRecord:
    """账本中一条已定位的事件记录。"""

    event: Event
    line_no: int
    offset: int
    byte_length: int
    checksum: str


@dataclass(frozen=True, slots=True)
class LedgerIssue:
    """扫描发现的完整性问题。``line_no`` 为 1 起算的物理行号。"""

    kind: IssueKind
    line_no: int
    offset: int
    message: str
    event_id: str | None = None


@dataclass(frozen=True, slots=True)
class LedgerWriteStats:
    """写入器统计快照。"""

    lines_written: int
    bytes_written: int
    fsyncs: int
    pending_lines: int
    out_of_order_lines: int
    tail_repaired_bytes: int
    last_offset: int
    closed: bool


@dataclass(frozen=True, slots=True)
class ScanResult:
    """账本扫描结果（权威顺序 = 文件追加顺序）。"""

    records: tuple[LedgerRecord, ...] = ()
    issues: tuple[LedgerIssue, ...] = ()
    lines_total: int = 0
    lines_valid: int = 0
    lines_skipped: int = 0
    bytes_total: int = 0

    @property
    def events(self) -> tuple[Event, ...]:
        return tuple(record.event for record in self.records)

    @property
    def duplicate_event_ids(self) -> tuple[str, ...]:
        ids = [
            issue.event_id
            for issue in self.issues
            if issue.kind is IssueKind.DUPLICATE_EVENT_ID and issue.event_id is not None
        ]
        return tuple(ids)

    @property
    def has_issues(self) -> bool:
        return bool(self.issues)

    @property
    def truncated_tail(self) -> bool:
        return any(issue.kind is IssueKind.TRUNCATED_TAIL for issue in self.issues)

    @property
    def issue_counts(self) -> Mapping[str, int]:
        counts: dict[str, int] = {}
        for issue in self.issues:
            key = str(issue.kind)
            counts[key] = counts.get(key, 0) + 1
        return MappingProxyType(counts)

    def kinds_causing_skips(self) -> tuple[IssueKind, ...]:
        """返回导致事件被跳过的分类（不含仅告警的 ``out_of_order``）。"""

        skipping = {
            IssueKind.TRUNCATED_TAIL,
            IssueKind.MALFORMED_LINE,
            IssueKind.OVERSIZED_LINE,
            IssueKind.CHECKSUM_MISMATCH,
            IssueKind.SCHEMA_UNSUPPORTED,
            IssueKind.EVENT_INVALID,
            IssueKind.DUPLICATE_EVENT_ID,
            IssueKind.ENVELOPE_INVALID,
        }
        seen: list[IssueKind] = []
        for issue in self.issues:
            if issue.kind in skipping and issue.kind not in seen:
                seen.append(issue.kind)
        return tuple(seen)


def ledger_digest(records: Iterable[LedgerRecord]) -> str:
    """账本内容摘要：``sha256`` over ``event_id:checksum`` 行序列。

    索引摘要用相同规则计算，因此可用于证明"索引与权威日志一致"。
    """

    hasher = hashlib.sha256()
    for record in records:
        hasher.update(f"{record.event.event_id}:{record.checksum}\n".encode("utf-8"))
    return f"{_CHECKSUM_ALGO}:{hasher.hexdigest()}"


# --------------------------------------------------------------------------- #
# 原始行迭代（含尾部截断与超长行识别）
# --------------------------------------------------------------------------- #

_LINE_OK: Final[str] = "line"
_LINE_TAIL: Final[str] = "tail"
_LINE_OVERSIZED: Final[str] = "oversized"


def _iter_raw_lines(fh: Any, limit: int) -> Iterator[tuple[bytes, str, int]]:
    """逐物理行产出 ``(chunk, state, consumed_bytes)``。

    ``state`` 为 ``line``（完整行）、``tail``（EOF 处无换行的不完整行）
    或 ``oversized``（单行超过 ``limit``，已丢弃剩余字节以重新同步）。
    """

    while True:
        chunk = fh.readline(limit)
        if not chunk:
            return
        if chunk.endswith(b"\n"):
            yield chunk, _LINE_OK, len(chunk)
            continue
        if len(chunk) < limit:
            yield chunk, _LINE_TAIL, len(chunk)
            return
        consumed = len(chunk)
        while True:
            more = fh.readline(limit)
            if not more:
                break
            consumed += len(more)
            if more.endswith(b"\n"):
                break
        if consumed == len(chunk):
            # 已到 EOF 且没有任何后续字节：是截断尾行，而不是超长行。
            yield chunk, _LINE_TAIL, consumed
            return
        yield chunk, _LINE_OVERSIZED, consumed


def _stream_ledger(
    path: Path,
    *,
    policy: UnknownFieldPolicy,
) -> Iterator[tuple[str, Any]]:
    """低层流式扫描。

    产出事件对：

    * ``("line", line_no)``：读到一条物理行（无论是否有效）。
    * ``("record", LedgerRecord)``：有效且首次出现的记录。
    * ``("issue", LedgerIssue)``：完整性问题。
    * 结束时 ``("bytes", total_bytes)``。
    """

    seen_event_ids: set[str] = set()
    last_monotonic: dict[tuple[str, str], int] = {}
    line_no = 0
    offset = 0

    with open(path, "rb") as fh:
        for raw, state, consumed in _iter_raw_lines(fh, MAX_LINE_BYTES):
            line_no += 1
            line_offset = offset
            offset += consumed
            yield ("line", line_no)

            if state == _LINE_TAIL:
                if raw.strip():
                    yield (
                        "issue",
                        LedgerIssue(
                            kind=IssueKind.TRUNCATED_TAIL,
                            line_no=line_no,
                            offset=line_offset,
                            message=(
                                "文件末尾存在无换行的不完整行（崩溃或写入中断）；"
                                f"已丢弃 {len(raw)} 字节"
                            ),
                        ),
                    )
                continue
            if state == _LINE_OVERSIZED:
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.OVERSIZED_LINE,
                        line_no=line_no,
                        offset=line_offset,
                        message=f"单行超过 {MAX_LINE_BYTES} 字节上限，已跳过并重新同步",
                    ),
                )
                continue

            stripped = raw.rstrip(b"\r\n")
            if not stripped.strip():
                continue

            try:
                envelope = json.loads(stripped)
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.MALFORMED_LINE,
                        line_no=line_no,
                        offset=line_offset,
                        message=f"JSON 解析失败：{exc}",
                    ),
                )
                continue

            if not isinstance(envelope, dict):
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.ENVELOPE_INVALID,
                        line_no=line_no,
                        offset=line_offset,
                        message="账本行必须是 JSON 对象信封 {v,len,checksum,event}",
                    ),
                )
                continue
            if envelope.get("v") != ENVELOPE_VERSION:
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.ENVELOPE_INVALID,
                        line_no=line_no,
                        offset=line_offset,
                        message=(
                            f"不支持的账本信封版本 {envelope.get('v')!r}"
                            f"（支持 {ENVELOPE_VERSION}）"
                        ),
                    ),
                )
                continue

            event_dict = envelope.get("event")
            if not isinstance(event_dict, dict):
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.ENVELOPE_INVALID,
                        line_no=line_no,
                        offset=line_offset,
                        message="信封缺少对象字段 event",
                    ),
                )
                continue

            tentative_id = event_dict.get("event_id")
            tentative_id_str = tentative_id if isinstance(tentative_id, str) else None

            try:
                body = canonical_json(event_dict).encode("utf-8")
            except (TypeError, ValueError) as exc:
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.ENVELOPE_INVALID,
                        line_no=line_no,
                        offset=line_offset,
                        message=f"event 字段无法规范化序列化：{exc}",
                        event_id=tentative_id_str,
                    ),
                )
                continue

            declared_checksum = envelope.get("checksum")
            actual_checksum = compute_checksum(body)
            if declared_checksum != actual_checksum:
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.CHECKSUM_MISMATCH,
                        line_no=line_no,
                        offset=line_offset,
                        message=(
                            f"校验值不匹配（声明 {declared_checksum!r}，"
                            f"实际 {actual_checksum!r}）"
                        ),
                        event_id=tentative_id_str,
                    ),
                )
                continue
            declared_len = envelope.get("len")
            if declared_len != len(body):
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.CHECKSUM_MISMATCH,
                        line_no=line_no,
                        offset=line_offset,
                        message=(
                            f"事件字节长度不匹配（声明 {declared_len!r}，"
                            f"实际 {len(body)}）"
                        ),
                        event_id=tentative_id_str,
                    ),
                )
                continue

            if event_dict.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
                supported = ", ".join(str(v) for v in sorted(SUPPORTED_SCHEMA_VERSIONS))
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.SCHEMA_UNSUPPORTED,
                        line_no=line_no,
                        offset=line_offset,
                        message=(
                            f"不支持的 schema_version "
                            f"{event_dict.get('schema_version')!r}（支持：{supported}）"
                        ),
                        event_id=tentative_id_str,
                    ),
                )
                continue

            try:
                event = event_from_dict(event_dict, policy=policy)
            except EventValidationError as exc:
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.EVENT_INVALID,
                        line_no=line_no,
                        offset=line_offset,
                        message=f"事件未通过校验：{exc}",
                        event_id=tentative_id_str,
                    ),
                )
                continue

            if event.event_id in seen_event_ids:
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.DUPLICATE_EVENT_ID,
                        line_no=line_no,
                        offset=line_offset,
                        message="重复的 event_id；保留首次出现，丢弃该行（幂等重放）",
                        event_id=event.event_id,
                    ),
                )
                continue
            seen_event_ids.add(event.event_id)

            stream_key = (event.run_id, str(event.source))
            previous = last_monotonic.get(stream_key)
            if previous is not None and event.monotonic_ns < previous:
                yield (
                    "issue",
                    LedgerIssue(
                        kind=IssueKind.OUT_OF_ORDER,
                        line_no=line_no,
                        offset=line_offset,
                        message=(
                            f"monotonic_ns {event.monotonic_ns} 早于同一 "
                            f"(run_id,source) 的上一条 {previous}；"
                            "事件保留，仅作数据质量告警"
                        ),
                        event_id=event.event_id,
                    ),
                )
            else:
                last_monotonic[stream_key] = event.monotonic_ns

            yield (
                "record",
                LedgerRecord(
                    event=event,
                    line_no=line_no,
                    offset=line_offset,
                    byte_length=consumed,
                    checksum=actual_checksum,
                ),
            )

    yield ("bytes", offset)


def scan_ledger(
    path: str | Path,
    *,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    missing_ok: bool = False,
) -> ScanResult:
    """扫描账本，返回有效记录与全部完整性问题。

    ``policy`` 必须与写入时使用的未知字段策略一致（默认 ``REJECT``）。
    """

    target = Path(path)
    if not target.exists():
        if missing_ok:
            return ScanResult()
        raise FileNotFoundError(f"账本文件不存在：{target}")

    records: list[LedgerRecord] = []
    issues: list[LedgerIssue] = []
    lines_total = 0
    bytes_total = 0
    for kind, payload in _stream_ledger(target, policy=policy):
        if kind == "line":
            lines_total += 1
        elif kind == "record":
            records.append(payload)
        elif kind == "issue":
            issues.append(payload)
        else:
            bytes_total = int(payload)

    return ScanResult(
        records=tuple(records),
        issues=tuple(issues),
        lines_total=lines_total,
        lines_valid=len(records),
        lines_skipped=lines_total - len(records),
        bytes_total=bytes_total,
    )


def iter_events(
    path: str | Path,
    *,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    issues: list[LedgerIssue] | None = None,
    missing_ok: bool = False,
) -> Iterator[Event]:
    """流式产出有效事件（权威顺序 = 文件追加顺序）。

    ``issues`` 非 ``None`` 时，完整性问题会追加到该列表，调用方因此不会
    "静默消费"坏行。
    """

    for kind, payload in _stream_or_empty(path, policy=policy, missing_ok=missing_ok):
        if kind == "record":
            yield payload.event
        elif kind == "issue" and issues is not None:
            issues.append(payload)


def iter_records(
    path: str | Path,
    *,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    issues: list[LedgerIssue] | None = None,
    missing_ok: bool = False,
) -> Iterator[LedgerRecord]:
    """流式产出定位记录（含行号/偏移/校验值）。

    与 :func:`iter_events` 同一套解析逻辑，区别只是保留账本定位信息，
    供索引记录溯源使用。
    """

    for kind, payload in _stream_or_empty(path, policy=policy, missing_ok=missing_ok):
        if kind == "record":
            yield payload
        elif kind == "issue" and issues is not None:
            issues.append(payload)


def _stream_or_empty(
    path: str | Path,
    *,
    policy: UnknownFieldPolicy,
    missing_ok: bool,
) -> Iterator[tuple[str, Any]]:
    target = Path(path)
    if not target.exists():
        if missing_ok:
            return
        raise FileNotFoundError(f"账本文件不存在：{target}")
    yield from _stream_ledger(target, policy=policy)


def read_ledger_events(
    path: str | Path,
    *,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    missing_ok: bool = False,
) -> ScanResult:
    """``scan_ledger`` 的别名，强调"读取权威记录"用途。"""

    return scan_ledger(path, policy=policy, missing_ok=missing_ok)


# --------------------------------------------------------------------------- #
# 写锁
# --------------------------------------------------------------------------- #


def _lock_path(path: Path) -> Path:
    return path.with_name(path.name + LOCK_SUFFIX)


def _acquire_writer_lock(path: Path) -> int:
    key = str(path.resolve())
    with _INPROCESS_LOCK_GUARD:
        if key in _INPROCESS_LOCKS:
            raise ConcurrentWriterError(
                f"同一进程内已打开账本 {path}；同一 JSONL 不支持多个写入者"
            )
    lock_file = _lock_path(path)
    fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o644)
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            holder = _read_lock_owner(fd)
            os.close(fd)
            raise ConcurrentWriterError(
                f"账本 {path} 已被其他进程持有写锁（{holder}）：{exc.strerror}"
            ) from exc
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"pid={os.getpid()} wall_time_ns={time.time_ns()}\n".encode())
        os.fsync(fd)
    except OSError:
        # 锁文件内容仅为诊断信息，写失败不影响互斥语义，但要释放 fd。
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        raise
    with _INPROCESS_LOCK_GUARD:
        _INPROCESS_LOCKS.add(key)
    return fd


def _read_lock_owner(fd: int) -> str:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        data = os.read(fd, 256)
    except OSError:
        return "未知持有者"
    text = data.decode("utf-8", "replace").strip()
    return text or "未知持有者"


def _release_writer_lock(path: Path, fd: int) -> None:
    key = str(path.resolve())
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
        with _INPROCESS_LOCK_GUARD:
            _INPROCESS_LOCKS.discard(key)


# --------------------------------------------------------------------------- #
# 已有文件的尾部检查
# --------------------------------------------------------------------------- #


def _last_complete_offset(fd: int, size: int, chunk: int = 1 << 20) -> int:
    """返回最后一个换行符之后的偏移；没有换行时返回 0。"""

    if size == 0:
        return 0
    if os.pread(fd, 1, size - 1) == b"\n":
        return size
    position = size
    while position > 0:
        start = max(0, position - chunk)
        data = os.pread(fd, position - start, start)
        index = data.rfind(b"\n")
        if index >= 0:
            return start + index + 1
        if not data:
            break
        position = start
    return 0


def _count_newlines(fd: int, limit: int, chunk: int = 1 << 20) -> int:
    """统计 ``[0, limit)`` 区间内的换行数。"""

    total = 0
    position = 0
    while position < limit:
        data = os.pread(fd, min(chunk, limit - position), position)
        if not data:
            break
        total += data.count(b"\n")
        position += len(data)
    return total


# --------------------------------------------------------------------------- #
# 写入器
# --------------------------------------------------------------------------- #


class JsonlEventLedger:
    """append-only JSONL 事件账本写入器。

    * 上下文管理器：``with JsonlEventLedger(path) as ledger: ledger.append(...)``。
    * 关闭后任何写入/刷新都抛 :class:`LedgerClosedError`。
    * ``__exit__`` 只负责关闭，不吞异常（返回 ``False``）。
    * 同一路径的第二个写入者抛 :class:`ConcurrentWriterError`。
    * 默认拒绝向"末尾有不完整行"的既有文件追加（``TruncatedLedgerError``）；
      需要修复时显式传 ``truncate_tail=True``。

    ``policy`` 只影响 :meth:`verify` 的**读取**策略（写入总是写入已有内容，
    包括 ``PRESERVE`` 保留的未知字段）；要与写入侧保持一致才能验证成功。
    """

    __slots__ = (
        "_path",
        "_policy",
        "_fsync_policy",
        "_fsync_every_lines",
        "_strict_order",
        "_lock_fd",
        "_fh",
        "_line_no",
        "_offset",
        "_checksum_of_last",
        "_fsyncs",
        "_pending_lines",
        "_out_of_order_lines",
        "_tail_repaired_bytes",
        "_monotonic_seen",
        "_closed",
    )

    def __init__(
        self,
        path: str | Path,
        *,
        fsync_policy: FsyncPolicy | str = FsyncPolicy.BATCH,
        fsync_every_lines: int = DEFAULT_FSYNC_BATCH_LINES,
        strict_order: bool = False,
        truncate_tail: bool = False,
        lock: bool = True,
        policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    ) -> None:
        self._path = Path(path)
        self._policy = UnknownFieldPolicy(policy)
        self._fsync_policy = FsyncPolicy(fsync_policy)
        if (
            isinstance(fsync_every_lines, bool)
            or not isinstance(fsync_every_lines, int)
            or fsync_every_lines < 1
        ):
            raise ValueError("fsync_every_lines 必须是 >= 1 的整数")
        self._fsync_every_lines = fsync_every_lines
        self._strict_order = bool(strict_order)
        self._closed = False

        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_fd: int | None = _acquire_writer_lock(self._path) if lock else None
        try:
            fd = os.open(self._path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o644)
        except OSError:
            if self._lock_fd is not None:
                _release_writer_lock(self._path, self._lock_fd)
                self._lock_fd = None
            raise
        try:
            size = os.fstat(fd).st_size
            complete = _last_complete_offset(fd, size)
            repaired = 0
            if complete != size:
                if not truncate_tail:
                    raise TruncatedLedgerError(
                        f"账本 {self._path} 末尾存在不完整行（{size - complete} 字节）；"
                        "请先用 truncate_tail=True 显式修复，或改用 scan_ledger() 只读恢复"
                    )
                os.ftruncate(fd, complete)
                os.fsync(fd)
                repaired = size - complete
                size = complete
            self._line_no = _count_newlines(fd, size)
            self._offset = size
            self._fh = os.fdopen(fd, "ab", buffering=_BUFFER_BYTES)
        except BaseException:
            os.close(fd)
            if self._lock_fd is not None:
                _release_writer_lock(self._path, self._lock_fd)
                self._lock_fd = None
            raise

        self._checksum_of_last: str | None = None
        self._fsyncs = 0
        self._pending_lines = 0
        self._out_of_order_lines = 0
        self._tail_repaired_bytes = repaired
        self._monotonic_seen: dict[tuple[str, str], int] = {}

    # -- 元信息 ------------------------------------------------------------- #

    @property
    def path(self) -> Path:
        return self._path

    @property
    def policy(self) -> UnknownFieldPolicy:
        return self._policy

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def stats(self) -> LedgerWriteStats:
        return LedgerWriteStats(
            lines_written=self._line_no,
            bytes_written=self._offset,
            fsyncs=self._fsyncs,
            pending_lines=self._pending_lines,
            out_of_order_lines=self._out_of_order_lines,
            tail_repaired_bytes=self._tail_repaired_bytes,
            last_offset=self._offset,
            closed=self._closed,
        )

    # -- 写入 --------------------------------------------------------------- #

    def append(self, event: Event) -> LedgerRecord:
        """追加一条事件，返回其在账本中的定位记录。"""

        record = self._append_no_fsync(event)
        self._maybe_fsync()
        return record

    def append_many(self, events: Iterable[Event]) -> tuple[LedgerRecord, ...]:
        """批量追加。

        单条事件的写入是原子的一行；批量中途失败时已写入的行保持有效
        （账本仍是"每行一个完整事件"），调用方可通过 ``scan_ledger`` 看到实际内容。
        """

        self._ensure_open()
        records = [self._append_no_fsync(event) for event in events]
        self.flush()
        return tuple(records)

    def _append_no_fsync(self, event: Event) -> LedgerRecord:
        self._ensure_open()
        if not isinstance(event, Event):
            raise EventValidationError(
                f"append 需要 Event 实例，实际为 {type(event).__name__}"
            )
        line, checksum, _body_len = build_envelope_line(event)

        stream_key = (event.run_id, str(event.source))
        previous = self._monotonic_seen.get(stream_key)
        if previous is not None and event.monotonic_ns < previous:
            self._out_of_order_lines += 1
            if self._strict_order:
                raise OutOfOrderEventError(
                    f"事件 monotonic_ns={event.monotonic_ns} 早于同一 (run_id, source) "
                    f"的上一条 {previous}；strict_order=True 时拒绝写入"
                )
        else:
            self._monotonic_seen[stream_key] = event.monotonic_ns

        line_no = self._line_no + 1
        offset = self._offset
        try:
            self._fh.write(line)
        except OSError as exc:
            # 写入失败不回滚 offset/line_no：OS 可能已写入部分字节。
            raise LedgerLockError(f"账本 {self._path} 写入失败：{exc}") from exc
        self._line_no = line_no
        self._offset += len(line)
        self._pending_lines += 1
        self._checksum_of_last = checksum
        return LedgerRecord(
            event=event,
            line_no=line_no,
            offset=offset,
            byte_length=len(line),
            checksum=checksum,
        )

    def flush(self, *, fsync: bool | None = None) -> None:
        """把缓冲区推给操作系统；``fsync`` 为 ``None`` 时按策略决定是否落盘。"""

        self._ensure_open()
        self._fh.flush()
        if fsync is None:
            fsync = self._fsync_policy is not FsyncPolicy.NEVER
        if fsync:
            self._fsync_now()

    def sync(self) -> None:
        """强制 ``flush`` + ``os.fsync``。"""

        self.flush(fsync=True)

    def _maybe_fsync(self) -> None:
        if self._fsync_policy is FsyncPolicy.ALWAYS:
            self._fsync_now()
        elif self._fsync_policy is FsyncPolicy.BATCH:
            if self._pending_lines >= self._fsync_every_lines:
                self._fsync_now()

    def _fsync_now(self) -> None:
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fsyncs += 1
        self._pending_lines = 0

    def close(self) -> None:
        """关闭账本（幂等）。非 ``NEVER`` 策略会 fsync 未落盘数据。"""

        if self._closed:
            return
        try:
            if self._fsync_policy is not FsyncPolicy.NEVER:
                self._fsync_now()
            else:
                self._fh.flush()
        finally:
            self._fh.close()
            self._closed = True
            if self._lock_fd is not None:
                _release_writer_lock(self._path, self._lock_fd)
                self._lock_fd = None

    # -- 校验 --------------------------------------------------------------- #

    def verify(self, *, missing_ok: bool = False) -> ScanResult:
        """扫描已写入内容（先 flush 缓冲，不做 fsync）。

        扫描是只读的：不会修改文件，也不会修复任何问题。
        """

        self._ensure_open()
        self._fh.flush()
        return scan_ledger(self._path, policy=self._policy, missing_ok=missing_ok)

    def _ensure_open(self) -> None:
        if self._closed:
            raise LedgerClosedError(
                f"账本 {self._path} 已关闭；关闭后拒绝写入与刷新"
            )

    # -- 上下文管理 --------------------------------------------------------- #

    def __enter__(self) -> JsonlEventLedger:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        """关闭账本；不吞异常（返回 ``False``）。"""

        self.close()
        return False

    def __repr__(self) -> str:  # pragma: no cover - 诊断用
        state = "closed" if self._closed else "open"
        return f"<JsonlEventLedger {self._path} lines={self._line_no} {state}>"

    __str__ = __repr__
