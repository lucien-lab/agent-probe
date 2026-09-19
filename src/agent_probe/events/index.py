"""SQLite **派生的**事件索引（M2 核心）。

定位
----

* JSONL 是权威记录；本模块只保存**派生物**：可从 JSONL 删除后完整重建。
* 写入以事务批量提交（``BEGIN IMMEDIATE`` + 单次 ``COMMIT``），失败即整体回滚，
  且绝不回写、截断或修补 JSONL——索引坏了删掉重建即可。
* **幂等的定义是"同 ID 同内容"**：只有 ``event_id`` 与规范化事件校验值都相同时
  才计为幂等重复（``ON CONFLICT(event_id) DO NOTHING``）；同 ``event_id``
  但内容不同属于**完整性冲突**，抛 :class:`~agent_probe.events.errors.IndexConflictError`
  并回滚整批，绝不静默保留旧内容或让新内容覆盖旧内容。
  因此"重放两次"与"重放一次"结果一致，而"改了已写入的事件"必须显式暴露。
* 每行保存规范化事件 JSON（``event_json``）与其校验值（``event_checksum``）。
  查询时按 ``PRESERVE`` 策略重新校验并重建 :class:`~agent_probe.events.model.Event`，
  这样未知字段也能原样回放，同时已知字段仍会被严格校验。

列只用于查询；**语义判定一律回到 ``event_json``**，避免索引列成为第二套真值。
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .errors import (
    EventValidationError,
    IndexClosedError,
    IndexConflictError,
    IndexReadError,
    IndexWriteError,
)
from .ledger import LedgerRecord, compute_checksum
from .model import (
    Event,
    EventResult,
    EventSource,
    EventType,
    UnknownFieldPolicy,
    event_from_json,
    event_to_bytes,
    event_to_json,
)

__all__ = [
    "INDEX_SCHEMA_VERSION",
    "SqliteIndex",
    "IndexBatchResult",
    "IndexIntegrityReport",
    "IndexConflictError",
]
#: 索引表结构版本；与事件 ``schema_version`` 独立。结构变更时递增并重建。
INDEX_SCHEMA_VERSION: Final[int] = 1

_INSERT_SQL: Final[str] = """
INSERT INTO events (
    event_id, run_id, source, event_type, monotonic_ns, wall_time, pid, tid,
    process_start_id, cgroup_id, pid_namespace, result, seq, error_code,
    correlation_id, event_json, event_checksum, ledger_line, ledger_offset
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(event_id) DO NOTHING
"""

#: 权威顺序：优先账本行号，其次插入顺序。
_ORDER_SQL: Final[str] = "ORDER BY (ledger_line IS NULL) ASC, ledger_line ASC, id ASC"

#: ``IN (...)`` 查询分片大小（避免触及 SQLite 变量数上限）。
_SQL_VARIABLE_CHUNK: Final[int] = 500

#: 冲突错误信息里最多展示多少个 event_id。
_MAX_CONFLICT_DETAILS: Final[int] = 3


@dataclass(frozen=True, slots=True)
class IndexBatchResult:
    """一次索引写入的结果。"""

    submitted: int
    inserted: int
    duplicates: int
    reset: bool
    deleted: int = 0

    @property
    def unchanged(self) -> bool:
        return self.inserted == 0


@dataclass(frozen=True, slots=True)
class IndexIntegrityReport:
    """索引自检结果（不涉及 JSONL）。"""

    rows: int
    bad_event_ids: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.bad_event_ids


@dataclass(frozen=True, slots=True)
class _PendingRow:
    """待写入行：将幂等键（``event_id`` + 校验值）与列值放在一起，避免下标魔法。"""

    event_id: str
    checksum: str
    values: tuple[Any, ...]


def _conflict_message(conflicts: Sequence[tuple[str, str, str]]) -> str:
    """拼接可诊断的冲突描述：``(event_id, 已存校验值, 本次校验值)``。"""

    shown = conflicts[:_MAX_CONFLICT_DETAILS]
    details = "; ".join(
        f"{event_id}(已存={stored}, 本次={incoming})"
        for event_id, stored, incoming in shown
    )
    remainder = ""
    if len(conflicts) > _MAX_CONFLICT_DETAILS:
        remainder = f"，另有 {len(conflicts) - _MAX_CONFLICT_DETAILS} 处"
    return (
        f"索引完整性冲突：{len(conflicts)} 个 event_id 对应了不同内容{remainder}："
        f"{details}；仅当 event_id 与事件校验值都一致时才计为幂等重复，"
        "否则请检查数据来源，必要时从权威 JSONL 重建索引"
    )


def _index_digest(rows: Iterable[tuple[str, str]]) -> str:
    """索引摘要：与 :func:`~agent_probe.events.ledger.ledger_digest` 同一规则。"""

    hasher = hashlib.sha256()
    for event_id, checksum in rows:
        hasher.update(f"{event_id}:{checksum}\n".encode("utf-8"))
    return f"sha256:{hasher.hexdigest()}"


class SqliteIndex:
    """可重建的 SQLite 事件索引。

    * 上下文管理器：``with SqliteIndex("runs/idx.sqlite") as index: ...``
    * 关闭后任何操作抛 :class:`IndexClosedError`。
    * ``read_only=True``（或只读 URI）时拒绝写入。
    * ``path=":memory:"`` 支持内存索引（测试与临时分析）。
    """

    __slots__ = ("_path", "_conn", "_read_only", "_closed")

    def __init__(
        self,
        path: str | Path,
        *,
        create: bool = True,
        read_only: bool = False,
    ) -> None:
        self._path = str(path)
        self._read_only = bool(read_only)
        self._closed = False
        memory = self._path == ":memory:"
        if not memory and not self._read_only and not create and not Path(self._path).exists():
            # 先检查再连接：避免 create=False 时在磁盘上留下空库文件。
            raise IndexWriteError(f"索引 {self._path} 不存在，且 create=False")

        try:
            if self._read_only:
                self._conn = sqlite3.connect(
                    f"file:{self._path}?mode=ro", uri=True, isolation_level=None
                )
            elif memory:
                self._conn = sqlite3.connect(":memory:", isolation_level=None)
            else:
                Path(self._path).parent.mkdir(parents=True, exist_ok=True)
                self._conn = sqlite3.connect(self._path, isolation_level=None)
        except sqlite3.Error as exc:
            raise IndexWriteError(f"无法打开索引 {self._path}：{exc}") from exc

        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout = 5000")
        if not self._read_only:
            # 索引是可重建的派生物：WAL + NORMAL 在"可丢最后若干事务但文件不损坏"
            # 与吞吐之间取平衡；权威日志的 fsync 语义不受影响（见 ledger.py）。
            if not memory:
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
        try:
            self._ensure_schema(create=create)
        except BaseException:
            self._conn.close()
            self._closed = True
            raise

    # -- 元信息 ------------------------------------------------------------- #

    @property
    def path(self) -> str:
        return self._path

    @property
    def read_only(self) -> bool:
        return self._read_only

    @property
    def closed(self) -> bool:
        return self._closed

    # -- schema ------------------------------------------------------------- #

    def _ensure_schema(self, *, create: bool) -> None:
        if self._read_only:
            exists = self._table_exists("events")
            if not exists:
                raise IndexWriteError(
                    f"只读索引 {self._path} 缺少 events 表（索引不存在或已损坏）"
                )
            return
        if not create and not self._table_exists("events"):
            raise IndexWriteError(f"索引 {self._path} 不存在，且 create=False")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS index_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                run_id TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                monotonic_ns INTEGER NOT NULL,
                wall_time INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                tid INTEGER NOT NULL,
                process_start_id INTEGER,
                cgroup_id INTEGER,
                pid_namespace INTEGER,
                result TEXT NOT NULL,
                seq INTEGER,
                error_code INTEGER,
                correlation_id TEXT,
                event_json TEXT NOT NULL,
                event_checksum TEXT NOT NULL,
                ledger_line INTEGER,
                ledger_offset INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_events_run
                ON events(run_id, monotonic_ns);
            CREATE INDEX IF NOT EXISTS idx_events_wall_time
                ON events(wall_time);
            CREATE INDEX IF NOT EXISTS idx_events_process
                ON events(pid, process_start_id);
            CREATE INDEX IF NOT EXISTS idx_events_type
                ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_ledger
                ON events(ledger_line);
            """
        )
        self._conn.execute(
            "INSERT INTO index_meta(key, value) VALUES('index_schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(INDEX_SCHEMA_VERSION),),
        )

    def _table_exists(self, name: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
        ).fetchone()
        return row is not None

    # -- 写入 --------------------------------------------------------------- #

    def index_events(
        self,
        events: Iterable[Event],
        *,
        reset: bool = False,
    ) -> IndexBatchResult:
        """索引一批裸事件（无账本定位信息）。"""

        return self.index_records(events, reset=reset)

    def index_records(
        self,
        items: Iterable[Event | LedgerRecord],
        *,
        reset: bool = False,
    ) -> IndexBatchResult:
        """事务批量写入。

        ``items`` 可混用 :class:`Event` 与 :class:`LedgerRecord`；
        后者会带上 ``ledger_line``/``ledger_offset`` 以便回溯权威日志。
        ``reset=True`` 时在同一事务内先清空再写入，因此重建是原子的。

        幂等键是 ``(event_id, 事件校验值)``：

        * 完全相同的重复（含同一批内的重复）→ 只写一次，计入 ``duplicates``；
        * 同 ``event_id`` 但校验值不同（与库内已有行，或同一批内两条互不一致）
          → 抛 :class:`IndexConflictError` 并回滚整批，不静默保留任一版本。

        ``reset=True`` 时先清空再检查冲突：重建本就是"以这批输入为准"，
        不会因库里旧内容不同而失败，但仍会拦截**批内**自相矛盾。
        """

        self._ensure_open()
        if self._read_only:
            raise IndexWriteError(f"只读索引 {self._path} 拒绝写入")

        pending = [self._build_pending(item) for item in self._normalize(items)]
        if not pending:
            deleted = 0
            if reset:

                def _clear() -> int:
                    before = self._conn.total_changes
                    self._conn.execute("DELETE FROM events")
                    return self._conn.total_changes - before

                deleted = self._transaction(_clear)
            return IndexBatchResult(
                submitted=0, inserted=0, duplicates=0, reset=reset, deleted=deleted
            )

        def _work() -> tuple[int, int]:
            deleted = 0
            if reset:
                deleted = self._conn.total_changes
                self._conn.execute("DELETE FROM events")
                deleted = self._conn.total_changes - deleted
            # 写入前的冲突检测与插入处于同一事务内：抛异常即整批回滚。
            self._reject_conflicts(pending)
            before = self._conn.total_changes
            self._conn.executemany(_INSERT_SQL, [item.values for item in pending])
            return self._conn.total_changes - before, deleted

        inserted, deleted = self._transaction(_work)
        return IndexBatchResult(
            submitted=len(pending),
            inserted=inserted,
            duplicates=len(pending) - inserted,
            reset=reset,
            deleted=deleted,
        )

    def _reject_conflicts(self, pending: Sequence[_PendingRow]) -> None:
        """写入前拒绝"同 event_id 不同内容"，否则抛 :class:`IndexConflictError`。

        两类冲突都要检测：

        1. **批内冲突**：同一批里同一个 ``event_id`` 出现多次且校验值不一致；
        2. **库内冲突**：与已有行的校验值不一致。

        调用方已开启事务，抛出的异常会被 ``_transaction`` 回滚。
        """

        first_seen: dict[str, str] = {}
        conflicts: list[tuple[str, str, str]] = []
        for item in pending:
            previous = first_seen.get(item.event_id)
            if previous is None:
                first_seen[item.event_id] = item.checksum
            elif previous != item.checksum:
                conflicts.append((item.event_id, previous, item.checksum))

        stored = self._existing_checksums(list(first_seen))
        for event_id, checksum in first_seen.items():
            existing = stored.get(event_id)
            if existing is not None and existing != checksum:
                conflicts.append((event_id, existing, checksum))

        if conflicts:
            raise IndexConflictError(_conflict_message(conflicts))

    def _existing_checksums(self, event_ids: Sequence[str]) -> dict[str, str]:
        """查询这批 ``event_id`` 在库内已存的校验值（分片避免变量数上限）。"""

        found: dict[str, str] = {}
        for start in range(0, len(event_ids), _SQL_VARIABLE_CHUNK):
            chunk = list(event_ids[start : start + _SQL_VARIABLE_CHUNK])
            placeholders = ", ".join("?" for _ in chunk)
            rows = self._conn.execute(
                f"SELECT event_id, event_checksum FROM events "
                f"WHERE event_id IN ({placeholders})",
                chunk,
            ).fetchall()
            for row in rows:
                found[row["event_id"]] = row["event_checksum"]
        return found

    def rebuild(
        self,
        items: Iterable[Event | LedgerRecord],
        *,
        reset: bool = True,
    ) -> IndexBatchResult:
        """从权威日志内容重建索引（默认先清空）。幂等：重复重建结果一致。"""

        return self.index_records(items, reset=reset)

    def _transaction(self, work: Any) -> Any:
        conn = self._conn
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise IndexWriteError(f"无法开启事务：{exc}") from exc
        try:
            result = work()
        except sqlite3.Error as exc:
            conn.rollback()
            raise IndexWriteError(f"索引写入失败，已回滚：{exc}") from exc
        except BaseException:
            conn.rollback()
            raise
        try:
            conn.commit()
        except sqlite3.Error as exc:  # pragma: no cover - 提交失败难以稳定构造
            conn.rollback()
            raise IndexWriteError(f"索引提交失败，已回滚：{exc}") from exc
        return result

    @staticmethod
    def _normalize(items: Iterable[Event | LedgerRecord]) -> list[Event | LedgerRecord]:
        return list(items)

    @staticmethod
    def _build_pending(item: Event | LedgerRecord) -> _PendingRow:
        if isinstance(item, LedgerRecord):
            event = item.event
            ledger_line: int | None = item.line_no
            ledger_offset: int | None = item.offset
        elif isinstance(item, Event):
            event = item
            ledger_line = None
            ledger_offset = None
        else:
            raise TypeError(
                f"索引只接受 Event 或 LedgerRecord，实际为 {type(item).__name__}"
            )

        event_json = event_to_json(event)
        checksum = compute_checksum(event_to_bytes(event))
        values = (
            event.event_id,
            event.run_id,
            str(event.source),
            str(event.event_type),
            event.monotonic_ns,
            event.wall_time,
            event.pid,
            event.tid,
            event.process_start_id,
            event.cgroup_id,
            event.pid_namespace,
            str(event.result),
            event.seq,
            event.error_code,
            event.correlation_id,
            event_json,
            checksum,
            ledger_line,
            ledger_offset,
        )
        return _PendingRow(
            event_id=event.event_id, checksum=checksum, values=values
        )

    # -- 查询 --------------------------------------------------------------- #

    def query(
        self,
        *,
        run_id: str | None = None,
        event_types: Sequence[EventType | str] | None = None,
        source: EventSource | str | None = None,
        pid: int | None = None,
        process_start_id: int | None = None,
        result: EventResult | str | None = None,
        since_ns: int | None = None,
        until_ns: int | None = None,
        time_field: str = "monotonic_ns",
        limit: int | None = None,
        offset: int = 0,
        verify_checksums: bool = False,
    ) -> tuple[Event, ...]:
        """按 run/时间/进程/类型组合查询，返回按权威顺序排列的事件。

        ``time_field`` 可选 ``monotonic_ns``（默认）或 ``wall_time``；
        两者的适用边界见 ``docs/02-event-ledger.md``。
        """

        self._ensure_open()
        clauses, params = self._build_filters(
            run_id=run_id,
            event_types=event_types,
            source=source,
            pid=pid,
            process_start_id=process_start_id,
            result=result,
            since_ns=since_ns,
            until_ns=until_ns,
            time_field=time_field,
        )
        if limit is not None and (isinstance(limit, bool) or limit < 1):
            raise ValueError(f"limit 必须是 >= 1 的整数或 None，实际为 {limit!r}")
        if isinstance(offset, bool) or offset < 0:
            raise ValueError(f"offset 必须是非负整数，实际为 {offset!r}")

        sql = "SELECT event_json, event_checksum, event_id FROM events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " " + _ORDER_SQL
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
            if offset:
                sql += " OFFSET ?"
                params.append(offset)
        elif offset:
            sql += " LIMIT -1 OFFSET ?"
            params.append(offset)

        try:
            cursor = self._conn.execute(sql, list(params))
            rows = cursor.fetchall()
        except sqlite3.Error as exc:
            raise IndexReadError(f"索引查询失败：{exc}") from exc
        return tuple(
            self._row_to_event(row, verify_checksum=verify_checksums) for row in rows
        )

    def _build_filters(
        self,
        *,
        run_id: str | None = None,
        event_types: Sequence[EventType | str] | None = None,
        source: EventSource | str | None = None,
        pid: int | None = None,
        process_start_id: int | None = None,
        result: EventResult | str | None = None,
        since_ns: int | None = None,
        until_ns: int | None = None,
        time_field: str = "monotonic_ns",
    ) -> tuple[list[str], list[Any]]:
        """把查询参数展开为 WHERE 子句与参数（不执行查询）。"""

        if time_field not in ("monotonic_ns", "wall_time"):
            raise ValueError(
                f"time_field 必须是 'monotonic_ns' 或 'wall_time'，实际为 {time_field!r}"
            )
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if event_types is not None:
            values = [str(EventType(item)) for item in event_types]
            if values:
                placeholders = ", ".join("?" for _ in values)
                clauses.append(f"event_type IN ({placeholders})")
                params.extend(values)
            else:
                clauses.append("0")
        if source is not None:
            clauses.append("source = ?")
            params.append(str(EventSource(source)))
        if pid is not None:
            clauses.append("pid = ?")
            params.append(pid)
        if process_start_id is not None:
            clauses.append("process_start_id = ?")
            params.append(process_start_id)
        if result is not None:
            clauses.append("result = ?")
            params.append(str(EventResult(result)))
        if since_ns is not None:
            clauses.append(f"{time_field} >= ?")
            params.append(since_ns)
        if until_ns is not None:
            clauses.append(f"{time_field} <= ?")
            params.append(until_ns)
        return clauses, params

    def events_for_run(self, run_id: str, **kwargs: Any) -> tuple[Event, ...]:
        return self.query(run_id=run_id, **kwargs)

    def events_in_time_range(
        self,
        since_ns: int,
        until_ns: int,
        *,
        time_field: str = "monotonic_ns",
        **kwargs: Any,
    ) -> tuple[Event, ...]:
        return self.query(
            since_ns=since_ns, until_ns=until_ns, time_field=time_field, **kwargs
        )

    def events_for_process(
        self,
        pid: int,
        process_start_id: int | None = None,
        **kwargs: Any,
    ) -> tuple[Event, ...]:
        return self.query(pid=pid, process_start_id=process_start_id, **kwargs)

    def events_of_type(
        self, event_type: EventType | str, **kwargs: Any
    ) -> tuple[Event, ...]:
        return self.query(event_types=[event_type], **kwargs)

    def count(self, **filters: Any) -> int:
        """返回满足过滤条件的行数（过滤条件与 :meth:`query` 相同）。"""

        self._ensure_open()
        if not filters:
            try:
                row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
            except sqlite3.Error as exc:
                raise IndexReadError(f"索引计数失败：{exc}") from exc
            return int(row["n"])
        clauses, params = self._build_filters(**filters)
        sql = "SELECT COUNT(*) AS n FROM events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        try:
            row = self._conn.execute(sql, list(params)).fetchone()
        except sqlite3.Error as exc:
            raise IndexReadError(f"索引计数失败：{exc}") from exc
        return int(row["n"])

    def meta(self) -> Mapping[str, str]:
        """读取索引元数据（供诊断与测试使用）。"""

        self._ensure_open()
        rows = self._conn.execute("SELECT key, value FROM index_meta").fetchall()
        return {row["key"]: row["value"] for row in rows}

    def _row_to_event(self, row: sqlite3.Row, *, verify_checksum: bool) -> Event:
        event_json = row["event_json"]
        if verify_checksum:
            actual = compute_checksum(event_json.encode("utf-8"))
            if actual != row["event_checksum"]:
                raise IndexReadError(
                    f"索引行 {row['event_id']} 的校验值不匹配"
                    f"（存 {row['event_checksum']!r}，实际 {actual!r}）；"
                    "请删除索引并从 JSONL 重建"
                )
        try:
            return event_from_json(event_json, policy=UnknownFieldPolicy.PRESERVE)
        except EventValidationError as exc:
            raise IndexReadError(
                f"索引行 {row['event_id']} 无法重建为事件：{exc}；"
                "请删除索引并从 JSONL 重建"
            ) from exc

    def verify_integrity(self) -> IndexIntegrityReport:
        """逐行自检 ``event_json`` 与校验值，返回坏行 ID。"""

        self._ensure_open()
        bad: list[str] = []
        rows = 0
        try:
            cursor = self._conn.execute(
                "SELECT event_id, event_json, event_checksum FROM events"
            )
            for row in cursor:
                rows += 1
                actual = compute_checksum(row["event_json"].encode("utf-8"))
                if actual != row["event_checksum"]:
                    bad.append(row["event_id"])
                    continue
                try:
                    event_from_json(row["event_json"], policy=UnknownFieldPolicy.PRESERVE)
                except EventValidationError:
                    bad.append(row["event_id"])
        except sqlite3.Error as exc:
            raise IndexReadError(f"索引自检失败：{exc}") from exc
        return IndexIntegrityReport(rows=rows, bad_event_ids=tuple(bad))

    def digest(self) -> str:
        """索引内容摘要（按权威顺序），用于与 ``ledger_digest`` 对比。

        摘要基于每行实际的 ``event_json`` **重新计算**校验值：这样任何对索引
        内容的篡改（包括只改 ``event_json`` 而保留旧校验值列）都会导致与权威
        日志不一致，而不是让摘要"恰好相同"。
        """

        self._ensure_open()
        try:
            rows = self._conn.execute(
                f"SELECT event_id, event_json FROM events {_ORDER_SQL}"
            ).fetchall()
        except sqlite3.Error as exc:
            raise IndexReadError(f"索引摘要失败：{exc}") from exc
        return _index_digest(
            (row["event_id"], compute_checksum(row["event_json"].encode("utf-8")))
            for row in rows
        )

    def stored_checksums(self) -> tuple[tuple[str, str], ...]:
        """返回 ``(event_id, 存储的 event_checksum)`` 序列（诊断用）。

        与 :meth:`digest` 不同，这里不做重新计算：若两者不一致，说明索引行
        被外部修改过，应用 :meth:`verify_integrity` 定位。
        """

        self._ensure_open()
        rows = self._conn.execute(
            f"SELECT event_id, event_checksum FROM events {_ORDER_SQL}"
        ).fetchall()
        return tuple((row["event_id"], row["event_checksum"]) for row in rows)

    # -- 生命周期 ----------------------------------------------------------- #

    def _ensure_open(self) -> None:
        if self._closed:
            raise IndexClosedError(f"索引 {self._path} 已关闭；请重新打开")

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._conn.close()
        finally:
            self._closed = True

    def __enter__(self) -> SqliteIndex:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self.close()
        return False

    def __repr__(self) -> str:  # pragma: no cover - 诊断用
        state = "closed" if self._closed else "open"
        mode = "ro" if self._read_only else "rw"
        return f"<SqliteIndex {self._path} {mode} {state}>"

    __str__ = __repr__


def index_meta(index: SqliteIndex) -> Mapping[str, str]:
    """读取索引元数据（模块级便捷函数，等价于 ``index.meta()``）。"""

    return index.meta()
