"""``agent_probe.events``：M2 可靠事件账本核心（库层，不接入 CLI）。

本子包只提供**库**能力，不注册任何 ``probe`` 子命令，也不包含 eBPF C 探针：

* :mod:`~agent_probe.events.model` —— 版本化事件模型、payload 边界与未知字段策略。
* :mod:`~agent_probe.events.ledger` —— JSONL 权威 append-only 日志（校验值/fsync/恢复）。
* :mod:`~agent_probe.events.index` —— 可删除重建的 SQLite 派生索引与查询。
* :mod:`~agent_probe.events.quality` —— 丢失与数据质量计数、快照。
* :mod:`~agent_probe.events.replay` —— 离线重放与"索引 vs 账本"一致性校验。
* :mod:`~agent_probe.events.errors` —— 异常层次。

根包 ``agent_probe`` 刻意保持只有 ``__version__`` 的骨架导出；语义见
``docs/02-event-ledger.md``。
"""

from __future__ import annotations

from .errors import (
    ConcurrentWriterError,
    EventLedgerError,
    EventTooLargeError,
    EventValidationError,
    IndexClosedError,
    IndexConflictError,
    IndexReadError,
    IndexWriteError,
    LedgerClosedError,
    LedgerError,
    LedgerLockError,
    LossCounterError,
    OutOfOrderEventError,
    TruncatedLedgerError,
    UnknownFieldError,
)
from .index import (
    INDEX_SCHEMA_VERSION,
    IndexBatchResult,
    IndexIntegrityReport,
    SqliteIndex,
)
from .ledger import (
    ENVELOPE_VERSION,
    MAX_LINE_BYTES,
    FsyncPolicy,
    JsonlEventLedger,
    LedgerIssue,
    LedgerRecord,
    LedgerWriteStats,
    ScanResult,
    build_envelope_line,
    compute_checksum,
    iter_events,
    iter_records,
    ledger_digest,
    scan_ledger,
)
from .model import (
    HEADER_FIELDS,
    MAX_ARGV_ITEMS,
    MAX_COUNTER_KEYS,
    MAX_EVENT_BYTES,
    MAX_LIST_ITEMS,
    MAX_PATH_BYTES,
    MAX_PAYLOAD_DEPTH,
    MAX_PID,
    MAX_STRING_BYTES,
    OPTIONAL_HEADER_FIELDS,
    PAYLOAD_SCHEMAS,
    REQUIRED_HEADER_FIELDS,
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    Event,
    EventClock,
    EventResult,
    EventSource,
    EventType,
    FieldSpec,
    SystemClock,
    UnknownFieldPolicy,
    canonical_json,
    event_from_dict,
    event_from_json,
    event_to_bytes,
    event_to_dict,
    event_to_json,
    new_event,
    new_event_id,
    new_run_id,
    payload_required_keys,
    payload_schema,
)
from .quality import (
    LOSS_EVENT_TYPES,
    IssueKind,
    LossCounters,
    LossKind,
    LossSnapshot,
)
from .replay import (
    ConsistencyReport,
    ReplayResult,
    replay,
    replay_into_index,
    scan,
    verify_against_ledger,
)

__all__ = [
    # errors
    "EventLedgerError",
    "EventValidationError",
    "EventTooLargeError",
    "UnknownFieldError",
    "LossCounterError",
    "LedgerError",
    "LedgerClosedError",
    "LedgerLockError",
    "ConcurrentWriterError",
    "TruncatedLedgerError",
    "OutOfOrderEventError",
    "IndexWriteError",
    "IndexConflictError",
    "IndexReadError",
    "IndexClosedError",
    # model
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_VERSIONS",
    "MAX_EVENT_BYTES",
    "MAX_STRING_BYTES",
    "MAX_PATH_BYTES",
    "MAX_LIST_ITEMS",
    "MAX_ARGV_ITEMS",
    "MAX_COUNTER_KEYS",
    "MAX_PAYLOAD_DEPTH",
    "MAX_PID",
    "HEADER_FIELDS",
    "REQUIRED_HEADER_FIELDS",
    "OPTIONAL_HEADER_FIELDS",
    "EventSource",
    "EventType",
    "EventResult",
    "UnknownFieldPolicy",
    "FieldSpec",
    "PAYLOAD_SCHEMAS",
    "payload_schema",
    "payload_required_keys",
    "Event",
    "EventClock",
    "SystemClock",
    "new_event",
    "new_event_id",
    "new_run_id",
    "canonical_json",
    "event_to_dict",
    "event_to_json",
    "event_to_bytes",
    "event_from_dict",
    "event_from_json",
    # ledger
    "ENVELOPE_VERSION",
    "MAX_LINE_BYTES",
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
    # index
    "INDEX_SCHEMA_VERSION",
    "SqliteIndex",
    "IndexBatchResult",
    "IndexIntegrityReport",
    # quality
    "LossKind",
    "IssueKind",
    "LOSS_EVENT_TYPES",
    "LossCounters",
    "LossSnapshot",
    # replay
    "ReplayResult",
    "ConsistencyReport",
    "replay",
    "replay_into_index",
    "scan",
    "verify_against_ledger",
]
