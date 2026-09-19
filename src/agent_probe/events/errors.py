"""事件账本的异常层次。

分层原则：

* :class:`EventValidationError` —— **数据**问题：字段非法、枚举不合法、
  超长、不可序列化。生产者必须修数据，账本不会替它猜。
* :class:`LedgerError` —— **日志**问题：写入/恢复路径上的状态冲突
  （已关闭、并发写入、尾部截断、乱序）。
* :class:`IndexWriteError` / :class:`IndexClosedError` —— **派生索引**问题。
  索引是可重建的派生物，索引失败必须显式抛出，且不得回写或损坏权威 JSONL。

所有异常都继承 :class:`EventLedgerError`，便于调用方一次性捕获。
"""

from __future__ import annotations

__all__ = [
    "EventLedgerError",
    "EventValidationError",
    "EventTooLargeError",
    "UnknownFieldError",
    "LossCounterError",
    "LedgerError",
    "LedgerClosedError",
    "ConcurrentWriterError",
    "TruncatedLedgerError",
    "OutOfOrderEventError",
    "LedgerLockError",
    "IndexWriteError",
    "IndexConflictError",
    "IndexReadError",
    "IndexClosedError",
]


class EventLedgerError(Exception):
    """事件账本相关错误的公共基类。"""


class EventValidationError(EventLedgerError, ValueError):
    """事件数据不满足 schema：字段类型、范围、枚举、长度或可序列化性。"""


class EventTooLargeError(EventValidationError):
    """序列化后的事件超过 ``MAX_EVENT_BYTES``。"""


class UnknownFieldError(EventValidationError):
    """出现未知字段，且当前策略为 ``REJECT``。"""


class LossCounterError(EventLedgerError, ValueError):
    """丢失/数据质量计数器的非法输入（未知分类、负数计数等）。"""


class LedgerError(EventLedgerError):
    """权威 JSONL 日志的读写错误。"""


class LedgerClosedError(LedgerError, RuntimeError):
    """对已关闭的账本写入器继续操作。"""


class LedgerLockError(LedgerError, RuntimeError):
    """无法建立/释放账本写锁。"""


class ConcurrentWriterError(LedgerLockError):
    """同一 JSONL 账本已被另一个写入者持有（跨进程或同进程重复打开）。"""


class TruncatedLedgerError(LedgerError, ValueError):
    """已有账本末尾存在不完整行，直接追加会破坏"每行一个完整事件"的不变式。"""


class OutOfOrderEventError(LedgerError, ValueError):
    """严格顺序模式下写入的事件 ``monotonic_ns`` 早于同一来源流的最后事件。"""


class IndexWriteError(LedgerError, RuntimeError):
    """SQLite 派生索引写入失败；事务已回滚，权威日志不受影响。"""


class IndexConflictError(IndexWriteError):
    """同一 ``event_id`` 对应了**不同内容**（校验值不一致）。

    这不是幂等重复，而是完整性冲突：索引里已有的行、或同一批输入里的另一条
    记录，对同一 ``event_id`` 给出了不同的事件体。可能原因包括 event_id 生成
    重复、上游改写了已落盘的事件、或索引与账本来自不同来源。

    处理方式：不要用"后写覆盖"来绕过冲突——先查数据来源；确实需要以新内容
    为准时，用 ``rebuild(..., reset=True)`` 从权威 JSONL 整批重建索引。
    该异常继承 :class:`IndexWriteError`，抛出时当前批次事务已回滚。
    """


class IndexReadError(LedgerError, RuntimeError):
    """SQLite 派生索引内容损坏（校验值或事件体不可解析）。

    索引是可重建的派生物：遇到该错误应直接删除索引并从 JSONL 重建，
    而不是修补索引。
    """


class IndexClosedError(LedgerError, RuntimeError):
    """对已关闭的索引继续操作。"""
