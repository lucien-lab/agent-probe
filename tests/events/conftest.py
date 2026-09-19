"""``tests/events`` 共享夹具。

设计原则：

* **确定性**：时间来自可注入的 :class:`FrozenClock`，事件 ID 与 run ID 由夹具
  显式生成，测试里不出现 ``time.time()`` 或随机值。
* **无仓库污染**：所有账本/索引路径都在 ``tmp_path`` 下（pytest 内建）。
* **显式期望**：每类事件的样例 payload 在测试侧独立声明，不复用被测代码的
  默认值，避免"用实现验证实现"。
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from agent_probe.events import (
    Event,
    EventResult,
    EventSource,
    EventType,
    canonical_json,
    compute_checksum,
    new_event,
    new_event_id,
    new_run_id,
)

#: 每类事件的最小合法 payload（测试自持，独立于实现内部）。
SAMPLE_PAYLOADS: dict[EventType, dict[str, Any]] = {
    EventType.PROCESS_FORK: {
        "child_pid": 1001,
        "parent_pid": 1000,
        "child_start_id": 555,
    },
    EventType.PROCESS_EXEC: {
        "exe": "/usr/bin/python3",
        "argv": ["python3", "-c", "print(1)"],
        "cwd": "/work",
    },
    EventType.PROCESS_EXIT: {"exit_code": 0},
    EventType.FILE_OPEN: {"path": "/work/a.txt", "flags": 0, "fd": 3},
    EventType.FILE_READ: {
        "fd": 3,
        "path": "/work/a.txt",
        "count": 4096,
        "bytes_read": 12,
    },
    EventType.FILE_WRITE: {
        "fd": 4,
        "path": "/work/b.txt",
        "count": 5,
        "bytes_written": 5,
    },
    EventType.FILE_TRUNCATE: {"path": "/work/a.txt", "length": 0},
    EventType.FILE_RENAME: {"old_path": "/work/a", "new_path": "/work/b"},
    EventType.FILE_UNLINK: {"path": "/work/a", "dir_fd": None},
    EventType.NET_CONNECT: {
        "family": "inet",
        "protocol": "tcp",
        "dest_addr": "127.0.0.1",
        "dest_port": 8443,
        "local_port": 51000,
    },
    EventType.NET_SEND: {
        "family": "inet",
        "protocol": "udp",
        "dest_addr": "8.8.8.8",
        "dest_port": 53,
        "bytes_sent": 42,
    },
    EventType.TLS_BYTES: {
        "direction": "write",
        "bytes": 1024,
        "connection_id": "conn-1",
        "plaintext_included": False,
        "truncated": False,
    },
    EventType.QUALITY_SEQUENCE_GAP: {
        "stream": "ebpf/ring0",
        "expected_seq": 10,
        "received_seq": 13,
        "missing": 3,
    },
    EventType.QUALITY_RING_DROP: {"count": 2, "reason": "ring_full"},
    EventType.QUALITY_QUEUE_DROP: {"count": 1, "reason": "queue_full"},
    EventType.QUALITY_STORAGE_DROP: {"count": 1, "reason": "enospc"},
    EventType.QUALITY_COUNTER_SNAPSHOT: {
        "counters": {"ring_drop": 5, "user_queue_drop": 2}
    },
}


class FrozenClock:
    """确定性时钟：每次读取自增固定步长。"""

    __slots__ = ("_monotonic", "_wall", "_step")

    def __init__(
        self,
        monotonic_ns: int = 1_000_000_000,
        wall_time_ns: int = 1_700_000_000_000_000_000,
        step_ns: int = 1_000_000,
    ) -> None:
        self._monotonic = monotonic_ns
        self._wall = wall_time_ns
        self._step = step_ns

    def monotonic_ns(self) -> int:
        value = self._monotonic
        self._monotonic += self._step
        return value

    def wall_time_ns(self) -> int:
        value = self._wall
        self._wall += self._step
        return value

    def advance(self, ns: int) -> None:
        self._monotonic += ns
        self._wall += ns


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def run_id() -> str:
    return new_run_id()


@pytest.fixture
def other_run_id() -> str:
    return new_run_id()


@pytest.fixture
def event_kwargs(run_id: str) -> dict[str, Any]:
    """一组合法的事件构造参数（可被测试就地覆盖）。"""

    return {
        "schema_version": 1,
        "event_id": new_event_id(),
        "run_id": run_id,
        "source": EventSource.EBPF,
        "event_type": EventType.FILE_OPEN,
        "monotonic_ns": 1_000_000,
        "wall_time": 1_700_000_000_000_000_000,
        "pid": 4242,
        "tid": 4243,
        "result": EventResult.OK,
        "payload": dict(SAMPLE_PAYLOADS[EventType.FILE_OPEN]),
    }


MakeEvent = Callable[..., Event]


@pytest.fixture
def make_event(run_id: str, clock: FrozenClock) -> MakeEvent:
    """构造合法事件；未显式给出的时间来自 :class:`FrozenClock`。"""

    def _make(
        event_type: EventType = EventType.FILE_OPEN,
        *,
        payload: Mapping[str, Any] | None = None,
        result: EventResult | str = EventResult.OK,
        error_code: int | None = None,
        source: EventSource | str = EventSource.EBPF,
        pid: int = 4242,
        tid: int = 4243,
        seq: int | None = None,
        monotonic_ns: int | None = None,
        wall_time: int | None = None,
        event_id: str | None = None,
        process_start_id: int | None = 9001,
        cgroup_id: int | None = None,
        pid_namespace: int | None = None,
        correlation_id: str | None = None,
        run: str | None = None,
    ) -> Event:
        resolved_type = EventType(event_type)
        if payload is None:
            payload = dict(SAMPLE_PAYLOADS[resolved_type])
        if EventResult(result) is EventResult.ERROR and error_code is None:
            error_code = 13
        return new_event(
            run_id=run if run is not None else run_id,
            event_type=resolved_type,
            payload=payload,
            result=result,
            error_code=error_code,
            source=source,
            pid=pid,
            tid=tid,
            seq=seq,
            monotonic_ns=monotonic_ns,
            wall_time=wall_time,
            event_id=event_id,
            process_start_id=process_start_id,
            cgroup_id=cgroup_id,
            pid_namespace=pid_namespace,
            correlation_id=correlation_id,
            clock=clock,
        )

    return _make


RawLine = Callable[..., bytes]


@pytest.fixture
def raw_line() -> RawLine:
    """手工构造账本行，用于伪造校验错/版本不支持等场景。"""

    def _raw(
        event_dict: Mapping[str, Any],
        *,
        envelope_version: int = 1,
        checksum: str | None = None,
        declared_len: int | None = None,
    ) -> bytes:
        body = canonical_json(event_dict).encode("utf-8")
        envelope = {
            "v": envelope_version,
            "len": len(body) if declared_len is None else declared_len,
            "checksum": compute_checksum(body) if checksum is None else checksum,
            "event": event_dict,
        }
        return canonical_json(envelope).encode("utf-8") + b"\n"

    return _raw


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "events.jsonl"


@pytest.fixture
def index_path(tmp_path: Path) -> Path:
    return tmp_path / "events.sqlite"
