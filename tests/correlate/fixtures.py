"""``tests/correlate`` 的共享测试夹具与场景构造器（供测试与 conftest 复用）。

原则（与 ``tests/events``/``tests/llm`` 一致）：

* **确定性**：事件 ID、run ID、时钟全部显式给出，测试里不出现 ``time.time()``、
  随机数或依赖输入顺序的断言。
* **测试自持期望**：payload 由测试侧独立声明，不复用被测代码的默认值。
* **无外部依赖**：不联网、不调用 Docker（容器解析器是测试自己的 fake）、
  不写仓库文件（需要时用 ``tmp_path``）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_probe.correlate import AssistantMarkers, Task
from agent_probe.events import (
    Event,
    EventResult,
    EventSource,
    EventType,
    new_event,
)
from agent_probe.llm import CallIdentity, HttpRequest, LlmCallRecord
from agent_probe.llm.common import BodyFraming, MessageKind

#: 两个独立的 probe run（任务）标识。
RUN_A = "11111111-1111-4111-8111-111111111111"
RUN_B = "22222222-2222-4222-8222-222222222222"

#: 任务窗口起点（单调时钟纳秒）。
T0 = 1_000_000_000

#: 任务窗口长度。
TASK_SPAN = 500_000_000

#: 事件 wall_time 与 monotonic_ns 之间的固定偏移（模拟同一 boot）。
WALL_OFFSET = 1_700_000_000_000_000_000

#: 并发场景的调用/工具时间线（相对 T0）。
#: ``CALL_STRIDE`` 大于连接活动区间长度，保证"不同连接"的调用时间窗互不重叠；
#: "同一连接"时所有调用共享同一个活动区间 —— 这正是外部模式无法区分的根源。
CALL_STRIDE = 300_000
CALL_REQUEST_OFFSET = 1_000_000
CALL_RESPONSE_OFFSET = 1_100_000
TOOL_OFFSET = 1_150_000
#: 用于"不同连接"场景的小时间窗（60µs）：只容得下"紧跟自己响应"的那次调用。
TIGHT_TIME_WINDOW_NS = 60_000

#: 主进程身份。
PID = 1000
TID = 1000
PROC_START = 555
#: 子进程身份（fork 产生的进程）。
CHILD_PID = 1001
CHILD_START = 777


def event_id(n: int) -> str:
    """规范化 UUID，便于在断言里读数。"""

    return f"00000000-0000-4000-8000-{n:012d}"


# --------------------------------------------------------------------------- #
# payload 构造器（测试自持，不复用实现内部数据）
# --------------------------------------------------------------------------- #


def payload_process_fork(
    *, child_pid: int = CHILD_PID, parent_pid: int = PID, child_start_id: int | None = CHILD_START
) -> dict[str, Any]:
    data: dict[str, Any] = {"child_pid": child_pid, "parent_pid": parent_pid}
    if child_start_id is not None:
        data["child_start_id"] = child_start_id
    return data


def payload_process_exec(exe: str = "/usr/bin/python3") -> dict[str, Any]:
    return {"exe": exe, "argv": [exe, "-m", "agent"], "cwd": "/work"}


def payload_process_exit(exit_code: int = 0) -> dict[str, Any]:
    return {"exit_code": exit_code}


def payload_tls(
    connection_id: str = "conn-1", *, direction: str = "write", byte_count: int = 128
) -> dict[str, Any]:
    return {
        "direction": direction,
        "bytes": byte_count,
        "connection_id": connection_id,
        "plaintext_included": False,
        "truncated": False,
    }


def payload_net_connect(addr: str = "203.0.113.10", port: int = 443) -> dict[str, Any]:
    return {
        "family": "inet",
        "protocol": "tcp",
        "dest_addr": addr,
        "dest_port": port,
        "local_port": 51000,
    }


def payload_file_open(path: str = "/work/a.txt") -> dict[str, Any]:
    return {"path": path, "flags": 0, "fd": 3}


def payload_file_write(path: str = "/work/a.txt", *, written: int = 5) -> dict[str, Any]:
    return {"fd": 3, "path": path, "count": written, "bytes_written": written}


def payload_file_read(path: str = "/work/a.txt", *, read: int = 12) -> dict[str, Any]:
    return {"fd": 3, "path": path, "count": 4096, "bytes_read": read}


def payload_file_rename(old: str = "/work/a", new: str = "/work/b") -> dict[str, Any]:
    return {"old_path": old, "new_path": new}


def payload_file_unlink(path: str = "/work/a") -> dict[str, Any]:
    return {"path": path, "dir_fd": None}


def payload_quality_counter() -> dict[str, Any]:
    return {"counters": {"ring_drop": 3}}


# --------------------------------------------------------------------------- #
# 事件 / 调用构造器
# --------------------------------------------------------------------------- #


def make_event(
    n: int,
    event_type: EventType,
    payload: dict[str, Any],
    *,
    monotonic_ns: int,
    run_id: str = RUN_A,
    pid: int = PID,
    tid: int = TID,
    process_start_id: int | None = PROC_START,
    cgroup_id: int | None = None,
    result: EventResult = EventResult.OK,
    error_code: int | None = None,
    correlation_id: str | None = None,
    wall_time: int | None = None,
) -> Event:
    """构造一条确定性事件；``wall_time`` 显式给出时才使用（默认同 boot 偏移）。"""

    resolved_wall = monotonic_ns + WALL_OFFSET if wall_time is None else wall_time
    return new_event(
        run_id=run_id,
        event_type=event_type,
        payload=payload,
        pid=pid,
        tid=tid,
        process_start_id=process_start_id,
        monotonic_ns=monotonic_ns,
        wall_time=resolved_wall,
        cgroup_id=cgroup_id,
        result=result,
        error_code=error_code,
        correlation_id=correlation_id,
        event_id=event_id(n),
        source=EventSource.SYNTHETIC,
    )


def make_request(index: int = 0, *, target: str = "/v1/messages") -> HttpRequest:
    return HttpRequest(
        kind=MessageKind.REQUEST,
        version="HTTP/1.1",
        message_index=index,
        headers=(("host", "api.example.test"),),
        redacted_header_names=(),
        body_framing=BodyFraming.CONTENT_LENGTH,
        content_length=12,
        transfer_encoding=None,
        content_encoding=None,
        connection_close=False,
        complete=True,
        incomplete_reason=None,
        body_bytes=12,
        payload=None,
        payload_decoded=True,
        payload_truncated=False,
        stream_start_offset=0,
        stream_end_offset=12,
        method="POST",
        target=target,
    )


def make_call(
    physical_request_id: str,
    connection_id: str = "conn-1",
    *,
    index: int = 0,
    logical_call_id: str | None = None,
) -> LlmCallRecord:
    """只带请求的最小调用记录（响应/usage/费用都缺省，避免测到别的层）。"""

    return LlmCallRecord(
        identity=CallIdentity(
            physical_request_id=physical_request_id,
            logical_call_id=logical_call_id or physical_request_id,
        ),
        connection_id=connection_id,
        request=make_request(index),
    )


def make_task(
    *,
    run_id: str = RUN_A,
    label: str = "task-a",
    process_start_ids: frozenset[int] | None = None,
    cgroup_id: int | None = None,
    started_monotonic_ns: int = T0,
    ended_monotonic_ns: int | None = T0 + TASK_SPAN,
    labels: dict[str, str] | None = None,
) -> Task:
    return Task(
        run_id=run_id,
        label=label,
        cgroup_id=cgroup_id,
        process_start_ids=(
            frozenset({PROC_START}) if process_start_ids is None else process_start_ids
        ),
        started_monotonic_ns=started_monotonic_ns,
        ended_monotonic_ns=ended_monotonic_ns,
        labels={} if labels is None else labels,
    )


# --------------------------------------------------------------------------- #
# 容器解析器 fake
# --------------------------------------------------------------------------- #


@dataclass
class FakeContainerResolver:
    """可注入的容器解析器 fake：只回答预先登记过的容器 ID。

    ``queries`` 记录被问过的容器 ID，用于验证"只按要求查询、不瞎猜"。
    """

    host_pids: dict[str, int] = field(default_factory=dict)
    cgroup_ids: dict[str, int] = field(default_factory=dict)
    queries: list[tuple[str, str]] = field(default_factory=list)

    def resolve_host_pid(self, container_id: str) -> int | None:
        self.queries.append(("host_pid", container_id))
        return self.host_pids.get(container_id)

    def resolve_cgroup_id(self, container_id: str) -> int | None:
        self.queries.append(("cgroup_id", container_id))
        return self.cgroup_ids.get(container_id)


# --------------------------------------------------------------------------- #
# 场景夹具
# --------------------------------------------------------------------------- #


def serial_scenario() -> tuple[tuple[Event, ...], tuple[LlmCallRecord, ...], tuple[Task, ...]]:
    """串行任务：一个任务、一个进程、若干 file/net/llm 事件。

    时间线（monotonic_ns，T0 = 1e9）：

    * ``T0+1ms``  ``process.exec``
    * ``T0+2ms``  ``net.connect``
    * ``T0+3ms``  ``tls.bytes``（请求写入，conn-1）
    * ``T0+10ms`` ``file.open`` / ``T0+11ms`` ``file.write`` / ``T0+12ms`` ``file.read``（同一路径）
    * ``T0+30ms`` ``tls.bytes``（响应读取，conn-1）
    """

    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(2, EventType.NET_CONNECT, payload_net_connect(), monotonic_ns=T0 + 2_000_000),
        make_event(3, EventType.TLS_BYTES, payload_tls(), monotonic_ns=T0 + 3_000_000),
        make_event(4, EventType.FILE_OPEN, payload_file_open(), monotonic_ns=T0 + 10_000_000),
        make_event(5, EventType.FILE_WRITE, payload_file_write(), monotonic_ns=T0 + 11_000_000),
        make_event(6, EventType.FILE_READ, payload_file_read(), monotonic_ns=T0 + 12_000_000),
        make_event(
            7,
            EventType.TLS_BYTES,
            payload_tls(direction="read", byte_count=256),
            monotonic_ns=T0 + 30_000_000,
        ),
    )
    calls = (make_call("req-1", "conn-1"),)
    tasks = (make_task(),)
    return events, calls, tasks


def concurrent_scenario(
    ways: int,
    *,
    shared_connection: bool = True,
    marker_times: bool = True,
    declared_pid: int = PID,
    declared_start: int | None = PROC_START,
    declaration_limit: int | None = None,
) -> tuple[
    tuple[Event, ...],
    tuple[LlmCallRecord, ...],
    tuple[Task, ...],
    AssistantMarkers | None,
]:
    """同进程 ``ways`` 路并发交错：连接（默认复用）与工具执行交错。

    每个调用有自己的请求/响应 ``tls.bytes``；每个工具紧随自己那次调用的响应之后
    写一个文件。默认所有调用共用 ``conn-1``（连接复用）→ 所有调用共享同一个活动
    区间，这是"外部模式无法区分是哪次调用"的根源；``shared_connection=False``
    时每次调用独占一条连接，配合 :data:`TIGHT_TIME_WINDOW_NS` 就能唯一归因（但
    仍只是 ``PROBABLE``：时间接近不构成确定性证据）。
    """

    events: list[Event] = [
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000)
    ]
    calls: list[LlmCallRecord] = []
    next_id = 10
    for index in range(ways):
        connection = "conn-1" if shared_connection else f"conn-{index}"
        events.append(
            make_event(
                next_id,
                EventType.TLS_BYTES,
                payload_tls(connection),
                monotonic_ns=T0 + CALL_REQUEST_OFFSET + index * CALL_STRIDE,
            )
        )
        next_id += 1
    for index in range(ways):
        connection = "conn-1" if shared_connection else f"conn-{index}"
        events.append(
            make_event(
                next_id,
                EventType.TLS_BYTES,
                payload_tls(connection, direction="read", byte_count=256),
                monotonic_ns=T0 + CALL_RESPONSE_OFFSET + index * CALL_STRIDE,
            )
        )
        next_id += 1
        calls.append(make_call(f"req-{index}", connection, index=index))
    tool_offsets: list[int] = []
    for index in range(ways):
        offset = TOOL_OFFSET + index * CALL_STRIDE
        tool_offsets.append(offset)
        events.append(
            make_event(
                next_id,
                EventType.FILE_WRITE,
                payload_file_write(f"/work/out{index}.txt", written=index + 1),
                monotonic_ns=T0 + offset,
            )
        )
        next_id += 1

    tasks = (make_task(label="concurrent"),)
    markers: AssistantMarkers | None = None
    if declaration_limit is not None:
        declarations = [
            {
                "call_id": f"req-{index}",
                "tool_id": f"tool-{index}",
                "task_label": "concurrent",
                "connection_id": "conn-1" if shared_connection else f"conn-{index}",
                "monotonic_ns": T0 + tool_offsets[index] if marker_times else None,
                "pid": declared_pid,
                "process_start_id": declared_start,
            }
            for index in range(min(ways, declaration_limit))
        ]
        markers = AssistantMarkers.from_records(declarations)
    return tuple(events), tuple(calls), tasks, markers


def corpus_scenario() -> tuple[
    tuple[Event, ...], tuple[LlmCallRecord, ...], tuple[Task, ...], AssistantMarkers
]:
    """较完整的语料：子进程 + 并发调用 + 容器标签 + 辅助标记。

    供消融/序列化/解释类测试使用。
    """

    events_list: list[Event] = [
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(
            2,
            EventType.PROCESS_FORK,
            payload_process_fork(),
            monotonic_ns=T0 + 2_000_000,
        ),
        make_event(
            3,
            EventType.PROCESS_EXEC,
            payload_process_exec("/bin/sh"),
            monotonic_ns=T0 + 3_000_000,
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=CHILD_START,
        ),
        make_event(
            4,
            EventType.FILE_WRITE,
            payload_file_write("/work/child.txt"),
            monotonic_ns=T0 + 4_000_000,
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=CHILD_START,
        ),
        make_event(
            5,
            EventType.PROCESS_EXIT,
            payload_process_exit(),
            monotonic_ns=T0 + 5_000_000,
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=CHILD_START,
        ),
        make_event(
            6,
            EventType.FILE_UNLINK,
            payload_file_unlink("/work/tmp"),
            monotonic_ns=T0 + 10_500_000,  # 落在 tool-0 的声明时间片内
        ),
    ]
    for index in range(3):
        events_list.append(
            make_event(
                10 + index,
                EventType.TLS_BYTES,
                payload_tls("conn-1"),
                monotonic_ns=T0 + 1_000_000 + index * 1_000,
            )
        )
        events_list.append(
            make_event(
                20 + index,
                EventType.TLS_BYTES,
                payload_tls("conn-1", direction="read", byte_count=64),
                monotonic_ns=T0 + 2_000_000 + index * 1_000,
            )
        )
        events_list.append(
            make_event(
                30 + index,
                EventType.FILE_WRITE,
                payload_file_write(f"/work/tool{index}.txt"),
                monotonic_ns=T0 + 10_000_000 + index * 1_000,
            )
        )
    calls = tuple(make_call(f"req-{index}", "conn-1", index=index) for index in range(3))
    tasks = (
        make_task(
            label="corpus",
            process_start_ids=frozenset({PROC_START, CHILD_START}),
            labels={"container_id": "ctr-1"},
        ),
    )
    markers = AssistantMarkers.from_records(
        [
            {
                "call_id": f"req-{index}",
                "tool_id": f"tool-{index}",
                "task_label": "corpus",
                "connection_id": "conn-1",
                "pid": PID,
                "process_start_id": PROC_START,
                "monotonic_ns": T0 + 10_000_000 + index * 1_000,
            }
            for index in range(3)
        ]
    )
    return tuple(events_list), calls, tasks, markers
