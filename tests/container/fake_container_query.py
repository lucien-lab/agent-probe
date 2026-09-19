"""测试用的内存 :class:`~agent_probe.container.ContainerQuery` 与 inspect 构造器。

目的：把"容器真值"变成显式数据，使映射测试**不依赖 docker、不依赖宿主平台、
不联网**，也不需要 root。

用法::

    query = FakeContainerQuery()
    cid = query.add(inspect_payload(container_id(1), labels={LABEL_KEY: LABEL}))
    mapping = ContainerTaskMapper(query).map_label(LABEL, observed_monotonic_ns=NOW)

时间字符串由本模块**独立**渲染（不调用被测实现的 ``format_rfc3339_ns``），
避免"用实现验证实现"。
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agent_probe.container import ContainerQueryError

#: 与实现默认值一致的标签键（测试侧独立声明，便于发现默认值被改坏）。
LABEL_KEY = "agent-probe.task"

#: 测试用任务标签。
LABEL = "task-1"

SECOND_NS = 1_000_000_000
MINUTE_NS = 60 * SECOND_NS

#: 固定时间基准：2023-11-14T22:13:20Z。
BASE_NS = 1_700_000_000_000_000_000

#: docker 的"尚未发生"时间戳。
ZERO_TIME = "0001-01-01T00:00:00Z"


def container_id(seed: int) -> str:
    """确定性 64 位十六进制容器 ID（低位是 ASCII 形状的十六进制）。"""

    return f"{seed:064x}"


def short_id(full_id: str) -> str:
    """docker 短 ID（前 12 位十六进制）。"""

    return full_id[:12]


def rfc3339_ns(value: int) -> str:
    """Unix epoch 纳秒 → ``YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ``（测试侧独立实现）。"""

    seconds, nanoseconds = divmod(value, SECOND_NS)
    moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{nanoseconds:09d}Z"


def mount_entry(
    *,
    mount_type: str = "bind",
    source: str | None = "/host/data",
    destination: str = "/data",
    rw: bool = True,
    include_source: bool | None = None,
) -> dict[str, Any]:
    """构造一个 ``docker inspect`` 的 ``Mounts[]`` 元素。

    ``include_source=False`` 表示连 ``Source`` 键都不写（与 ``source=""`` 不同）。
    """

    entry: dict[str, Any] = {
        "Type": mount_type,
        "Destination": destination,
        "RW": rw,
        "Mode": "",
        "Propagation": "",
    }
    if include_source is None:
        include_source = source is not None
    if include_source:
        entry["Source"] = source
    return entry


def inspect_payload(
    container_id_value: str,
    *,
    name: str = "task",
    labels: Mapping[str, str] | None = None,
    status: str | None = "running",
    pid: int | None = 4242,
    created_ns: int | None = BASE_NS,
    started_ns: int | None = None,
    finished_ns: int | None = None,
    mounts: Sequence[Mapping[str, Any]] = (),
    cgroup_id: int | None = None,
    cgroup_path: str | None = None,
    cgroup_note: str | None = None,
    include_state: bool = True,
    include_config: bool = True,
    include_mounts: bool = True,
    include_state_times: bool = True,
) -> dict[str, Any]:
    """构造 ``docker inspect <id>`` 的单容器 JSON 对象。

    * ``status=None`` / ``pid=None``：连键都不写（与显式 ``null`` 不同）。
    * ``started_ns`` / ``finished_ns`` 为 ``None`` 时写 docker 的零时间。
    """

    payload: dict[str, Any] = {
        "Id": container_id_value,
        "Name": f"/{name}",
        "Created": ZERO_TIME if created_ns is None else rfc3339_ns(created_ns),
    }
    if include_state:
        state: dict[str, Any] = {}
        if status is not None:
            state["Status"] = status
        if pid is not None:
            state["Pid"] = pid
        if include_state_times:
            state["StartedAt"] = (
                ZERO_TIME if started_ns is None else rfc3339_ns(started_ns)
            )
            state["FinishedAt"] = (
                ZERO_TIME if finished_ns is None else rfc3339_ns(finished_ns)
            )
        payload["State"] = state
    if include_config:
        payload["Config"] = {"Labels": dict(labels or {})}
    if include_mounts:
        payload["Mounts"] = [dict(entry) for entry in mounts]
    if cgroup_id is not None:
        payload["CgroupID"] = cgroup_id
    if cgroup_path is not None:
        payload["CgroupPath"] = cgroup_path
    if cgroup_note is not None:
        payload["CgroupProbeNote"] = cgroup_note
    return payload


@dataclass
class FakeContainerQuery:
    """内存 :class:`~agent_probe.container.ContainerQuery` 实现。

    * ``ids``：``list_container_ids`` 的返回（可故意列出短 ID 或重复 ID）。
    * ``payloads``：``inspect`` 的返回，键是 ``list_container_ids`` 给出的 ID。
    * ``list_error`` / ``inspect_errors``：注入查询失败。
    * ``calls``：调用记录，用于断言"没有多余查询"。
    """

    ids: list[str] = field(default_factory=list)
    payloads: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    list_error: Exception | None = None
    inspect_errors: dict[str, Exception] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    # ---- 构造辅助 ------------------------------------------------------------

    def add(
        self,
        payload: Mapping[str, Any],
        *,
        listed_id: str | None = None,
    ) -> str:
        """登记一个容器：加入 list 结果并登记 inspect 响应，返回完整容器 ID。"""

        full_id = str(payload["Id"])
        lookup = full_id if listed_id is None else listed_id
        self.ids.append(lookup)
        self.payloads[lookup] = payload
        return full_id

    def fail_list(self, exc: Exception) -> None:
        self.list_error = exc

    def fail_inspect(self, container_id_value: str, exc: Exception) -> None:
        self.inspect_errors[container_id_value] = exc

    def list_call_count(self) -> int:
        return sum(1 for call in self.calls if call == "list")

    def inspect_calls(self) -> tuple[str, ...]:
        return tuple(
            call.split(":", 1)[1] for call in self.calls if call.startswith("inspect:")
        )

    # ---- ContainerQuery ------------------------------------------------------

    def list_container_ids(self) -> tuple[str, ...]:
        self.calls.append("list")
        if self.list_error is not None:
            raise self.list_error
        return tuple(self.ids)

    def inspect(self, container_id_value: str) -> Mapping[str, Any]:
        self.calls.append(f"inspect:{container_id_value}")
        error = self.inspect_errors.get(container_id_value)
        if error is not None:
            raise error
        try:
            return self.payloads[container_id_value]
        except KeyError:  # pragma: no cover - 测试配置错误时给出明确原因
            raise ContainerQueryError(
                f"FakeContainerQuery 未登记容器 {container_id_value!r}"
            ) from None


@dataclass
class FakeRunner:
    """按完整命令行匹配的假 runner（测试绝不执行真实 docker）。

    ``results`` 的键是 ``" ".join(argv)``，值是三元组或 ``RunnerResult``。
    未配置的命令会抛 :class:`AssertionError`（而不是让 docker 真的跑起来）。
    """

    results: dict[str, Any] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def set(self, argv: Sequence[str], result: Any) -> None:
        self.results[" ".join(str(part) for part in argv)] = result

    def __call__(self, argv: Sequence[str]) -> Any:
        call = tuple(str(part) for part in argv)
        self.calls.append(call)
        key = " ".join(call)
        if key not in self.results:
            raise AssertionError(f"FakeRunner 未配置命令：{key}")
        return self.results[key]


class RaisingRunner:
    """总是抛出给定异常的 runner（用于超时/启动失败路径）。"""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str]) -> Any:
        self.calls.append(tuple(str(part) for part in argv))
        raise self.exc


def ps_result(*ids: str, returncode: int = 0, stderr: str = "") -> tuple[int, str, str]:
    """``docker ps`` 的假输出。"""

    return (returncode, "\n".join(ids) + ("\n" if ids else ""), stderr)


def inspect_result(
    *payloads: Mapping[str, Any], raw: str | None = None
) -> tuple[int, str, str]:
    """``docker inspect`` 的假输出（默认包成 JSON 数组，与 docker 行为一致）。"""

    if raw is not None:
        return (0, raw, "")
    return (0, json.dumps([dict(payload) for payload in payloads]), "")
