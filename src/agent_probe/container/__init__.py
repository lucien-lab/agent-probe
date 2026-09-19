"""``agent_probe.container``：M3 Docker 任务映射核心（库层，不接入 CLI）。

只做**解析与映射**这一件事：``任务标签 → 容器 → 宿主 PID/cgroup → 挂载视图``。

* :mod:`~agent_probe.container.model` —— 规范化模型：容器状态、挂载类型、
  ``docker inspect`` 解析、映射结果与序列化。
* :mod:`~agent_probe.container.query` —— 查询端口 ``ContainerQuery`` 与
  可注入 runner 的真实实现 ``DockerCli``。
* :mod:`~agent_probe.container.mapper` —— ``ContainerTaskMapper``：标签唯一匹配、
  歧义、时间窗与短命任务竞态、有界候选。
* :mod:`~agent_probe.container.mounts` —— ``MountResolver``：容器内 ↔ 宿主路径
  双向解析（目录边界、最长前缀优先）。
* :mod:`~agent_probe.container.cgroup` —— 可注入的 cgroup 标识读取端口
  （``/proc/<pid>/cgroup`` + cgroupfs inode），失败即 ``None``。
* :mod:`~agent_probe.container.paths` —— 路径词法规范化与边界匹配（纯计算）。
* :mod:`~agent_probe.container.errors` —— 异常层次。

**不做什么**

* 不做关联引擎（任务/请求/系统事件的证据图、置信度）：那是 T05 的
  ``agent_probe.correlate``，两者按结构化协议解耦，本子包不 import 它。
* 不采集 eBPF、不读事件账本、不注册任何 ``probe`` 子命令、不接入 CLI。
* 不做因果推断：容器由 Docker daemon 创建，**不是** agent 的子进程，
  因此本层只用 label、容器状态与 inspect 真值字段做映射，禁止进程树推断。

根包 ``agent_probe`` 刻意只导出 ``__version__``；语义与真值边界见
``docs/03b-container-mapping.md``。
"""

from __future__ import annotations

from .cgroup import (
    DEFAULT_CGROUP_ROOT,
    DEFAULT_PROC_ROOT,
    MAX_CGROUP_LINES,
    CgroupReader,
    CgroupRecord,
    NullCgroupReader,
    ProcCgroupReader,
)
from .errors import (
    ContainerError,
    ContainerNotFoundError,
    ContainerQueryError,
    ContainerTimeoutError,
    ContainerValidationError,
)
from .mapper import (
    DEFAULT_MAX_CANDIDATES,
    MAX_CANDIDATES,
    MAX_EVIDENCE_ITEMS,
    ContainerTaskMapper,
)
from .model import (
    CGROUP_ID_KEY,
    CGROUP_NOTE_KEY,
    CGROUP_PATH_KEY,
    CONTAINER_ID_HEX_LENGTHS,
    DEFAULT_LABEL_KEY,
    DOCKER_STATE_MAP,
    INSPECT_REQUIRED_KEYS,
    MAX_INT64,
    MAX_LABELS,
    MAX_MOUNTS,
    MAX_RAW_TYPE_BYTES,
    MAX_TEXT_BYTES,
    MOUNT_TYPE_MAP,
    ZERO_DOCKER_TIMESTAMP_PREFIX,
    ContainerInfo,
    ContainerMapping,
    ContainerMount,
    ContainerState,
    InspectView,
    MappingOutcome,
    MountType,
    canonical_json,
    format_rfc3339_ns,
    parse_container_state,
    parse_inspect,
    parse_mounts,
    parse_rfc3339_ns,
    validate_container_id,
)
from .mounts import MAX_RESOLVER_EVIDENCE, MountResolver
from .paths import (
    MAX_PATH_BYTES,
    is_clean_absolute_path,
    join_path,
    normalize_path,
    relative_to,
)
from .query import (
    DEFAULT_DOCKER_BINARY,
    DEFAULT_TIMEOUT_S,
    INSPECT_ARGS,
    MAX_EXCERPT_BYTES,
    PS_ARGS,
    ContainerQuery,
    DockerCli,
    DockerRunner,
    RunnerResult,
    SubprocessRunner,
)

__all__ = [
    # errors
    "ContainerError",
    "ContainerValidationError",
    "ContainerQueryError",
    "ContainerTimeoutError",
    "ContainerNotFoundError",
    # model
    "DEFAULT_LABEL_KEY",
    "MAX_TEXT_BYTES",
    "MAX_LABELS",
    "MAX_MOUNTS",
    "MAX_RAW_TYPE_BYTES",
    "MAX_INT64",
    "CONTAINER_ID_HEX_LENGTHS",
    "CGROUP_ID_KEY",
    "CGROUP_PATH_KEY",
    "CGROUP_NOTE_KEY",
    "ZERO_DOCKER_TIMESTAMP_PREFIX",
    "INSPECT_REQUIRED_KEYS",
    "DOCKER_STATE_MAP",
    "MOUNT_TYPE_MAP",
    "ContainerState",
    "MountType",
    "MappingOutcome",
    "ContainerMount",
    "ContainerInfo",
    "InspectView",
    "ContainerMapping",
    "validate_container_id",
    "parse_container_state",
    "parse_rfc3339_ns",
    "format_rfc3339_ns",
    "parse_mounts",
    "parse_inspect",
    "canonical_json",
    # paths
    "MAX_PATH_BYTES",
    "is_clean_absolute_path",
    "normalize_path",
    "relative_to",
    "join_path",
    # mounts
    "MAX_RESOLVER_EVIDENCE",
    "MountResolver",
    # query
    "DEFAULT_DOCKER_BINARY",
    "DEFAULT_TIMEOUT_S",
    "MAX_EXCERPT_BYTES",
    "PS_ARGS",
    "INSPECT_ARGS",
    "RunnerResult",
    "DockerRunner",
    "SubprocessRunner",
    "ContainerQuery",
    "DockerCli",
    # cgroup
    "DEFAULT_PROC_ROOT",
    "DEFAULT_CGROUP_ROOT",
    "MAX_CGROUP_LINES",
    "CgroupRecord",
    "CgroupReader",
    "NullCgroupReader",
    "ProcCgroupReader",
    # mapper
    "DEFAULT_MAX_CANDIDATES",
    "MAX_CANDIDATES",
    "MAX_EVIDENCE_ITEMS",
    "ContainerTaskMapper",
]
