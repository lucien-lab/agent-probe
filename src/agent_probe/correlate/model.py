"""证据图数据模型、置信度语义与关联配置（M3 核心，用户态、离线可测）。

本模块只描述"证据图长什么样"和"置信度是什么意思"，不做任何关联计算；
关联算法见 :mod:`agent_probe.correlate.graph`，门面见
:mod:`agent_probe.correlate.engine`。

三条不可妥协的语义（详见 ``docs/03-correlation.md``）：

1. **只做带证据的关联，不做因果推断。** 每条 :class:`EvidenceEdge` 必须携带
   ``basis``（依据类别）、``method_version``（方法版本）、``confidence``
   （置信等级）与 ``evidence``（人类可读的证据串）；缺任何一项都无法构造。
2. **不确定就必须说出来。** 有多个同等强度候选时输出
   :attr:`Confidence.AMBIGUOUS` 并把**全部候选**保留在
   :attr:`EvidenceEdge.candidates` 中；没有任何候选时输出
   :attr:`Confidence.UNKNOWN`。禁止"取时间最近的那个"这类伪确定。
3. **稳定性可复现。** ``node_id``/``edge_id`` 一律由**内容**哈希派生
   （kind+key / src+dst+basis+method_version），不含 ``id()``、时间戳、随机数，
   也不依赖字典迭代顺序；同一输入必须产出逐字节相同的序列化结果。
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from agent_probe.events import canonical_json

from .errors import CorrelationInputError

__all__ = [
    "METHOD_VERSION",
    "MAX_ID_BYTES",
    "stable_id",
    "EvidenceNodeKind",
    "EdgeBasis",
    "Confidence",
    "CONFIDENCE_RANK",
    "CONFIDENCE_BY_RANK",
    "compose_confidence",
    "BASIS_EXPLANATIONS",
    "CONFIDENCE_EXPLANATIONS",
    "Task",
    "EvidenceNode",
    "EvidenceEdge",
    "Ambiguity",
    "NodeAttribution",
    "CorrelationConfig",
    "AttributionStats",
    "CorrelationResult",
    "ContainerResolver",
]


#: 默认方法版本。任何会改变关联结论的语义改动都必须递增它，并写进
#: ``docs/03-correlation.md`` 的"方法版本"一节；边上的这个字符串是
#: "这条结论是用哪一版方法得出的"的唯一线索。
METHOD_VERSION: Final[str] = "m3-correlate-1"

#: node_id / edge_id 的长度上限（防护性校验）。
MAX_ID_BYTES: Final[int] = 128


def stable_id(namespace: str, key: str) -> str:
    """由内容派生稳定 ID：``<前缀>:<sha256 前 32 位十六进制>``。

    同一 ``(namespace, key)`` 在任何进程、任何时间、任何输入顺序下都得到同一
    字符串；不同内容碰撞到同一 ID 在 128 位截断下可忽略，且 ``key`` 本身会被
    保留在 :class:`EvidenceNode` 里以便排查。
    """

    digest = hashlib.sha256(f"{namespace}\x1f{key}".encode("utf-8")).hexdigest()
    return f"{namespace[:1]}:{digest[:32]}"


class EvidenceNodeKind(StrEnum):
    """证据图节点类别。"""

    #: 任务（一个 probe run 的归属根）。
    TASK = "task"
    #: 进程实例（``pid`` + ``process_start_id``，与 run 绑定）。
    PROCESS = "process"
    #: 一次物理 LLM 请求（``physical_request_id``）。
    LLM_CALL = "llm_call"
    #: 一次工具调用。**只来自应用侧声明**（辅助模式），系统事件里没有这种类型。
    TOOL_CALL = "tool_call"
    #: 文件副作用（同一进程 + 同一文件身份的多个事件聚合）。
    FILE_EFFECT = "file_effect"
    #: 网络副作用（``net.connect``/``net.send`` 聚合，或 ``tls.bytes`` 连接）。
    NET_EFFECT = "net_effect"
    #: 容器（仅当注入了 :class:`ContainerResolver` 且解析命中时才会出现）。
    CONTAINER = "container"


class EdgeBasis(StrEnum):
    """关联边的依据类别。名字本身是对外契约，不要重命名。"""

    #: 进程身份与血缘：``(pid, process_start_id)`` 精确身份、``process.fork``
    #: 父子链、任务声明的根进程集合及其后代。
    PROCESS_LINEAGE = "process_lineage"
    #: 时间窗：同一 ``run_id`` 内按 ``monotonic_ns`` 判断的包含关系。
    #: **永远不能单独给出 CERTAIN**，最高 PROBABLE。
    TIME_WINDOW = "time_window"
    #: 连接身份：``tls.bytes.payload.connection_id`` 与
    #: ``LlmCallRecord.connection_id`` 的精确匹配。
    CONNECTION_ID = "connection_id"
    #: 运行/任务标记：系统侧 ``run_id`` 相同，以及任务自带的 ``cgroup_id``
    #: 与事件 ``cgroup_id`` 精确相同。
    RUN_ID_MARKER = "run_id_marker"
    #: 应用声明的 ``call_id``（声明，需与系统证据交叉核验）。
    CALL_ID_MARKER = "call_id_marker"
    #: 应用声明的 ``tool_id``（声明，需与系统证据交叉核验）。
    TOOL_ID_MARKER = "tool_id_marker"
    #: 容器映射：**只在注入 ContainerResolver 后产生**
    #: （容器 → 任务 由标签声明 + resolver 解析；进程 → 容器 由宿主
    #: pid / cgroup 命中）。
    CONTAINER_MAPPING = "container_mapping"


class Confidence(StrEnum):
    """关联置信等级。

    * ``CERTAIN``：由**精确标识**匹配确立（连接 ID 精确匹配、``(pid,
      process_start_id)`` 精确身份、``cgroup_id`` 精确匹配、声明与系统事件
      双向核验通过且无缺口）。候选唯一。
    * ``PROBABLE``：有方向一致的系统证据但缺少唯一标识（时间窗内唯一候选、
      仅 ``run_id`` 相同且无诞生事件、声明存在未核验缺口但没有反证）。
      候选唯一，但**不是**精确匹配。
    * ``AMBIGUOUS``：存在 ≥2 个同等强度的候选，无法择一。**全部候选**必须
      出现在 :attr:`EvidenceEdge.candidates` 里，不得只留一个。
    * ``UNKNOWN``：没有任何可用证据，或证据不足以产生候选（包括缺少必要
      输入：未提供任务声明、辅助标记未启用、时间锚点缺失等）。
    """

    CERTAIN = "certain"
    PROBABLE = "probable"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


#: 置信强度的偏序：``UNKNOWN < AMBIGUOUS < PROBABLE < CERTAIN``。
#:
#: 路径合成的规则是"取最弱一环"（:func:`compose_confidence`）。把
#: ``AMBIGUOUS`` 排在 ``PROBABLE`` 之下是刻意的：对**某一个具体候选**而言，
#: "多个候选并列"比"唯一候选但非精确匹配"更弱。
CONFIDENCE_RANK: Final[Mapping[Confidence, int]] = {
    Confidence.UNKNOWN: 0,
    Confidence.AMBIGUOUS: 1,
    Confidence.PROBABLE: 2,
    Confidence.CERTAIN: 3,
}

#: :data:`CONFIDENCE_RANK` 的反查表（强度 → 等级）。
CONFIDENCE_BY_RANK: Final[Mapping[int, Confidence]] = {
    rank: confidence for confidence, rank in CONFIDENCE_RANK.items()
}


def compose_confidence(*values: Confidence) -> Confidence:
    """路径合成：返回最弱的一环（见 :data:`CONFIDENCE_RANK`）。"""

    if not values:
        return Confidence.UNKNOWN
    return min(values, key=lambda item: CONFIDENCE_RANK[Confidence(item)])


#: ``explain`` 使用的依据说明表。名字是公开契约的一部分。
BASIS_EXPLANATIONS: Final[Mapping[EdgeBasis, str]] = {
    EdgeBasis.PROCESS_LINEAGE: (
        "进程身份与血缘：事件自带的 (pid, process_start_id) 精确身份；"
        "process.fork 的父子链；任务声明的根进程集合及其后代。"
        "PID 复用（同 pid 不同 process_start_id）视为不同进程。"
    ),
    EdgeBasis.TIME_WINDOW: (
        "时间窗：仅在同一 run_id 内按 monotonic_ns 判断包含关系；"
        "wall_time 只能作为弱证据（PROBABLE 上限）且必须显式标注；"
        "绝不跨 boot 比较。时间接近本身永远不足以给出 CERTAIN。"
    ),
    EdgeBasis.CONNECTION_ID: (
        "连接身份：tls.bytes.payload.connection_id 与 "
        "LlmCallRecord.connection_id 精确相等。这是调用与系统事件之间"
        "唯一可以给出 CERTAIN 的调用级依据。"
    ),
    EdgeBasis.RUN_ID_MARKER: (
        "运行/任务标记：系统侧 run_id 相同；或任务声明的 cgroup_id 与"
        "事件 cgroup_id 精确相同。仅 run_id 相同（无血缘、无 cgroup）"
        "最高只能 PROBABLE。"
    ),
    EdgeBasis.CALL_ID_MARKER: (
        "应用声明的 call_id：属于**声明**，必须与系统证据交叉核验。"
        "声明与系统证据冲突时降级为 AMBIGUOUS/PROBABLE，且 evidence 里"
        "同时保留声明与系统证据两条。"
    ),
    EdgeBasis.TOOL_ID_MARKER: (
        "应用声明的 tool_id：属于**声明**，必须与系统证据（进程身份、"
        "时间）交叉核验。核验通过才给 CERTAIN；冲突必须降级。"
    ),
    EdgeBasis.CONTAINER_MAPPING: (
        "容器映射：只在注入 ContainerResolver 且宿主 pid / cgroup_id"
        "命中时建立。未注入 resolver 时不会凭空产生容器归属。"
    ),
}

#: ``explain`` 使用的置信度说明表。
CONFIDENCE_EXPLANATIONS: Final[Mapping[Confidence, str]] = {
    Confidence.CERTAIN: "精确标识匹配且候选唯一。",
    Confidence.PROBABLE: "系统证据方向一致、候选唯一，但不是精确标识匹配。",
    Confidence.AMBIGUOUS: "存在多个同等强度的候选；全部候选保留在 candidates 中。",
    Confidence.UNKNOWN: "没有可用证据或证据不足以产生候选；不猜测。",
}


# --------------------------------------------------------------------------- #
# 校验原语
# --------------------------------------------------------------------------- #


def _check_text(name: str, value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise CorrelationInputError(
            f"{name} 必须是字符串，实际为 {type(value).__name__}"
        )
    if "\x00" in value:
        raise CorrelationInputError(f"{name} 不能包含 NUL 字节")
    if not value and not allow_empty:
        raise CorrelationInputError(f"{name} 不能为空字符串")
    if len(value.encode("utf-8")) > 4096:
        raise CorrelationInputError(f"{name} 超过 4096 字节上限")
    return value


def _check_int(name: str, value: Any, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CorrelationInputError(
            f"{name} 必须是整数，实际为 {type(value).__name__}"
        )
    if minimum is not None and value < minimum:
        raise CorrelationInputError(f"{name} 必须 ≥ {minimum}，实际为 {value}")
    return value


def _check_json_serializable(name: str, value: Any) -> None:
    """属性表必须能 JSON 往返（否则 :meth:`CorrelationResult.to_dict` 会炸）。"""

    if value is None or isinstance(value, (bool, int, float, str)):
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CorrelationInputError(f"{name} 的键必须是字符串")
            _check_json_serializable(f"{name}.{key}", item)
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_json_serializable(f"{name}[{index}]", item)
        return
    raise CorrelationInputError(
        f"{name} 的值 {type(value).__name__} 不是 JSON 原生类型"
    )


def _normalize_attributes(name: str, attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    """规范化属性表：键排序、数组转 list、拒绝非 JSON 值。

    排序与 list 化只为一件事：``to_dict`` 的字节完全确定。
    """

    if attributes is None:
        return {}
    if not isinstance(attributes, Mapping):
        raise CorrelationInputError(f"{name} 必须是映射")
    normalized: dict[str, Any] = {}
    for key in sorted(attributes):
        value = attributes[key]
        if not isinstance(key, str):
            raise CorrelationInputError(f"{name} 的键必须是字符串")
        _check_json_serializable(f"{name}.{key}", value)
        normalized[key] = _to_json_value(value)
    return normalized


def _to_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _to_json_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_to_json_value(item) for item in value]
    if isinstance(value, (frozenset, set)):
        return [_to_json_value(item) for item in sorted(value, key=repr)]
    if isinstance(value, StrEnum):
        return str(value)
    return value


# --------------------------------------------------------------------------- #
# 任务
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Task:
    """一个待归因的任务（= 一次 probe run）。

    * ``run_id``：任务身份。同一批输入里 ``run_id`` 必须唯一（重复且内容不同
      会抛 :class:`~agent_probe.correlate.errors.CorrelationInputError`）。
    * ``label``：人类可读标签，用于报告；**不参与**任何关联判定。
    * ``cgroup_id``：任务自带的 cgroup。与事件 ``cgroup_id`` 精确相同即
      :attr:`EdgeBasis.RUN_ID_MARKER` + ``CERTAIN``（系统侧字段比较，
      **不需要**容器解析器）。
    * ``process_start_ids``：任务根进程的 ``/proc/<pid>/stat`` starttime 集合。
      命中即"根进程"，其后代经 ``process.fork`` 链归入本任务。
    * ``started_monotonic_ns`` / ``ended_monotonic_ns``：任务观察窗口，
      用于"run 开始前就存在的进程"判定（此时不给 PROBABLE，只给 UNKNOWN）。
    * ``labels``：任意字符串标签（容器 ID 等）。
    """

    run_id: str
    label: str = ""
    cgroup_id: int | None = None
    process_start_ids: frozenset[int] = field(default_factory=frozenset)
    started_monotonic_ns: int = 0
    ended_monotonic_ns: int | None = None
    labels: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _check_text("Task.run_id", self.run_id)
        _check_text("Task.label", self.label, allow_empty=True)
        if self.cgroup_id is not None:
            _check_int("Task.cgroup_id", self.cgroup_id, minimum=0)
        starts = self.process_start_ids
        if not isinstance(starts, frozenset):
            object.__setattr__(self, "process_start_ids", frozenset(starts))
        for value in self.process_start_ids:
            _check_int("Task.process_start_ids 元素", value, minimum=0)
        _check_int("Task.started_monotonic_ns", self.started_monotonic_ns, minimum=0)
        if self.ended_monotonic_ns is not None:
            _check_int("Task.ended_monotonic_ns", self.ended_monotonic_ns, minimum=0)
            if self.ended_monotonic_ns < self.started_monotonic_ns:
                raise CorrelationInputError(
                    "Task.ended_monotonic_ns 不能早于 Task.started_monotonic_ns"
                )
        if not isinstance(self.labels, Mapping):
            raise CorrelationInputError("Task.labels 必须是映射")
        object.__setattr__(
            self,
            "labels",
            {key: str(self.labels[key]) for key in sorted(self.labels)},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "label": self.label,
            "cgroup_id": self.cgroup_id,
            "process_start_ids": sorted(self.process_start_ids),
            "started_monotonic_ns": self.started_monotonic_ns,
            "ended_monotonic_ns": self.ended_monotonic_ns,
            "labels": {key: self.labels[key] for key in sorted(self.labels)},
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Task:
        _require_keys("Task", data, set(cls.__dataclass_fields__))
        return cls(
            run_id=data["run_id"],
            label=data["label"],
            cgroup_id=data["cgroup_id"],
            process_start_ids=frozenset(data["process_start_ids"]),
            started_monotonic_ns=data["started_monotonic_ns"],
            ended_monotonic_ns=data["ended_monotonic_ns"],
            labels=dict(data["labels"]),
        )


def _require_keys(context: str, data: Mapping[str, Any], expected: set[str]) -> None:
    if not isinstance(data, Mapping):
        raise CorrelationInputError(f"{context}：期望对象，实际为 {type(data).__name__}")
    missing = sorted(expected - set(data))
    unknown = sorted(set(data) - expected)
    if missing:
        raise CorrelationInputError(f"{context}：缺少字段 {', '.join(missing)}")
    if unknown:
        raise CorrelationInputError(f"{context}：未知字段 {', '.join(unknown)}")


# --------------------------------------------------------------------------- #
# 节点与边
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class EvidenceNode:
    """证据图节点。

    * ``node_id``：由 ``(kind, key)`` 内容哈希派生，稳定可复现。
    * ``key``：去重主键。语义由 kind 决定：
      ``run:<run_id>``（TASK）、``run:…:pid:…:start:…``（PROCESS）、
      ``physical_request_id``（LLM_CALL）、声明身份（TOOL_CALL）、
      ``run:…:pid:…:…:path:…``（FILE_EFFECT / NET_EFFECT）、
      ``container:<id>``（CONTAINER）。
    * ``monotonic_ns``：节点在单调时钟上的代表时刻（首个事件），未知写 ``None``。
    * ``attributes``：JSON 可序列化的证据摘要（键已排序、数组已 list 化）。
    """

    node_id: str
    kind: EvidenceNodeKind
    key: str
    monotonic_ns: int | None
    attributes: Mapping[str, Any]

    def __post_init__(self) -> None:
        kind = EvidenceNodeKind(self.kind)
        object.__setattr__(self, "kind", kind)
        _check_text("EvidenceNode.node_id", self.node_id)
        _check_text("EvidenceNode.key", self.key)
        if self.monotonic_ns is not None:
            _check_int("EvidenceNode.monotonic_ns", self.monotonic_ns, minimum=0)
        object.__setattr__(
            self, "attributes", _normalize_attributes("EvidenceNode.attributes", self.attributes)
        )
        expected = stable_id("node", f"{kind.value}\x1f{self.key}")
        if self.node_id != expected:
            raise CorrelationInputError(
                f"EvidenceNode.node_id 与内容不符：期望 {expected!r}，实际 {self.node_id!r}"
            )

    @classmethod
    def create(
        cls,
        *,
        kind: EvidenceNodeKind,
        key: str,
        monotonic_ns: int | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> EvidenceNode:
        resolved = EvidenceNodeKind(kind)
        return cls(
            node_id=stable_id("node", f"{resolved.value}\x1f{key}"),
            kind=resolved,
            key=key,
            monotonic_ns=monotonic_ns,
            attributes=attributes if attributes is not None else {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": str(self.kind),
            "key": self.key,
            "monotonic_ns": self.monotonic_ns,
            "attributes": _to_json_value(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvidenceNode:
        _require_keys(
            "EvidenceNode", data, {"node_id", "kind", "key", "monotonic_ns", "attributes"}
        )
        return cls(
            node_id=data["node_id"],
            kind=data["kind"],
            key=data["key"],
            monotonic_ns=data["monotonic_ns"],
            attributes=data["attributes"],
        )


@dataclass(frozen=True, slots=True)
class EvidenceEdge:
    """一条**带证据**的关联边：``src`` 归属于 ``dst``（自下而上）。

    方向约定（必须与 ``docs/03-correlation.md`` 一致）：边从"被归属者"指向
    "归属者"。因此任务级归因是 ``PROCESS/LLM_CALL/FILE_EFFECT → TASK``，
    进程血缘是 ``子进程 → 父进程``。"任务 → 调用 → 工具 → 事件"这条概念链
    与之一一对应，只是边的方向取"证据自下而上"：``explain(node_id=…)`` 直接
    读该节点的出边就等于读它的归属，不需要反向索引。

    * ``confidence``：见 :class:`Confidence`。
    * ``candidates``：**仅**在 ``AMBIGUOUS`` 时非空，存放"其他候选 dst"；
      ``dst_node_id`` 是按 ``node_id`` 升序确定性选出的主候选，**不代表
      归因成立**，只是让边可寻址。
    * ``evidence``：至少一条人类可读证据串，必须能回答"凭什么"。
    """

    edge_id: str
    src_node_id: str
    dst_node_id: str
    basis: EdgeBasis
    method_version: str
    confidence: Confidence
    evidence: tuple[str, ...]
    candidates: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        basis = EdgeBasis(self.basis)
        confidence = Confidence(self.confidence)
        object.__setattr__(self, "basis", basis)
        object.__setattr__(self, "confidence", confidence)
        _check_text("EvidenceEdge.edge_id", self.edge_id)
        _check_text("EvidenceEdge.src_node_id", self.src_node_id)
        _check_text("EvidenceEdge.dst_node_id", self.dst_node_id)
        _check_text("EvidenceEdge.method_version", self.method_version)
        if self.src_node_id == self.dst_node_id:
            raise CorrelationInputError("EvidenceEdge 不允许自环")
        evidence = tuple(self.evidence)
        if not evidence:
            raise CorrelationInputError("EvidenceEdge 必须至少携带一条 evidence 字符串")
        for item in evidence:
            _check_text("EvidenceEdge.evidence 元素", item)
        object.__setattr__(self, "evidence", evidence)
        candidates = tuple(self.candidates)
        for item in candidates:
            _check_text("EvidenceEdge.candidates 元素", item)
        if confidence is Confidence.AMBIGUOUS:
            if not candidates:
                raise CorrelationInputError(
                    "AMBIGUOUS 边必须给出其他候选 dst（不得丢弃候选）"
                )
        elif candidates:
            raise CorrelationInputError(
                f"{confidence} 边不允许携带 candidates；候选只有唯一一个"
            )
        if self.dst_node_id in candidates:
            raise CorrelationInputError("candidates 不能包含 dst_node_id 自身")
        object.__setattr__(self, "candidates", candidates)
        expected = edge_identity(self.src_node_id, self.dst_node_id, basis, self.method_version)
        if self.edge_id != expected:
            raise CorrelationInputError(
                f"EvidenceEdge.edge_id 与内容不符：期望 {expected!r}，实际 {self.edge_id!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "src_node_id": self.src_node_id,
            "dst_node_id": self.dst_node_id,
            "basis": str(self.basis),
            "method_version": self.method_version,
            "confidence": str(self.confidence),
            "evidence": list(self.evidence),
            "candidates": list(self.candidates),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvidenceEdge:
        _require_keys(
            "EvidenceEdge",
            data,
            {
                "edge_id",
                "src_node_id",
                "dst_node_id",
                "basis",
                "method_version",
                "confidence",
                "evidence",
                "candidates",
            },
        )
        return cls(
            edge_id=data["edge_id"],
            src_node_id=data["src_node_id"],
            dst_node_id=data["dst_node_id"],
            basis=data["basis"],
            method_version=data["method_version"],
            confidence=data["confidence"],
            evidence=tuple(data["evidence"]),
            candidates=tuple(data["candidates"]),
        )


def edge_identity(
    src_node_id: str, dst_node_id: str, basis: EdgeBasis, method_version: str
) -> str:
    """边的稳定身份：``(src, dst, basis, method_version)`` 的内容哈希。

    ``confidence``/``evidence`` 刻意**不**参与身份：同一条关联被更多证据支持时
    应当合并成一条边（置信取最强、证据取并集），而不是产生一堆同身份边。
    """

    return stable_id(
        "edge",
        "\x1f".join((src_node_id, dst_node_id, EdgeBasis(basis).value, method_version)),
    )


@dataclass(frozen=True, slots=True)
class Ambiguity:
    """一条显式记录的歧义：``node_id`` 或 ``edge_id`` 二选一。"""

    candidates: tuple[str, ...]
    reason: str
    node_id: str | None = None
    edge_id: str | None = None

    def __post_init__(self) -> None:
        if (self.node_id is None) == (self.edge_id is None):
            raise CorrelationInputError("Ambiguity 必须且只能指定 node_id 或 edge_id 之一")
        candidates = tuple(self.candidates)
        if len(candidates) < 2:
            raise CorrelationInputError("Ambiguity 至少要有 2 个候选")
        object.__setattr__(self, "candidates", candidates)
        _check_text("Ambiguity.reason", self.reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "edge_id": self.edge_id,
            "candidates": list(self.candidates),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Ambiguity:
        _require_keys("Ambiguity", data, {"node_id", "edge_id", "candidates", "reason"})
        return cls(
            node_id=data["node_id"],
            edge_id=data["edge_id"],
            candidates=tuple(data["candidates"]),
            reason=data["reason"],
        )


@dataclass(frozen=True, slots=True)
class NodeAttribution:
    """一个节点在**任务级**上的归因结论（由证据图上的路径合成）。

    * ``targets``：最高强度的候选任务 node_id（升序）。``AMBIGUOUS`` 时 ≥2 个，
      ``UNKNOWN`` 时可能为空或含仅有 UNKNOWN 证据的目标。
    * ``primary``：``targets`` 中确定性选出的第一个（仅用于寻址，不代表成立）。
    * ``path``：得到 ``primary`` 的最强路径上的边 id（自下而上）。
    """

    node_id: str
    confidence: Confidence
    targets: tuple[str, ...]
    primary: str | None
    path: tuple[str, ...] = ()

    @property
    def determinate(self) -> bool:
        """是否有唯一归因（``CERTAIN``/``PROBABLE`` 且候选唯一）。"""

        return self.confidence in (Confidence.CERTAIN, Confidence.PROBABLE)


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CorrelationConfig:
    """关联配置：消融开关 + 规模上限。

    每个 ``use_*`` 开关都必须能独立关闭（M6 消融实验依赖这一点）。默认值：
    五个数据通道全开、辅助标记默认关闭（辅助模式需要应用侧适配器提供声明，
    不能默认假设存在）。

    ``max_nodes``/``max_edges``/``max_candidates`` 是**硬上限**：超限抛
    :class:`~agent_probe.correlate.errors.CorrelationLimitError`，绝不静默截断
    （静默截断会悄悄改变 precision/recall 的分母）。唯一允许的截断是
    "歧义候选过多"时的候选列表，且必须把截断事实写进边的 evidence。
    """

    use_time_window: bool = True
    use_process_lineage: bool = True
    use_connection_id: bool = True
    use_container_mapping: bool = True
    use_assisted_markers: bool = False
    time_window_ns: int = 5_000_000_000
    method_version: str = METHOD_VERSION
    max_nodes: int = 100_000
    max_edges: int = 100_000
    max_candidates: int = 32

    def __post_init__(self) -> None:
        for name in (
            "use_time_window",
            "use_process_lineage",
            "use_connection_id",
            "use_container_mapping",
            "use_assisted_markers",
        ):
            if not isinstance(getattr(self, name), bool):
                raise CorrelationInputError(f"CorrelationConfig.{name} 必须是 bool")
        _check_int("CorrelationConfig.time_window_ns", self.time_window_ns, minimum=0)
        _check_text("CorrelationConfig.method_version", self.method_version)
        for name in ("max_nodes", "max_edges", "max_candidates"):
            _check_int(f"CorrelationConfig.{name}", getattr(self, name), minimum=1)

    # -- 便利访问器 --------------------------------------------------------- #

    @property
    def enabled_switches(self) -> tuple[str, ...]:
        return tuple(
            name
            for name in (
                "use_time_window",
                "use_process_lineage",
                "use_connection_id",
                "use_container_mapping",
                "use_assisted_markers",
            )
            if getattr(self, name)
        )

    def with_switch(self, name: str, value: bool) -> CorrelationConfig:
        if name not in {
            "use_time_window",
            "use_process_lineage",
            "use_connection_id",
            "use_container_mapping",
            "use_assisted_markers",
        }:
            raise CorrelationInputError(f"未知的消融开关 {name!r}")
        return replace(self, **{name: value})

    def to_dict(self) -> dict[str, Any]:
        return {
            "use_time_window": self.use_time_window,
            "use_process_lineage": self.use_process_lineage,
            "use_connection_id": self.use_connection_id,
            "use_container_mapping": self.use_container_mapping,
            "use_assisted_markers": self.use_assisted_markers,
            "time_window_ns": self.time_window_ns,
            "method_version": self.method_version,
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
            "max_candidates": self.max_candidates,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CorrelationConfig:
        _require_keys("CorrelationConfig", data, set(cls.__dataclass_fields__))
        return cls(**dict(data))


# --------------------------------------------------------------------------- #
# 统计与结果
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AttributionStats:
    """归因质量统计。

    口径（与 plan.md §4 一致，必须一起解释，不能只报一个数）：

    * ``determinate_coverage`` = (CERTAIN + PROBABLE) / 待归因节点数。
      "待归因节点" = 除 TASK 节点（归因目标）以外的全部节点。
    * ``ambiguity_rate`` = AMBIGUOUS / 待归因节点数。
    * ``precision`` = 有唯一且正确归因的节点 / **所有给出唯一归因的节点**（分母
      只统计真值覆盖到的节点）；``recall`` = 唯一且正确归因的节点 /
      **真值中的全部节点**（含结果里根本没有的节点与 UNKNOWN 归因节点，
      未知归因不得从分母里删除）。二者只在传入真值时计算，否则为 ``None``。
    * ``edges_*``：边级别置信分布，用于观察"调用级关联"的退化
      （例如并发下 TIME_WINDOW 边退化为 AMBIGUOUS）。
    """

    tasks_total: int = 0
    nodes_total: int = 0
    nodes_certain: int = 0
    nodes_probable: int = 0
    nodes_ambiguous: int = 0
    nodes_unknown: int = 0
    determinate_coverage: float = 0.0
    ambiguity_rate: float = 0.0
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    edges_total: int = 0
    edges_certain: int = 0
    edges_probable: int = 0
    edges_ambiguous: int = 0
    edges_unknown: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tasks_total": self.tasks_total,
            "nodes_total": self.nodes_total,
            "nodes_certain": self.nodes_certain,
            "nodes_probable": self.nodes_probable,
            "nodes_ambiguous": self.nodes_ambiguous,
            "nodes_unknown": self.nodes_unknown,
            "determinate_coverage": self.determinate_coverage,
            "ambiguity_rate": self.ambiguity_rate,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "edges_total": self.edges_total,
            "edges_certain": self.edges_certain,
            "edges_probable": self.edges_probable,
            "edges_ambiguous": self.edges_ambiguous,
            "edges_unknown": self.edges_unknown,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AttributionStats:
        _require_keys("AttributionStats", data, set(cls.__dataclass_fields__))
        return cls(**dict(data))

    def with_scores(self, *, precision: float | None, recall: float | None) -> AttributionStats:
        if precision is None or recall is None:
            return replace(self, precision=precision, recall=recall, f1=None)
        total = precision + recall
        f1 = 0.0 if total == 0 else 2 * precision * recall / total
        return replace(self, precision=precision, recall=recall, f1=f1)


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    """可序列化的关联结果（``to_dict`` → ``from_dict`` → 再计算一致）。

    ``notes`` 是结果级别的显式说明（未注入 resolver、忽略的标记、
    wall/monotonic 混用被拒、候选被截断等）。它是**结论的一部分**：
    "没有容器归属"和"容器归属没启用"必须能区分开。
    """

    nodes: tuple[EvidenceNode, ...]
    edges: tuple[EvidenceEdge, ...]
    ambiguities: tuple[Ambiguity, ...]
    stats: AttributionStats
    config: CorrelationConfig
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "nodes", tuple(self.nodes))
        object.__setattr__(self, "edges", tuple(self.edges))
        object.__setattr__(self, "ambiguities", tuple(self.ambiguities))
        object.__setattr__(self, "notes", tuple(self.notes))

    # -- 查询 --------------------------------------------------------------- #

    def node_by_id(self) -> dict[str, EvidenceNode]:
        return {node.node_id: node for node in self.nodes}

    def edge_by_id(self) -> dict[str, EvidenceEdge]:
        return {edge.edge_id: edge for edge in self.edges}

    def nodes_of_kind(self, kind: EvidenceNodeKind) -> tuple[EvidenceNode, ...]:
        resolved = EvidenceNodeKind(kind)
        return tuple(node for node in self.nodes if node.kind is resolved)

    def outgoing(self, node_id: str) -> tuple[EvidenceEdge, ...]:
        return tuple(edge for edge in self.edges if edge.src_node_id == node_id)

    def incoming(self, node_id: str) -> tuple[EvidenceEdge, ...]:
        return tuple(edge for edge in self.edges if edge.dst_node_id == node_id)

    @property
    def mode(self) -> str:
        """``assisted``（启用辅助标记）或 ``external``（纯外部观测）。"""

        return "assisted" if self.config.use_assisted_markers else "external"

    # -- 序列化 ------------------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "stats": self.stats.to_dict(),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "ambiguities": [item.to_dict() for item in self.ambiguities],
            "notes": list(self.notes),
        }

    def to_json(self) -> str:
        """规范化 JSON 文本：同输入逐字节相同（``sort_keys`` + 紧凑分隔符）。"""

        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CorrelationResult:
        _require_keys(
            "CorrelationResult",
            data,
            {"config", "stats", "nodes", "edges", "ambiguities", "notes"},
        )
        return cls(
            nodes=tuple(EvidenceNode.from_dict(item) for item in data["nodes"]),
            edges=tuple(EvidenceEdge.from_dict(item) for item in data["edges"]),
            ambiguities=tuple(Ambiguity.from_dict(item) for item in data["ambiguities"]),
            stats=AttributionStats.from_dict(data["stats"]),
            config=CorrelationConfig.from_dict(data["config"]),
            notes=tuple(data["notes"]),
        )

    @classmethod
    def from_json(cls, text: str | bytes) -> CorrelationResult:
        import json

        if isinstance(text, bytes):
            text = text.decode("utf-8")
        return cls.from_dict(json.loads(text))


# --------------------------------------------------------------------------- #
# 容器解析协议（本模块自行定义，绝不 import agent_probe.container）
# --------------------------------------------------------------------------- #


@runtime_checkable
class ContainerResolver(Protocol):
    """容器 → 宿主资源解析接口（由调用方注入，T06 提供实现）。

    本模块**只依赖这两个方法**，不 import ``agent_probe.container``：两个任务
    按"结构化协议"解耦，各自可独立合并。返回值 ``None`` 表示**解析不到**，
    绝不能当成 0——解析不到就不建立容器归属。
    """

    def resolve_host_pid(self, container_id: str) -> int | None:
        """返回容器在宿主上的 pid；无法解析返回 ``None``。"""

        ...

    def resolve_cgroup_id(self, container_id: str) -> int | None:
        """返回容器的 cgroup id；无法解析返回 ``None``。"""

        ...
