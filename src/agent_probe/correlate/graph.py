"""证据图构建：从系统事件 + 调用记录 + 任务声明 + 应用声明生成节点与边。

本模块是 M3 关联引擎的算法核心，**只做带证据的关联，不做因果推断**。
它不知道 Docker 查询怎么实现（只调用注入的
:class:`~agent_probe.correlate.model.ContainerResolver`），也不知道 CLI。

构建顺序（固定，保证确定性）
----------------------------

1. 容器标签解析（仅在注入 resolver 且开关打开时）
2. TASK 节点
3. CONTAINER 节点 + ``CONTAINER → TASK`` 边
4. 进程聚合 → PROCESS 节点（键为 ``run_id + pid + process_start_id``）
5. 血缘边 ``子进程 → 父进程``（``process.fork``）
6. 进程归属边 ``PROCESS → TASK``
7. 副作用聚合 → FILE_EFFECT / NET_EFFECT 节点
8. 副作用归属边 ``EFFECT → PROCESS``
9. LLM_CALL 节点（时间锚点来自同 ``connection_id`` 的 ``tls.bytes`` 事件）
10. ``LLM_CALL → NET_EFFECT(tls)``（``connection_id`` 精确匹配）
11. 辅助标记：TOOL_CALL 节点、声明边、标记时间段的副作用归属
12. 外部调用的副作用归属（``TIME_WINDOW``；被标记判定过的副作用跳过）
13. ``PROCESS → CONTAINER`` 边

边的方向一律是"被归属者 → 归属者"（见
:class:`~agent_probe.correlate.model.EvidenceEdge`）。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_probe.events import Event, EventType
from agent_probe.llm import LlmCallRecord

from .errors import CorrelationInputError, CorrelationLimitError
from .markers import AssistantMarkers, MarkerDeclaration
from .model import (
    CONFIDENCE_RANK,
    Confidence,
    ContainerResolver,
    CorrelationConfig,
    EdgeBasis,
    EvidenceEdge,
    EvidenceNode,
    EvidenceNodeKind,
    compose_confidence,
    edge_identity,
)

__all__ = ["GraphBuild", "build_graph", "IGNORED_EVENT_TYPES"]

#: 被本模块**刻意忽略**的事件类型。``quality.*`` 描述的是采集器自身的质量
#: 信号（丢失/缺口），它的 pid 是采集器的 pid；把它当成 agent 进程只会制造
#: 假节点。质量信息由 M2 的账本/索引负责，关联层不重复解释。
IGNORED_EVENT_TYPES: frozenset[EventType] = frozenset(
    {
        EventType.QUALITY_SEQUENCE_GAP,
        EventType.QUALITY_RING_DROP,
        EventType.QUALITY_QUEUE_DROP,
        EventType.QUALITY_STORAGE_DROP,
        EventType.QUALITY_COUNTER_SNAPSHOT,
    }
)

_FILE_EVENT_TYPES: frozenset[EventType] = frozenset(
    {
        EventType.FILE_OPEN,
        EventType.FILE_READ,
        EventType.FILE_WRITE,
        EventType.FILE_TRUNCATE,
        EventType.FILE_RENAME,
        EventType.FILE_UNLINK,
    }
)

_NET_EVENT_TYPES: frozenset[EventType] = frozenset(
    {EventType.NET_CONNECT, EventType.NET_SEND}
)

#: 节点属性里保留的样本事件 id 数量上限（证据可回溯，但不无限膨胀）。
_SAMPLE_EVENT_IDS = 4

#: 任务标签里可能承载容器 ID 的键（按优先级，大小写不敏感）。
_CONTAINER_LABEL_KEYS = (
    "container_id",
    "docker_container_id",
    "container",
    "docker",
    "containerid",
)


@dataclass(frozen=True, slots=True)
class GraphBuild:
    """构建结果：节点/边（已排序、已合并）与结果级说明。"""

    nodes: tuple[EvidenceNode, ...]
    edges: tuple[EvidenceEdge, ...]
    notes: tuple[str, ...]


@dataclass
class _EdgeAcc:
    """同身份边的累加器：置信取最强，证据取并集。"""

    src: str
    dst: str
    basis: EdgeBasis
    method_version: str
    confidence: Confidence
    evidence: list[str] = field(default_factory=list)
    candidates: tuple[str, ...] = ()


@dataclass
class _ProcAgg:
    run_id: str
    pid: int
    start_id: int | None
    first_ns: int
    last_ns: int
    first_wall_time: int = 0
    event_count: int = 0
    event_types: set[str] = field(default_factory=set)
    tids: set[int] = field(default_factory=set)
    cgroup_ids: set[int] = field(default_factory=set)
    pid_namespaces: set[int] = field(default_factory=set)
    observed_via: set[str] = field(default_factory=set)
    event_ids: list[str] = field(default_factory=list)
    exec_count: int = 0
    exe: str | None = None
    exe_ns: int = -1
    has_exit: bool = False
    exit_code: int | None = None
    signal: int | None = None


@dataclass
class _EffectAgg:
    kind: EvidenceNodeKind
    ident: str
    run_id: str
    pid: int
    start_id: int | None
    first_ns: int
    last_ns: int
    event_types: set[str] = field(default_factory=set)
    count: int = 0
    results: dict[str, int] = field(default_factory=dict)
    event_ids: list[str] = field(default_factory=list)
    correlation_ids: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    bytes_read: int = 0
    bytes_written: int = 0
    protocol: str | None = None
    dest_addr: str | None = None
    dest_port: int | None = None
    connection_id: str | None = None
    directions: set[str] = field(default_factory=set)
    bytes_total: int = 0


@dataclass
class _CallAgg:
    node_id: str
    record: LlmCallRecord
    tls_node_ids: tuple[str, ...]
    span_lo: int | None
    span_hi: int | None


@dataclass
class _DeclVerdict:
    declaration: MarkerDeclaration
    checks: dict[str, str] = field(default_factory=dict)
    confidence: Confidence = Confidence.UNKNOWN
    call_targets: tuple[str, ...] = ()
    process_targets: tuple[str, ...] = ()
    task_targets: tuple[str, ...] = ()
    start_ns: int | None = None
    identity_bridge: bool = False
    declared_evidence: tuple[str, ...] = ()
    system_evidence: tuple[str, ...] = ()


def _proc_ident(run_id: str, pid: int, start_id: int | None) -> str:
    return f"run:{run_id}:pid:{pid}:start:{'unknown' if start_id is None else start_id}"


def _file_ident(event: Event) -> str:
    payload = event.payload
    if event.event_type is EventType.FILE_RENAME:
        return f"path:{payload['new_path']}"
    path = payload.get("path")
    if path is not None:
        return f"path:{path}"
    return f"fd:{payload.get('fd')}"


def _net_ident(event: Event) -> str:
    payload = event.payload
    if event.event_type is EventType.TLS_BYTES:
        return f"tls:{payload['connection_id']}"
    return f"net:{payload['protocol']}:{payload['dest_addr']}:{payload['dest_port']}"


def _sample(values: Sequence[str]) -> list[str]:
    return sorted(values)[:_SAMPLE_EVENT_IDS]


def _proc_sort_key(agg: _ProcAgg) -> tuple[Any, ...]:
    return (agg.run_id, agg.pid, agg.start_id is None, agg.start_id or 0)


def _effect_sort_key(agg: _EffectAgg) -> tuple[Any, ...]:
    return (
        agg.run_id,
        agg.pid,
        agg.start_id is None,
        agg.start_id or 0,
        agg.ident,
    )


def _call_sort_key(record: LlmCallRecord) -> tuple[str, str, str, int]:
    return (
        record.physical_request_id,
        record.logical_call_id,
        record.connection_id,
        record.identity.attempt_index,
    )


def _declaration_summary(declaration: MarkerDeclaration) -> str:
    parts = [
        f"{name}={getattr(declaration, name)!r}"
        for name in declaration.declared_fields()
    ]
    if declaration.label:
        parts.append(f"label={declaration.label!r}")
    return "MarkerDeclaration(" + ", ".join(parts) + ")"


class _GraphBuilder:
    def __init__(
        self,
        *,
        events: Sequence[Event],
        calls: Sequence[LlmCallRecord],
        tasks: Sequence[Any],
        markers: AssistantMarkers | None,
        config: CorrelationConfig,
        container_resolver: ContainerResolver | None,
    ) -> None:
        self.config = config
        self.resolver = container_resolver
        self.events = tuple(
            sorted(events, key=lambda item: (item.run_id, item.monotonic_ns, item.event_id))
        )
        self.calls = tuple(sorted(calls, key=_call_sort_key))
        self.tasks = tuple(sorted(tasks, key=lambda item: item.run_id))
        self.markers = markers

        self._nodes: dict[str, EvidenceNode] = {}
        self._edges: dict[str, _EdgeAcc] = {}
        self._notes: list[str] = []
        self._note_seen: set[str] = set()

        self._task_by_run: dict[str, tuple[Any, str]] = {}
        self._proc_aggs: dict[tuple[str, int, int | None], _ProcAgg] = {}
        self._proc_nodes: dict[tuple[str, int, int | None], EvidenceNode] = {}
        self._proc_by_pid: dict[tuple[str, int], list[str]] = {}
        self._effect_aggs: dict[str, _EffectAgg] = {}
        self._effect_nodes: dict[str, EvidenceNode] = {}
        self._effect_to_process: dict[str, str] = {}
        self._tls_by_connection: dict[str, list[str]] = {}
        self._correlation_index: dict[str, list[str]] = {}
        self._call_aggs: dict[str, _CallAgg] = {}
        self._call_processes: dict[str, set[str]] = {}
        self._container_infos: dict[str, dict[str, Any]] = {}
        self._container_nodes: dict[str, str] = {}
        self._tool_nodes: dict[str, str] = {}
        self._tool_call_targets: dict[str, set[str]] = {}
        self._marker_decided_effects: set[str] = set()
        self._correlation_owned: dict[str, str] = {}

    # ------------------------------------------------------------------ #
    # 基础设施
    # ------------------------------------------------------------------ #

    def _note(self, text: str) -> None:
        if text not in self._note_seen:
            self._note_seen.add(text)
            self._notes.append(text)

    def _add_node(self, node: EvidenceNode) -> EvidenceNode:
        existing = self._nodes.get(node.node_id)
        if existing is not None:
            if existing != node:
                raise CorrelationInputError(
                    f"节点身份冲突：{node.key!r} 产生了两种不同内容"
                )
            return existing
        if len(self._nodes) >= self.config.max_nodes:
            raise CorrelationLimitError(
                f"节点数量超过 CorrelationConfig.max_nodes={self.config.max_nodes}；"
                "证据图不会静默截断，请缩小输入范围或调高上限"
            )
        self._nodes[node.node_id] = node
        return node

    def _candidate_limit(self) -> int:
        """``candidates`` 列表（不含 dst）的长度上限。"""

        return max(1, self.config.max_candidates - 1)

    def _split_candidates(
        self, src: str, candidates: Sequence[str]
    ) -> tuple[str, tuple[str, ...], str | None]:
        """把候选集合切成 ``(主候选, 其他候选, 截断说明)``，去重且升序。"""

        ordered = tuple(sorted({item for item in candidates if item != src}))
        if len(ordered) < 2:
            raise CorrelationInputError("歧义边至少需要 2 个候选")
        primary = ordered[0]
        others = ordered[1:]
        note: str | None = None
        if len(ordered) > self.config.max_candidates:
            note = (
                f"candidates_truncated: kept {self.config.max_candidates} of "
                f"{len(ordered)}（max_candidates 上限；被截断的候选 id 见候选全集的"
                "边外记录）"
            )
            self._note(
                f"candidates: 一次歧义的候选数 {len(ordered)} 超过 "
                f"max_candidates={self.config.max_candidates}，已截断"
            )
            others = others[: self._candidate_limit()]
        return primary, others, note

    def _add_edge(
        self,
        src: str,
        dst: str,
        basis: EdgeBasis,
        confidence: Confidence,
        evidence: str | Sequence[str],
        *,
        candidates: Sequence[str] = (),
    ) -> str:
        resolved_basis = EdgeBasis(basis)
        resolved_confidence = Confidence(confidence)
        items = (evidence,) if isinstance(evidence, str) else tuple(evidence)
        if not items:
            raise CorrelationInputError("边必须至少带一条证据")
        if src == dst:
            raise CorrelationInputError("证据边不允许自环")

        others = tuple(sorted({item for item in candidates if item != dst}))
        if resolved_confidence is Confidence.AMBIGUOUS:
            if not others:
                raise CorrelationInputError(
                    f"AMBIGUOUS 边缺少候选（src={src} dst={dst} basis={resolved_basis}）"
                )
            others = others[: self._candidate_limit()]
        else:
            others = ()

        edge_id = edge_identity(src, dst, resolved_basis, self.config.method_version)
        acc = self._edges.get(edge_id)
        if acc is None:
            if len(self._edges) >= self.config.max_edges:
                raise CorrelationLimitError(
                    f"边数量超过 CorrelationConfig.max_edges={self.config.max_edges}；"
                    "证据图不会静默截断"
                )
            acc = _EdgeAcc(
                src=src,
                dst=dst,
                basis=resolved_basis,
                method_version=self.config.method_version,
                confidence=resolved_confidence,
                candidates=others,
            )
            self._edges[edge_id] = acc
            acc.evidence.extend(items)
            return edge_id

        acc.evidence.extend(items)
        if CONFIDENCE_RANK[resolved_confidence] > CONFIDENCE_RANK[acc.confidence]:
            if acc.candidates:
                acc.evidence.append(
                    "更强的证据收敛了候选：原候选 "
                    f"{list(acc.candidates)} 不再是并列候选"
                )
            acc.confidence = resolved_confidence
            acc.candidates = others
        elif resolved_confidence is Confidence.AMBIGUOUS and acc.confidence is Confidence.AMBIGUOUS:
            merged = tuple(sorted(set(acc.candidates) | set(others)))
            if merged != acc.candidates:
                acc.evidence.append(f"候选取并集后为 {list(merged)}")
            acc.candidates = merged[: self._candidate_limit()]
        return edge_id

    def _add_ambiguous_edge(
        self,
        src: str,
        candidates: Sequence[str],
        basis: EdgeBasis,
        evidence: Sequence[str],
    ) -> None:
        primary, others, truncated = self._split_candidates(src, candidates)
        payload = list(evidence)
        payload.append(
            f"共 {len(others) + 1} 个候选：{[primary, *others]}；"
            f"dst={primary} 只是确定性占位，不代表归因成立"
        )
        if truncated:
            payload.append(truncated)
        self._add_edge(src, primary, basis, Confidence.AMBIGUOUS, payload, candidates=others)

    # ------------------------------------------------------------------ #
    # 入口
    # ------------------------------------------------------------------ #

    def build(self) -> GraphBuild:
        self._validate_tasks()
        self._resolve_containers()
        self._build_tasks()
        self._build_container_nodes()
        self._aggregate_processes()
        if self.config.use_process_lineage:
            self._build_lineage_edges()
        self._build_process_owner_edges()
        self._aggregate_effects()
        self._build_effect_process_edges()
        self._build_calls()
        self._build_call_connection_edges()
        self._build_assisted_markers()
        self._build_external_effect_call_edges()
        self._build_process_container_edges()

        nodes = tuple(sorted(self._nodes.values(), key=lambda node: node.node_id))
        edges = tuple(
            EvidenceEdge(
                edge_id=edge_identity(acc.src, acc.dst, acc.basis, acc.method_version),
                src_node_id=acc.src,
                dst_node_id=acc.dst,
                basis=acc.basis,
                method_version=acc.method_version,
                confidence=acc.confidence,
                evidence=tuple(sorted(set(acc.evidence))),
                candidates=acc.candidates,
            )
            for acc in sorted(
                self._edges.values(),
                key=lambda item: (item.src, item.dst, item.basis.value),
            )
        )
        if not self.tasks:
            self._note(
                "tasks: 未提供任务声明；所有节点在任务级上都是 UNKNOWN（不猜测归属）"
            )
        if not self.events:
            self._note("events: 未提供系统事件；结果只反映调用记录与声明")
        if not self.calls:
            self._note("calls: 未提供调用记录；调用级关联为空")
        return GraphBuild(nodes=nodes, edges=edges, notes=tuple(self._notes))

    # ------------------------------------------------------------------ #
    # 1–3. 任务与容器
    # ------------------------------------------------------------------ #

    def _validate_tasks(self) -> None:
        seen: dict[str, Any] = {}
        for task in self.tasks:
            previous = seen.get(task.run_id)
            if previous is None:
                seen[task.run_id] = task
            elif previous != task:
                raise CorrelationInputError(
                    f"run_id={task.run_id!r} 上出现了内容不同的两个任务声明；"
                    "任务必须一一对应"
                )

    def _lookup_container_id(self, task: Any) -> str | None:
        lowered = {key.lower(): value for key, value in task.labels.items()}
        for key in _CONTAINER_LABEL_KEYS:
            value = lowered.get(key)
            if value:
                return value
        return None

    def _resolve_containers(self) -> None:
        for task in self.tasks:
            info: dict[str, Any] = {
                "status": "no_container_label",
                "container_id": None,
                "host_pid": None,
                "cgroup_id": None,
            }
            container_id = self._lookup_container_id(task)
            if container_id is not None:
                info["container_id"] = container_id
                if not self.config.use_container_mapping:
                    info["status"] = "disabled_by_config"
                    self._note(
                        "container_mapping: config.use_container_mapping=False；"
                        "未建立任何容器归属"
                    )
                elif self.resolver is None:
                    info["status"] = "no_resolver"
                    self._note(
                        "container_mapping: 未注入 ContainerResolver；未建立容器归属"
                        "（相关节点保持原状，不假装知道容器成员）"
                    )
                else:
                    host_pid = self.resolver.resolve_host_pid(container_id)
                    cgroup_id = self.resolver.resolve_cgroup_id(container_id)
                    info["host_pid"] = host_pid
                    info["cgroup_id"] = cgroup_id
                    if host_pid is None and cgroup_id is None:
                        info["status"] = "unresolved"
                        self._note(
                            f"container_mapping: container_id={container_id!r} 未能解析"
                            "（resolve_host_pid/resolve_cgroup_id 均返回 None）"
                        )
                    else:
                        info["status"] = "resolved"
            self._container_infos[task.run_id] = info

    def _build_tasks(self) -> None:
        for task in self.tasks:
            info = self._container_infos[task.run_id]
            node = EvidenceNode.create(
                kind=EvidenceNodeKind.TASK,
                key=f"run:{task.run_id}",
                monotonic_ns=task.started_monotonic_ns,
                attributes={
                    "run_id": task.run_id,
                    "label": task.label,
                    "cgroup_id": task.cgroup_id,
                    "process_start_ids": sorted(task.process_start_ids),
                    "started_monotonic_ns": task.started_monotonic_ns,
                    "ended_monotonic_ns": task.ended_monotonic_ns,
                    "labels": {key: task.labels[key] for key in sorted(task.labels)},
                    "container_mapping": info["status"],
                    "container_id": info["container_id"],
                    "container_host_pid": info["host_pid"],
                    "container_cgroup_id": info["cgroup_id"],
                },
            )
            self._add_node(node)
            self._task_by_run[task.run_id] = (task, node.node_id)

    def _build_container_nodes(self) -> None:
        for run_id in sorted(self._container_infos):
            info = self._container_infos[run_id]
            if info["status"] != "resolved":
                continue
            container_id = info["container_id"]
            node = self._add_node(
                EvidenceNode.create(
                    kind=EvidenceNodeKind.CONTAINER,
                    key=f"container:{container_id}",
                    monotonic_ns=None,
                    attributes={
                        "container_id": container_id,
                        "run_id": run_id,
                        "resolved_host_pid": info["host_pid"],
                        "resolved_cgroup_id": info["cgroup_id"],
                        "resolver": type(self.resolver).__name__
                        if self.resolver is not None
                        else None,
                    },
                )
            )
            self._container_nodes[run_id] = node.node_id
            _, task_node_id = self._task_by_run[run_id]
            self._add_edge(
                node.node_id,
                task_node_id,
                EdgeBasis.CONTAINER_MAPPING,
                Confidence.CERTAIN,
                (
                    f"任务标签声明 container_id={container_id!r}，且注入的 "
                    f"ContainerResolver 解析成功（host_pid={info['host_pid']}, "
                    f"cgroup_id={info['cgroup_id']}）",
                    f"容器与任务来自同一份标签声明（run_id={run_id}）",
                ),
            )

    # ------------------------------------------------------------------ #
    # 4. 进程聚合
    # ------------------------------------------------------------------ #

    def _proc_attributes(self, agg: _ProcAgg) -> dict[str, Any]:
        cgroups = sorted(agg.cgroup_ids)
        return {
            "run_id": agg.run_id,
            "pid": agg.pid,
            "process_start_id": agg.start_id,
            "start_id_known": agg.start_id is not None,
            "first_seen_monotonic_ns": agg.first_ns,
            "last_seen_monotonic_ns": agg.last_ns,
            "first_wall_time_ns": agg.first_wall_time,
            "event_count": agg.event_count,
            "event_types": sorted(agg.event_types),
            "tids": sorted(agg.tids),
            "cgroup_id": cgroups[0] if len(cgroups) == 1 else None,
            "cgroup_ids": cgroups,
            "pid_namespaces": sorted(agg.pid_namespaces),
            "observed_via": sorted(agg.observed_via),
            "exec_count": agg.exec_count,
            "exe": agg.exe,
            "has_process_exit": agg.has_exit,
            "exit_code": agg.exit_code,
            "signal": agg.signal,
            "sample_event_ids": _sample(agg.event_ids),
        }

    def _aggregate_processes(self) -> None:
        for event in self.events:
            if event.event_type in IGNORED_EVENT_TYPES:
                continue
            key = (event.run_id, event.pid, event.process_start_id)
            agg = self._proc_aggs.get(key)
            if agg is None:
                agg = _ProcAgg(
                    run_id=event.run_id,
                    pid=event.pid,
                    start_id=event.process_start_id,
                    first_ns=event.monotonic_ns,
                    last_ns=event.monotonic_ns,
                    first_wall_time=event.wall_time,
                )
                self._proc_aggs[key] = agg
            else:
                agg.first_ns = min(agg.first_ns, event.monotonic_ns)
                agg.last_ns = max(agg.last_ns, event.monotonic_ns)
                if agg.first_wall_time == 0:
                    agg.first_wall_time = event.wall_time
            agg.event_count += 1
            agg.event_types.add(str(event.event_type))
            agg.tids.add(event.tid)
            if event.cgroup_id is not None:
                agg.cgroup_ids.add(event.cgroup_id)
            if event.pid_namespace is not None:
                agg.pid_namespaces.add(event.pid_namespace)
            agg.observed_via.add("event")
            agg.event_ids.append(event.event_id)
            if event.event_type is EventType.PROCESS_EXEC:
                if event.monotonic_ns >= agg.exe_ns:
                    agg.exe_ns = event.monotonic_ns
                    agg.exe = event.payload["exe"]
                agg.exec_count += 1
            elif event.event_type is EventType.PROCESS_EXIT:
                agg.has_exit = True
                agg.exit_code = event.payload.get("exit_code")
                agg.signal = event.payload.get("signal")

        for agg in sorted(self._proc_aggs.values(), key=_proc_sort_key):
            node = self._add_node(
                EvidenceNode.create(
                    kind=EvidenceNodeKind.PROCESS,
                    key=_proc_ident(agg.run_id, agg.pid, agg.start_id),
                    monotonic_ns=agg.first_ns,
                    attributes=self._proc_attributes(agg),
                )
            )
            self._proc_nodes[(agg.run_id, agg.pid, agg.start_id)] = node
            self._proc_by_pid.setdefault((agg.run_id, agg.pid), []).append(node.node_id)
        for bucket in self._proc_by_pid.values():
            bucket.sort()

    def _pid_nodes(self, run_id: str, pid: int) -> list[EvidenceNode]:
        return [self._nodes[node_id] for node_id in self._proc_by_pid.get((run_id, pid), ())]

    def _create_process(
        self,
        run_id: str,
        pid: int,
        start_id: int | None,
        *,
        via: str,
        monotonic_ns: int,
    ) -> EvidenceNode:
        key = (run_id, pid, start_id)
        existing = self._proc_nodes.get(key)
        if existing is not None:
            return existing
        agg = _ProcAgg(
            run_id=run_id,
            pid=pid,
            start_id=start_id,
            first_ns=monotonic_ns,
            last_ns=monotonic_ns,
        )
        agg.observed_via.add(via)
        self._proc_aggs[key] = agg
        node = self._add_node(
            EvidenceNode.create(
                kind=EvidenceNodeKind.PROCESS,
                key=_proc_ident(run_id, pid, start_id),
                monotonic_ns=agg.first_ns,
                attributes=self._proc_attributes(agg),
            )
        )
        self._proc_nodes[key] = node
        bucket = self._proc_by_pid.setdefault((run_id, pid), [])
        bucket.append(node.node_id)
        bucket.sort()
        return node

    # ------------------------------------------------------------------ #
    # 5. 血缘
    # ------------------------------------------------------------------ #

    def _lookup_process(
        self,
        run_id: str,
        pid: int,
        start_id: int | None,
        *,
        via: str,
        monotonic_ns: int,
    ) -> tuple[EvidenceNode, tuple[str, ...]]:
        """解析进程身份，返回 ``(主节点, 其他候选节点 id)``。

        ``start_id is None`` 且同 pid 存在多个进程实例（PID 复用）时，无法判定
        是哪一次，必须保留全部候选而不是任取一个。
        """

        if start_id is not None:
            return (
                self._create_process(run_id, pid, start_id, via=via, monotonic_ns=monotonic_ns),
                (),
            )
        siblings = self._pid_nodes(run_id, pid)
        if not siblings:
            node = self._create_process(
                run_id, pid, None, via=via, monotonic_ns=monotonic_ns
            )
            return node, ()
        return siblings[0], tuple(node.node_id for node in siblings[1:])

    def _build_lineage_edges(self) -> None:
        for event in self.events:
            if event.event_type is not EventType.PROCESS_FORK:
                continue
            payload = event.payload
            parent_pid = payload["parent_pid"]
            child_pid = payload["child_pid"]
            child_start = payload.get("child_start_id")
            parent_start = event.process_start_id if parent_pid == event.pid else None
            parent_node, parent_candidates = self._lookup_process(
                event.run_id,
                parent_pid,
                parent_start,
                via="fork_parent",
                monotonic_ns=event.monotonic_ns,
            )
            child_node, child_candidates = self._lookup_process(
                event.run_id,
                child_pid,
                child_start,
                via="fork_child",
                monotonic_ns=event.monotonic_ns,
            )

            confidence = Confidence.CERTAIN
            evidence = [
                f"process.fork 事件 {event.event_id}（monotonic_ns="
                f"{event.monotonic_ns}）：parent_pid={parent_pid} → "
                f"child_pid={child_pid}[start_id={child_start}]"
            ]
            if child_start is None:
                confidence = compose_confidence(confidence, Confidence.PROBABLE)
                evidence.append(
                    "child_start_id 未采集：无法区分 PID 复用，子进程身份只有 pid"
                )
            if parent_start is None:
                confidence = compose_confidence(confidence, Confidence.PROBABLE)
                evidence.append(
                    "fork 事件的 process_start_id 未采集：父进程身份只能按 pid 定位"
                )
            if parent_pid != event.pid:
                confidence = compose_confidence(confidence, Confidence.PROBABLE)
                evidence.append(
                    f"数据自相矛盾：事件 pid={event.pid} 与 payload.parent_pid="
                    f"{parent_pid} 不同，因此不采用该事件的 process_start_id 作为父身份"
                )

            all_candidates = tuple(sorted(set(child_candidates) | set(parent_candidates)))
            if all_candidates:
                confidence = Confidence.AMBIGUOUS
                evidence.append(
                    "PID 复用：同 pid 存在多个进程实例（"
                    + ", ".join(all_candidates)
                    + "），fork 的父子对应关系无法唯一确定；保留全部候选"
                )
                for candidate_child in (child_node.node_id, *child_candidates):
                    others = tuple(
                        item
                        for item in all_candidates
                        if item != candidate_child and item != parent_node.node_id
                    )
                    if not others:
                        continue
                    self._add_edge(
                        candidate_child,
                        parent_node.node_id,
                        EdgeBasis.PROCESS_LINEAGE,
                        Confidence.AMBIGUOUS,
                        evidence,
                        candidates=others,
                    )
                continue
            self._add_edge(
                child_node.node_id,
                parent_node.node_id,
                EdgeBasis.PROCESS_LINEAGE,
                confidence,
                evidence,
            )

    # ------------------------------------------------------------------ #
    # 6. 进程归属
    # ------------------------------------------------------------------ #

    def _lineage_adjacency(self) -> dict[str, list[tuple[str, Confidence, str]]]:
        adjacency: dict[str, list[tuple[str, Confidence, str]]] = {}
        for acc in self._edges.values():
            if acc.basis is not EdgeBasis.PROCESS_LINEAGE:
                continue
            src = self._nodes.get(acc.src)
            dst = self._nodes.get(acc.dst)
            if src is None or dst is None:
                continue
            if src.kind is not EvidenceNodeKind.PROCESS or dst.kind is not EvidenceNodeKind.PROCESS:
                continue
            adjacency.setdefault(acc.src, []).append(
                (acc.dst, acc.confidence, edge_identity(acc.src, acc.dst, acc.basis, acc.method_version))
            )
        for bucket in adjacency.values():
            bucket.sort()
        return adjacency

    def _root_path(
        self,
        node_id: str,
        task: Any,
        adjacency: dict[str, list[tuple[str, Confidence, str]]],
    ) -> tuple[Confidence, tuple[str, ...]] | None:
        """从 ``node_id`` 向上找任务根进程，返回 ``(合成置信, 边 id 路径)``。"""

        best: tuple[Confidence, tuple[str, ...]] | None = None
        queue: list[tuple[str, Confidence, tuple[str, ...], frozenset[str]]] = [
            (node_id, Confidence.CERTAIN, (), frozenset({node_id}))
        ]
        while queue:
            current, confidence, path, visited = queue.pop(0)
            node = self._nodes[current]
            start_id = node.attributes.get("process_start_id")
            if (
                current != node_id
                and start_id is not None
                and start_id in task.process_start_ids
            ):
                if best is None or CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[best[0]]:
                    best = (confidence, path)
                continue
            for dst, edge_confidence, edge_id in adjacency.get(current, ()):
                if dst in visited:
                    continue
                queue.append(
                    (
                        dst,
                        compose_confidence(confidence, edge_confidence),
                        path + (edge_id,),
                        visited | {dst},
                    )
                )
        return best

    def _build_process_owner_edges(self) -> None:
        adjacency = self._lineage_adjacency()
        for node in sorted(self._proc_nodes.values(), key=lambda item: item.node_id):
            run_id = node.attributes["run_id"]
            entry = self._task_by_run.get(run_id)
            if entry is None:
                continue
            task, task_node_id = entry
            pid = node.attributes["pid"]
            start_id = node.attributes["process_start_id"]
            identity = _proc_ident(run_id, pid, start_id)

            if self.config.use_process_lineage:
                if start_id is not None and start_id in task.process_start_ids:
                    self._add_edge(
                        node.node_id,
                        task_node_id,
                        EdgeBasis.PROCESS_LINEAGE,
                        Confidence.CERTAIN,
                        f"{identity} 的 process_start_id={start_id} ∈ 任务根进程集合"
                        f"（run_id={run_id}）",
                    )
                    continue
                found = self._root_path(node.node_id, task, adjacency)
                if found is not None:
                    confidence, path = found
                    self._add_edge(
                        node.node_id,
                        task_node_id,
                        EdgeBasis.PROCESS_LINEAGE,
                        confidence,
                        f"{identity} 经 process.fork 链（边 "
                        + " → ".join(path)
                        + f"）到达任务根进程（process_start_ids="
                        f"{sorted(task.process_start_ids)}）",
                    )
                    continue

            cgroup_id = node.attributes.get("cgroup_id")
            if (
                task.cgroup_id is not None
                and cgroup_id is not None
                and cgroup_id == task.cgroup_id
            ):
                self._add_edge(
                    node.node_id,
                    task_node_id,
                    EdgeBasis.RUN_ID_MARKER,
                    Confidence.CERTAIN,
                    f"{identity} 的 cgroup_id={cgroup_id} 与任务声明的 cgroup_id="
                    f"{task.cgroup_id} 精确相同（系统侧字段比较，无需容器解析器）",
                )
                continue

            first_seen = node.attributes["first_seen_monotonic_ns"]
            if first_seen < task.started_monotonic_ns:
                self._add_edge(
                    node.node_id,
                    task_node_id,
                    EdgeBasis.RUN_ID_MARKER,
                    Confidence.UNKNOWN,
                    f"{identity} 在任务窗口开始前（{first_seen} < "
                    f"{task.started_monotonic_ns}）就已存在，且既不在任务进程树内也"
                    "没有 cgroup 命中：无法确定归属，不猜测",
                )
                continue
            self._add_edge(
                node.node_id,
                task_node_id,
                EdgeBasis.RUN_ID_MARKER,
                Confidence.PROBABLE,
                f"{identity} 与任务 run_id={run_id} 相同、首次出现在任务窗口内"
                f"（{first_seen} ≥ {task.started_monotonic_ns}），但未观测到诞生事件"
                "（process.fork）也没有 cgroup 命中：只能给 PROBABLE",
            )

    # ------------------------------------------------------------------ #
    # 7–8. 副作用
    # ------------------------------------------------------------------ #

    def _effect_node_key(self, agg: _EffectAgg) -> str:
        return f"{_proc_ident(agg.run_id, agg.pid, agg.start_id)}:{agg.ident}"

    def _effect_attributes(self, agg: _EffectAgg) -> dict[str, Any]:
        common: dict[str, Any] = {
            "run_id": agg.run_id,
            "pid": agg.pid,
            "process_start_id": agg.start_id,
            "identity": agg.ident,
            "event_types": sorted(agg.event_types),
            "event_count": agg.count,
            "results": {name: agg.results[name] for name in sorted(agg.results)},
            "first_seen_monotonic_ns": agg.first_ns,
            "last_seen_monotonic_ns": agg.last_ns,
            "correlation_ids": sorted(agg.correlation_ids),
            "sample_event_ids": _sample(agg.event_ids),
        }
        if agg.kind is EvidenceNodeKind.FILE_EFFECT:
            common.update(
                {
                    "paths": sorted(agg.paths),
                    "bytes_read": agg.bytes_read,
                    "bytes_written": agg.bytes_written,
                }
            )
        else:
            common.update(
                {
                    "connection_id": agg.connection_id,
                    "protocol": agg.protocol,
                    "dest_addr": agg.dest_addr,
                    "dest_port": agg.dest_port,
                    "directions": sorted(agg.directions),
                    "bytes_total": agg.bytes_total,
                }
            )
        return common

    def _aggregate_effects(self) -> None:
        for event in self.events:
            if event.event_type in IGNORED_EVENT_TYPES:
                continue
            if event.event_type in _FILE_EVENT_TYPES:
                kind = EvidenceNodeKind.FILE_EFFECT
                ident = _file_ident(event)
            elif event.event_type in _NET_EVENT_TYPES or event.event_type is EventType.TLS_BYTES:
                kind = EvidenceNodeKind.NET_EFFECT
                ident = _net_ident(event)
            else:
                continue
            key = f"{_proc_ident(event.run_id, event.pid, event.process_start_id)}:{ident}"
            agg = self._effect_aggs.get(key)
            if agg is None:
                agg = _EffectAgg(
                    kind=kind,
                    ident=ident,
                    run_id=event.run_id,
                    pid=event.pid,
                    start_id=event.process_start_id,
                    first_ns=event.monotonic_ns,
                    last_ns=event.monotonic_ns,
                )
                self._effect_aggs[key] = agg
            else:
                agg.first_ns = min(agg.first_ns, event.monotonic_ns)
                agg.last_ns = max(agg.last_ns, event.monotonic_ns)
            agg.count += 1
            agg.event_types.add(str(event.event_type))
            agg.results[str(event.result)] = agg.results.get(str(event.result), 0) + 1
            agg.event_ids.append(event.event_id)
            if event.correlation_id:
                agg.correlation_ids.add(event.correlation_id)
            payload = event.payload
            if kind is EvidenceNodeKind.FILE_EFFECT:
                if event.event_type is EventType.FILE_RENAME:
                    agg.paths.add(payload["new_path"])
                    agg.paths.add(payload["old_path"])
                elif payload.get("path"):
                    agg.paths.add(payload["path"])
                if event.event_type is EventType.FILE_READ:
                    agg.bytes_read += payload["bytes_read"]
                elif event.event_type is EventType.FILE_WRITE:
                    agg.bytes_written += payload["bytes_written"]
            elif event.event_type is EventType.TLS_BYTES:
                agg.connection_id = payload["connection_id"]
                agg.directions.add(payload["direction"])
                agg.bytes_total += payload["bytes"]
            else:
                agg.protocol = payload["protocol"]
                agg.dest_addr = payload["dest_addr"]
                agg.dest_port = payload["dest_port"]
                agg.bytes_total += payload.get("bytes_sent", 0)

        for agg in sorted(self._effect_aggs.values(), key=_effect_sort_key):
            node = self._add_node(
                EvidenceNode.create(
                    kind=agg.kind,
                    key=self._effect_node_key(agg),
                    monotonic_ns=agg.first_ns,
                    attributes=self._effect_attributes(agg),
                )
            )
            self._effect_nodes[self._effect_node_key(agg)] = node
            for correlation_id in sorted(agg.correlation_ids):
                self._correlation_index.setdefault(correlation_id, []).append(node.node_id)
            if agg.connection_id is not None:
                self._tls_by_connection.setdefault(agg.connection_id, []).append(
                    node.node_id
                )
        for bucket in self._tls_by_connection.values():
            bucket.sort()
        for bucket in self._correlation_index.values():
            bucket.sort()

    def _build_effect_process_edges(self) -> None:
        for agg in sorted(self._effect_aggs.values(), key=_effect_sort_key):
            node = self._effect_nodes[self._effect_node_key(agg)]
            proc_node = self._proc_nodes.get((agg.run_id, agg.pid, agg.start_id))
            if proc_node is None:
                continue
            self._effect_to_process[node.node_id] = proc_node.node_id
            confidence = (
                Confidence.CERTAIN if agg.start_id is not None else Confidence.PROBABLE
            )
            evidence = [
                f"事件自带的 (pid={agg.pid}, process_start_id={agg.start_id}) 与该进程"
                f"节点身份一致；样本事件 {_sample(agg.event_ids)}"
            ]
            if agg.start_id is None:
                evidence.append(
                    "process_start_id 未采集：无法区分 PID 复用，只能给 PROBABLE"
                )
            self._add_edge(
                node.node_id,
                proc_node.node_id,
                EdgeBasis.PROCESS_LINEAGE,
                confidence,
                evidence,
            )

    # ------------------------------------------------------------------ #
    # 9–10. 调用
    # ------------------------------------------------------------------ #

    def _build_calls(self) -> None:
        seen: dict[str, int] = {}
        for record in self.calls:
            physical = record.physical_request_id
            seen[physical] = seen.get(physical, 0) + 1
            if seen[physical] > 1:
                self._note(
                    f"calls: physical_request_id={physical!r} 出现多次，只保留排序后的"
                    "第一条（确定性去重）"
                )
                continue
            tls_nodes = tuple(self._tls_by_connection.get(record.connection_id, ()))
            span_lo: int | None = None
            span_hi: int | None = None
            run_ids: set[str] = set()
            for node_id in tls_nodes:
                node = self._nodes[node_id]
                # 连接的活动区间取自该连接节点聚合的全部 tls.bytes 事件
                # （请求写入 → 响应读回），而不是只取首个事件时刻。
                low = node.attributes.get("first_seen_monotonic_ns", node.monotonic_ns)
                high = node.attributes.get("last_seen_monotonic_ns", node.monotonic_ns)
                if low is None or high is None:
                    continue
                span_lo = low if span_lo is None else min(span_lo, low)
                span_hi = high if span_hi is None else max(span_hi, high)
                run_ids.add(node.attributes["run_id"])
            usage = record.usage
            token_usage = usage.usage if usage is not None and usage.present else None
            attributes: dict[str, Any] = {
                "physical_request_id": physical,
                "logical_call_id": record.logical_call_id,
                "attempt_index": record.identity.attempt_index,
                "retry_of": record.identity.retry_of,
                "is_retry": record.identity.is_retry,
                "connection_id": record.connection_id,
                "method": record.method,
                "target": record.target,
                "status_code": record.status_code,
                "model": record.model,
                "usage_status": None if usage is None else str(usage.status),
                "input_tokens": None if token_usage is None else token_usage.input_tokens,
                "output_tokens": None
                if token_usage is None
                else token_usage.output_tokens,
                "total_tokens": None if token_usage is None else token_usage.total_tokens,
                "cost_total": None
                if record.cost is None or record.cost.total_cost is None
                else str(record.cost.total_cost),
                "cost_complete": None if record.cost is None else record.cost.complete,
                "cost_currency": None if record.cost is None else record.cost.currency,
                "transport_truncated": record.is_transport_truncated,
                "request_index": record.request_index,
                "response_index": record.response_index,
                "diagnostic_codes": sorted(
                    {str(diagnostic.code) for diagnostic in record.diagnostics}
                ),
                "anchor_monotonic_ns": span_lo,
                "anchor_run_ids": sorted(run_ids),
                "tls_event_nodes": list(tls_nodes),
            }
            node = self._add_node(
                EvidenceNode.create(
                    kind=EvidenceNodeKind.LLM_CALL,
                    key=physical,
                    monotonic_ns=span_lo,
                    attributes=attributes,
                )
            )
            self._call_aggs[node.node_id] = _CallAgg(
                node_id=node.node_id,
                record=record,
                tls_node_ids=tls_nodes,
                span_lo=span_lo,
                span_hi=span_hi,
            )
            self._call_processes[node.node_id] = set()

    def _build_call_connection_edges(self) -> None:
        if not self.config.use_connection_id:
            self._note(
                "connection_id: 已按配置关闭；调用无法用连接身份贴到系统事件上"
                "（调用级关联只能依赖辅助标记）"
            )
            return
        for node_id in sorted(self._call_aggs):
            agg = self._call_aggs[node_id]
            for tls_node_id in agg.tls_node_ids:
                tls_node = self._nodes[tls_node_id]
                proc_node_id = self._effect_to_process.get(tls_node_id)
                if proc_node_id is not None:
                    self._call_processes[node_id].add(proc_node_id)
                self._add_edge(
                    node_id,
                    tls_node_id,
                    EdgeBasis.CONNECTION_ID,
                    Confidence.CERTAIN,
                    f"tls.bytes.payload.connection_id={agg.record.connection_id!r} 与调用 "
                    f"{agg.record.physical_request_id!r} 的 connection_id 精确相等；"
                    f"该连接节点聚合了 {tls_node.attributes.get('event_count')} 个 "
                    f"tls.bytes 事件（样本 {tls_node.attributes.get('sample_event_ids')}）",
                )

    # ------------------------------------------------------------------ #
    # 11. 辅助标记
    # ------------------------------------------------------------------ #

    def _boot_offsets(self, run_id: str) -> tuple[int, int] | None:
        """同一 run 内 ``wall_time - monotonic_ns`` 的偏移区间（boot 指纹）。"""

        offsets = [
            event.wall_time - event.monotonic_ns
            for event in self.events
            if event.run_id == run_id and event.wall_time != 0
        ]
        if not offsets:
            return None
        return min(offsets), max(offsets)

    def _run_time_range(self, run_id: str) -> tuple[int, int] | None:
        times = [
            event.monotonic_ns
            for event in self.events
            if event.run_id == run_id and event.event_type not in IGNORED_EVENT_TYPES
        ]
        if not times:
            return None
        return min(times), max(times)

    def _declared_time(
        self, declaration: MarkerDeclaration
    ) -> tuple[int | None, str | None]:
        """把声明的时刻换算成 ``monotonic_ns``；跨时钟族必须显式说明。"""

        if declaration.monotonic_ns is not None:
            return declaration.monotonic_ns, None
        wall = declaration.wall_time_ns
        if wall in (None, 0):
            return None, None
        run_id = declaration.run_id
        if run_id is None:
            text = (
                "wall_clock_fallback: 声明只给了 wall_time_ns 而没有 run_id，无法确定"
                "所属 boot 的时钟偏移；放弃时间窗比较（不得跨 boot 比较）"
            )
            self._note(text)
            return None, text
        offsets = self._boot_offsets(run_id)
        if offsets is None:
            text = (
                f"wall_clock_fallback: run {run_id} 内没有带 wall_time 的事件，"
                "无法把 wall_time 换算成 monotonic；放弃时间窗比较"
            )
            self._note(text)
            return None, text
        low, high = offsets
        derived_lo = wall - high
        derived_hi = wall - low
        note = (
            f"wall_clock_fallback: 声明只给了 wall_time_ns={wall}，按 run {run_id} 的 "
            f"boot 偏移区间 [{low}, {high}] 推算 monotonic∈[{derived_lo}, "
            f"{derived_hi}]；wall_time 与 monotonic 混用属于弱证据，置信上限 PROBABLE"
        )
        observed = self._run_time_range(run_id)
        if observed is not None:
            lo = observed[0] - self.config.time_window_ns
            hi = observed[1] + self.config.time_window_ns
            if derived_hi < lo or derived_lo > hi:
                self._note(
                    f"wall_clock_fallback: 由 wall_time_ns={wall} 推算的单调时刻区间 "
                    f"[{derived_lo}, {derived_hi}] 与 run {run_id} 的观测区间 "
                    f"[{lo}, {hi}] 无交集（疑似跨 boot），已拒绝该声明的时间窗比较"
                )
                return None, None
        return derived_lo, note

    def _build_assisted_markers(self) -> None:
        declarations = () if self.markers is None else self.markers.declarations
        if not declarations:
            return
        if not self.config.use_assisted_markers:
            self._note(
                f"assisted_markers: 提供了 {len(declarations)} 条声明，但 "
                "config.use_assisted_markers=False，已全部忽略（声明不参与结论）"
            )
            return
        verdicts = [
            self._verify_declaration(declaration)
            for declaration in sorted(declarations, key=MarkerDeclaration.sort_key)
        ]
        for verdict in verdicts:
            self._emit_declaration_edges(verdict)
        for verdict in verdicts:
            self._emit_correlation_edges(verdict)
        self._emit_marker_segments(verdicts)

    def _pid_candidates(self, declaration: MarkerDeclaration) -> set[str]:
        """按 run_id + pid 过滤的进程节点（不看 start_id）。"""

        if declaration.pid is None:
            return set()
        return {
            node.node_id
            for node in self._proc_nodes.values()
            if (declaration.run_id is None or node.attributes["run_id"] == declaration.run_id)
            and node.attributes["pid"] == declaration.pid
        }

    def _exact_process_candidates(self, declaration: MarkerDeclaration) -> set[str]:
        """按 run_id + pid（若声明）+ start_id 过滤的进程节点。"""

        if declaration.process_start_id is None:
            return set()
        return {
            node.node_id
            for node in self._proc_nodes.values()
            if (declaration.run_id is None or node.attributes["run_id"] == declaration.run_id)
            and (
                declaration.pid is None or node.attributes["pid"] == declaration.pid
            )
            and node.attributes["process_start_id"] == declaration.process_start_id
        }

    def _verify_declaration(self, declaration: MarkerDeclaration) -> _DeclVerdict:
        verdict = _DeclVerdict(declaration=declaration)
        declared_evidence: list[str] = [
            "declared: " + _declaration_summary(declaration)
        ]
        system_evidence: list[str] = []

        task_targets: set[str] = set()
        if declaration.run_id is not None:
            entry = self._task_by_run.get(declaration.run_id)
            if entry is not None:
                verdict.checks["run_id"] = "verified"
                task_targets.add(entry[1])
                system_evidence.append(
                    f"system: run_id={declaration.run_id} 存在对应任务节点"
                )
            else:
                verdict.checks["run_id"] = "unverifiable"
                system_evidence.append(
                    f"system: run_id={declaration.run_id} 没有任务声明（采集缺口，非反证）"
                )

        if declaration.task_label is not None:
            labelled = [task for task in self.tasks if task.label == declaration.task_label]
            if labelled:
                verdict.checks["task_label"] = "verified"
                task_targets |= {
                    self._task_by_run[task.run_id][1] for task in labelled
                }
                system_evidence.append(
                    f"system: task_label={declaration.task_label!r} 命中 "
                    f"{len(labelled)} 个任务声明"
                )
            else:
                verdict.checks["task_label"] = "unverifiable"
                system_evidence.append(
                    f"system: task_label={declaration.task_label!r} 没有对应任务"
                    "声明（采集缺口，非反证）"
                )

        call_targets: set[str] = set()
        if declaration.call_id is not None:
            matches = {
                node_id
                for node_id, agg in self._call_aggs.items()
                if agg.record.physical_request_id == declaration.call_id
                or agg.record.logical_call_id == declaration.call_id
            }
            if matches:
                verdict.checks["call_id"] = "verified"
                call_targets |= matches
                system_evidence.append(
                    f"system: call_id={declaration.call_id} 命中调用记录 {sorted(matches)}"
                )
            else:
                verdict.checks["call_id"] = "unverifiable"
                system_evidence.append(
                    f"system: call_id={declaration.call_id} 没有对应调用记录"
                    "（可能是捕获缺口，不是反证）"
                )
        conn_calls: set[str] = set()
        if declaration.connection_id is not None:
            conn_calls = {
                node_id
                for node_id, agg in self._call_aggs.items()
                if agg.record.connection_id == declaration.connection_id
            }
            tls_nodes = set(self._tls_by_connection.get(declaration.connection_id, ()))
            if conn_calls or tls_nodes:
                verdict.checks["connection_id"] = "verified"
                system_evidence.append(
                    f"system: connection_id={declaration.connection_id} 命中 "
                    f"{len(conn_calls)} 条调用记录 / {len(tls_nodes)} 个连接节点"
                )
            else:
                verdict.checks["connection_id"] = "unverifiable"
                system_evidence.append(
                    f"system: connection_id={declaration.connection_id} 没有任何 "
                    "tls.bytes 或调用记录（可能是捕获缺口）"
                )
            if call_targets and conn_calls:
                intersection = call_targets & conn_calls
                if not intersection:
                    verdict.checks["connection_id"] = "conflict"
                    system_evidence.append(
                        "system: 声明中的 call_id 与 connection_id 指向不同的调用，"
                        "声明内部自相矛盾"
                    )
                else:
                    call_targets = intersection
            elif declaration.call_id is None and conn_calls:
                call_targets |= conn_calls

        process_targets: set[str] = set()
        if declaration.pid is not None:
            pid_candidates = self._pid_candidates(declaration)
            if pid_candidates:
                verdict.checks["pid"] = "verified"
                process_targets |= pid_candidates
                system_evidence.append(
                    f"system: pid={declaration.pid} 命中进程节点 "
                    f"{sorted(pid_candidates)}"
                )
            else:
                verdict.checks["pid"] = "conflict"
                system_evidence.append(
                    f"system: pid={declaration.pid} 在系统事件中不存在"
                    "（声明与系统证据冲突）"
                )
        if declaration.process_start_id is not None:
            exact = self._exact_process_candidates(declaration)
            if exact:
                verdict.checks["process_start_id"] = "verified"
                process_targets |= exact
                system_evidence.append(
                    f"system: process_start_id={declaration.process_start_id} 命中进程实例"
                )
            else:
                verdict.checks["process_start_id"] = "conflict"
                system_evidence.append(
                    f"system: process_start_id={declaration.process_start_id} 没有对应"
                    "进程实例（PID 复用或采集缺口；声明与系统证据冲突）"
                )

        start_ns, time_note = self._declared_time(declaration)
        wall_fallback = time_note is not None
        if declaration.monotonic_ns is not None and start_ns is not None:
            verdict.checks["monotonic_ns"] = self._verify_declared_monotonic(
                declaration, start_ns, system_evidence
            )
        elif wall_fallback and start_ns is not None:
            verdict.checks["monotonic_ns"] = "unverifiable"
        if time_note is not None and start_ns is not None:
            declared_evidence.append(time_note)
            system_evidence.append(
                "system: 声明时间由 wall_time 推算（弱证据），未做单调时钟直接比对"
            )
        elif time_note is not None:
            declared_evidence.append(time_note)
            system_evidence.append("system: 未采用声明时间做时间窗比较（见上一条说明）")
        verdict.start_ns = start_ns

        if declaration.tool_id is not None:
            # tool_id 本身是应用侧名字，系统里没有对应物；它**不参与**"全部已声明
            # 字段均已核验"的判定（否则任何未传播 correlation_id 的应用都会被永久
            # 压到 PROBABLE）。系统侧 correlation_id 命中属于额外奖励证据。
            if declaration.tool_id in self._correlation_index:
                system_evidence.append(
                    f"system: 存在 correlation_id={declaration.tool_id!r} 的系统事件"
                    "（系统侧传播的工具标记，额外交叉核验通过）"
                )
            else:
                system_evidence.append(
                    "system: 未见 correlation_id="
                    f"{declaration.tool_id!r} 的系统事件（外部可观测量里没有工具名，"
                    "属正常；工具身份依赖 call_id/进程/时间等其他已声明字段的核验）"
                )

        # "身份桥"：声明与系统之间有没有一条**独立于声明本身**的对应关系。
        # 只有桥在，声明才可能升到 CERTAIN：
        #   * connection_id 与系统里捕获到的调用/tls 事件对得上；
        #   * 系统事件携带的 correlation_id 与声明一致。
        # 只有 call_id + pid + 时间这类"应用说它们是一对"的声明，即使每项都能单独
        # 核验到存在，也只能给 PROBABLE——因为系统里没有任何东西证明这对关系。
        bridge = False
        if (
            declaration.connection_id is not None
            and verdict.checks.get("connection_id") == "verified"
            and call_targets
        ):
            bridge = True
        correlation_keys = [
            key
            for key in (declaration.call_id, declaration.tool_id)
            if key is not None and key in self._correlation_index
        ]
        if correlation_keys:
            bridge = True
            system_evidence.append(
                "system: 系统事件携带的 correlation_id 与声明的一致（"
                + ", ".join(sorted(correlation_keys))
                + "）——这是独立于声明的身份桥"
            )
        verdict.identity_bridge = bridge

        verdict.call_targets = tuple(sorted(call_targets))
        verdict.process_targets = tuple(sorted(process_targets))
        verdict.task_targets = tuple(sorted(task_targets))
        verdict.declared_evidence = tuple(declared_evidence)
        verdict.system_evidence = tuple(system_evidence)

        if "conflict" in verdict.checks.values():
            verdict.confidence = Confidence.AMBIGUOUS
        elif verdict.checks and all(
            value == "verified" for value in verdict.checks.values()
        ):
            verdict.confidence = (
                Confidence.CERTAIN if bridge else Confidence.PROBABLE
            )
        elif any(value == "verified" for value in verdict.checks.values()):
            verdict.confidence = Confidence.PROBABLE
        else:
            verdict.confidence = Confidence.UNKNOWN
        if wall_fallback:
            verdict.confidence = compose_confidence(verdict.confidence, Confidence.PROBABLE)

        if verdict.confidence is Confidence.PROBABLE and not bridge and verdict.checks:
            verdict.system_evidence = verdict.system_evidence + (
                "system: 没有可用的身份桥（既无匹配的 connection_id，也无系统侧 "
                "correlation_id），声明本身不足以给出 CERTAIN，最高 PROBABLE",
            )
        return verdict

    def _verify_declared_monotonic(
        self,
        declaration: MarkerDeclaration,
        start_ns: int,
        system_evidence: list[str],
    ) -> str:
        """声明的 ``monotonic_ns`` 是否落在系统观测区间内（± 时间窗）。"""

        anchors: list[tuple[int, int]] = []
        if declaration.run_id is not None:
            observed = self._run_time_range(declaration.run_id)
            if observed is not None:
                anchors.append(observed)
        for node_id in self._pid_candidates(declaration):
            attributes = self._nodes[node_id].attributes
            anchors.append(
                (
                    attributes["first_seen_monotonic_ns"],
                    attributes["last_seen_monotonic_ns"],
                )
            )
        if not anchors:
            system_evidence.append(
                "system: 没有可用于比对声明时刻的系统时间基准（run/进程均无观测区间）"
            )
            return "unverifiable"
        window = self.config.time_window_ns
        for low, high in sorted(anchors):
            if low - window <= start_ns <= high + window:
                system_evidence.append(
                    f"system: 声明时刻 {start_ns} 落在系统观测区间 [{low}, {high}] "
                    f"± {window}ns 内"
                )
                return "verified"
        system_evidence.append(
            f"system: 声明时刻 {start_ns} 不在任何系统观测区间内（时钟不一致或采集"
            "缺口），不做时间窗核验"
        )
        return "unverifiable"

    def _owner_call_set(self, node_id: str) -> set[str]:
        """归属节点在**调用层**上对应的调用节点集合（用于与时间窗候选比对）。"""

        node = self._nodes.get(node_id)
        if node is None:
            return set()
        if node.kind is EvidenceNodeKind.LLM_CALL:
            return {node_id}
        if node.kind is EvidenceNodeKind.TOOL_CALL:
            return set(self._tool_call_targets.get(node_id, ()))
        return set()

    def _declaration_evidence(self, verdict: _DeclVerdict) -> tuple[str, ...]:
        return verdict.declared_evidence + verdict.system_evidence

    def _create_tool_node(self, verdict: _DeclVerdict) -> str:
        declaration = verdict.declaration
        node = self._add_node(
            EvidenceNode.create(
                kind=EvidenceNodeKind.TOOL_CALL,
                key=f"tool:{declaration.identity_key()}",
                monotonic_ns=verdict.start_ns,
                attributes={
                    "tool_id": declaration.tool_id,
                    "call_id": declaration.call_id,
                    "connection_id": declaration.connection_id,
                    "run_id": declaration.run_id,
                    "declared_pid": declaration.pid,
                    "declared_process_start_id": declaration.process_start_id,
                    "declared_monotonic_ns": declaration.monotonic_ns,
                    "declared_wall_time_ns": declaration.wall_time_ns,
                    "effective_monotonic_ns": verdict.start_ns,
                    "label": declaration.label,
                    "source": declaration.source,
                    "verification": {
                        "checks": {
                            key: verdict.checks[key] for key in sorted(verdict.checks)
                        },
                        "confidence": str(verdict.confidence),
                        "declared_fields": list(declaration.declared_fields()),
                        "call_targets": list(verdict.call_targets),
                        "process_targets": list(verdict.process_targets),
                        "task_targets": list(verdict.task_targets),
                        "extra": dict(declaration.extra or {}),
                    },
                },
            )
        )
        return node.node_id

    def _declaration_confidence(self, verdict: _DeclVerdict) -> Confidence:
        """声明边的置信上限：由核验档位决定；冲突时降到 PROBABLE（冲突证据仍保留）。"""

        if verdict.confidence in (Confidence.CERTAIN, Confidence.PROBABLE):
            return verdict.confidence
        return Confidence.PROBABLE

    def _emit_multi_target_edge(
        self,
        src: str,
        targets: Sequence[str],
        basis: EdgeBasis,
        confidence: Confidence,
        evidence: Sequence[str],
    ) -> None:
        ordered = tuple(sorted({item for item in targets if item != src}))
        if not ordered:
            return
        if len(ordered) == 1:
            self._add_edge(src, ordered[0], basis, confidence, evidence)
            return
        payload = list(evidence)
        payload.append(
            f"声明指向 {len(ordered)} 个同等强度的系统候选（basis={basis}）："
            f"{list(ordered)}；全部保留，不取'最近的'当唯一归因"
        )
        self._add_ambiguous_edge(src, ordered, basis, payload)

    def _emit_declaration_edges(self, verdict: _DeclVerdict) -> None:
        declaration = verdict.declaration
        evidence = self._declaration_evidence(verdict)
        tool_node_id: str | None = None
        if declaration.tool_id is not None:
            tool_node_id = self._create_tool_node(verdict)
            self._tool_nodes[declaration.identity_key()] = tool_node_id

        # 所有声明边的置信度都**不得超过**声明的核验档位：
        # 没有身份桥（connection_id 匹配 / 系统侧 correlation_id）时上限就是
        # PROBABLE —— 声明不能单独把结论推到 CERTAIN。
        declared_confidence = self._declaration_confidence(verdict)
        if tool_node_id is not None and verdict.call_targets:
            self._tool_call_targets.setdefault(tool_node_id, set()).update(
                verdict.call_targets
            )
            self._emit_multi_target_edge(
                tool_node_id,
                verdict.call_targets,
                EdgeBasis.CALL_ID_MARKER,
                declared_confidence,
                evidence,
            )
        if tool_node_id is not None and verdict.process_targets:
            self._emit_multi_target_edge(
                tool_node_id,
                verdict.process_targets,
                EdgeBasis.TOOL_ID_MARKER,
                declared_confidence,
                evidence,
            )
        if tool_node_id is not None and verdict.task_targets:
            self._emit_multi_target_edge(
                tool_node_id,
                verdict.task_targets,
                EdgeBasis.RUN_ID_MARKER,
                declared_confidence,
                evidence,
            )
        if tool_node_id is None and verdict.call_targets:
            if verdict.process_targets:
                self._emit_multi_target_edge(
                    verdict.call_targets[0],
                    verdict.process_targets,
                    EdgeBasis.CALL_ID_MARKER,
                    declared_confidence,
                    evidence,
                )
            if verdict.task_targets:
                self._emit_multi_target_edge(
                    verdict.call_targets[0],
                    verdict.task_targets,
                    EdgeBasis.RUN_ID_MARKER,
                    declared_confidence,
                    evidence,
                )

    def _emit_correlation_edges(self, verdict: _DeclVerdict) -> None:
        """系统侧 ``correlation_id`` 与声明一致 → 双向核验通过（CERTAIN）。

        ``correlation_id`` 是**系统事件**里的字段，声明是应用侧给出的；两者相等
        才叫交叉核验，单靠任何一方都不够。
        """

        declaration = verdict.declaration
        keys = [
            key
            for key in (declaration.call_id, declaration.tool_id)
            if key is not None
        ]
        if not keys:
            return
        owner = self._tool_nodes.get(declaration.identity_key())
        if owner is None:
            if len(verdict.call_targets) == 1:
                owner = verdict.call_targets[0]
            else:
                return
        matched: set[str] = set()
        for key in keys:
            matched.update(self._correlation_index.get(key, ()))
        matched.discard(owner)
        for effect_node_id in sorted(matched):
            basis = (
                EdgeBasis.TOOL_ID_MARKER
                if declaration.tool_id in keys
                else EdgeBasis.CALL_ID_MARKER
            )
            self._add_edge(
                effect_node_id,
                owner,
                basis,
                Confidence.CERTAIN,
                (
                    "declared: " + _declaration_summary(declaration),
                    "system: 该副作用事件携带 correlation_id="
                    + ", ".join(
                        sorted(set(self._nodes[effect_node_id].attributes["correlation_ids"]))
                    )
                    + "，与声明一致（声明与系统证据双向核验通过）",
                ),
            )
            self._correlation_owned[effect_node_id] = owner
            self._marker_decided_effects.add(effect_node_id)

    def _declaration_owner(self, verdict: _DeclVerdict) -> str | None:
        declaration = verdict.declaration
        if declaration.tool_id is not None:
            return self._tool_nodes.get(declaration.identity_key())
        if len(verdict.call_targets) == 1:
            return verdict.call_targets[0]
        if len(verdict.task_targets) == 1:
            return verdict.task_targets[0]
        return None

    def _emit_marker_segments(self, verdicts: Sequence[_DeclVerdict]) -> None:
        """把声明的时间段切成互斥区间，区间内的副作用归到该声明的所有者。

        同一进程上**同一时刻**的多条声明 → 该区间的全部声明都是候选
        （``AMBIGUOUS``），不会任取一条。
        """

        grouped: dict[str, dict[int, list[_DeclVerdict]]] = {}
        for verdict in verdicts:
            if verdict.start_ns is None:
                continue
            process_keys = set(verdict.process_targets)
            # 声明与系统证据冲突（pid 不存在/PID 复用不匹配）或完全没有进程声明时，
            # 退回到"该调用所属的进程"：交集仍由系统侧的 connection_id 边给出，
            # 不是凭空猜的进程。
            if not process_keys or verdict.confidence is Confidence.AMBIGUOUS:
                for call_node_id in verdict.call_targets:
                    process_keys |= self._call_processes.get(call_node_id, set())
            if not process_keys:
                continue
            for process_node_id in process_keys:
                grouped.setdefault(process_node_id, {}).setdefault(
                    verdict.start_ns, []
                ).append(verdict)

        for process_node_id in sorted(grouped):
            starts = sorted(grouped[process_node_id])
            for index, start in enumerate(starts):
                next_start = starts[index + 1] if index + 1 < len(starts) else None
                group = grouped[process_node_id][start]
                owners: list[str] = []
                conflicted = False
                evidence: list[str] = []
                group_confidence = Confidence.CERTAIN
                for verdict in group:
                    owner = self._declaration_owner(verdict)
                    if owner is not None:
                        owners.append(owner)
                    if verdict.confidence is Confidence.AMBIGUOUS:
                        conflicted = True
                        group_confidence = compose_confidence(
                            group_confidence, Confidence.PROBABLE
                        )
                    else:
                        group_confidence = compose_confidence(
                            group_confidence, verdict.confidence
                        )
                    evidence.extend(self._declaration_evidence(verdict))
                owners = sorted(set(owners))
                if not owners:
                    continue
                effects = self._effects_in_window(process_node_id, start, next_start)
                for effect_node_id in effects:
                    self._emit_marker_effect_edge(
                        effect_node_id,
                        owners,
                        group,
                        conflicted,
                        group_confidence,
                        evidence,
                    )

    def _effects_in_window(
        self, process_node_id: str, start: int, end: int | None
    ) -> tuple[str, ...]:
        result: list[str] = []
        for node_id in sorted(self._effect_to_process):
            if self._effect_to_process[node_id] != process_node_id:
                continue
            if node_id in self._correlation_owned:
                continue
            node = self._nodes[node_id]
            if node.attributes.get("connection_id") is not None:
                continue
            if node.monotonic_ns is None or node.monotonic_ns < start:
                continue
            if end is not None and node.monotonic_ns >= end:
                continue
            result.append(node_id)
        return tuple(result)

    def _emit_marker_effect_edge(
        self,
        effect_node_id: str,
        owners: Sequence[str],
        group: Sequence[_DeclVerdict],
        conflicted: bool,
        group_confidence: Confidence,
        evidence: Sequence[str],
    ) -> None:
        declared = tuple(sorted(set(owners)))
        external = self._external_call_candidates(effect_node_id)
        payload = list(evidence)
        basis = (
            EdgeBasis.TOOL_ID_MARKER
            if any(item.declaration.tool_id is not None for item in group)
            else EdgeBasis.CALL_ID_MARKER
        )
        payload.append(
            "system: 外部时间窗候选（basis=time_window，最高只到 PROBABLE）="
            f"{list(external) if external else '（无）'}"
        )

        if len(declared) >= 2:
            payload.append(
                f"同一时间段有 {len(declared)} 条声明指向不同的所有者：{list(declared)}；"
                "声明之间无法区分，保留全部候选（工具粒度，不再混入更粗的调用候选）"
            )
            self._add_ambiguous_edge(effect_node_id, declared, basis, payload)
            self._marker_decided_effects.add(effect_node_id)
            return

        owner = declared[0]
        external_set = set(external)
        owner_calls = self._owner_call_set(owner)
        contradicts = bool(external_set) and bool(owner_calls) and not (
            owner_calls & external_set
        )
        if conflicted or contradicts:
            candidates = tuple(sorted({owner} | external_set))
            if len(candidates) >= 2:
                payload.append(
                    f"声明与系统证据不一致：声明指向 {owner}（其调用 "
                    f"{sorted(owner_calls) if owner_calls else '未知'}），系统时间窗候选"
                    f"为 {list(external)}；降级为 AMBIGUOUS，声明与系统证据都保留"
                )
                self._add_ambiguous_edge(effect_node_id, candidates, basis, payload)
            else:
                payload.append(
                    f"声明与系统证据冲突（声明指向 {owner}）但没有替代候选：降级为 "
                    "PROBABLE，声明与系统证据都保留"
                )
                self._add_edge(
                    effect_node_id,
                    owner,
                    basis,
                    Confidence.PROBABLE,
                    payload,
                )
            self._marker_decided_effects.add(effect_node_id)
            return

        if not external_set:
            payload.append(
                "system: 没有可用的时间窗候选集合可交叉核验（连接身份被关闭或无 "
                "tls.bytes 事件），结论只由声明的核验档位决定"
            )
        payload.append(
            f"声明与系统证据交叉核验通过：所有者 {owner}（其调用 "
            f"{sorted(owner_calls) if owner_calls else '未知'} ⊆ 时间窗候选）"
        )
        self._add_edge(effect_node_id, owner, basis, group_confidence, payload)
        self._marker_decided_effects.add(effect_node_id)

    # ------------------------------------------------------------------ #
    # 12. 外部调用的副作用归属
    # ------------------------------------------------------------------ #

    def _call_span(self, call_node_id: str) -> tuple[int, int] | None:
        agg = self._call_aggs.get(call_node_id)
        if agg is None or agg.span_lo is None or agg.span_hi is None:
            return None
        return agg.span_lo, agg.span_hi

    def _external_call_candidates(self, effect_node_id: str) -> tuple[str, ...]:
        if not (self.config.use_time_window and self.config.use_connection_id):
            return ()
        process_node_id = self._effect_to_process.get(effect_node_id)
        if process_node_id is None:
            return ()
        effect = self._nodes[effect_node_id]
        if effect.monotonic_ns is None:
            return ()
        window = self.config.time_window_ns
        result: list[str] = []
        for call_node_id in sorted(self._call_aggs):
            if process_node_id not in self._call_processes.get(call_node_id, ()):
                continue
            span = self._call_span(call_node_id)
            if span is None:
                continue
            if span[0] - window <= effect.monotonic_ns <= span[1] + window:
                result.append(call_node_id)
        return tuple(result)

    def _build_external_effect_call_edges(self) -> None:
        if not (self.config.use_time_window and self.config.use_connection_id):
            return
        for node_id in sorted(self._effect_to_process):
            node = self._nodes[node_id]
            if node.kind not in (
                EvidenceNodeKind.FILE_EFFECT,
                EvidenceNodeKind.NET_EFFECT,
            ):
                continue
            if node.attributes.get("connection_id") is not None:
                # 连接节点代表连接本身（可能被多个调用复用）；把它归因到单个调用
                # 只会制造虚假歧义。它的归属由调用侧的 CONNECTION_ID 边表达。
                continue
            if node_id in self._marker_decided_effects:
                continue
            candidates = self._external_call_candidates(node_id)
            if not candidates:
                continue
            process = self._nodes[self._effect_to_process[node_id]]
            base = [
                f"时间窗（basis=time_window，最高只给 PROBABLE）：副作用时刻 "
                f"{node.monotonic_ns} 落在调用的连接活动区间 ± "
                f"{self.config.time_window_ns}ns 内",
                f"同一进程 pid={process.attributes['pid']}, "
                f"process_start_id={process.attributes['process_start_id']}"
                f"（run {process.attributes['run_id']}）",
            ]
            if len(candidates) == 1:
                span = self._call_span(candidates[0])
                self._add_edge(
                    node_id,
                    candidates[0],
                    EdgeBasis.TIME_WINDOW,
                    Confidence.PROBABLE,
                    base
                    + [
                        f"唯一候选：调用节点 {candidates[0]}（连接活动区间 {span}）；"
                        "时间接近本身不足以给出确定性归因"
                    ],
                )
                continue
            payload = list(base)
            payload.append(
                f"同一进程内有 {len(candidates)} 个调用候选：{list(candidates)}；"
                "外部模式无法区分，保留全部候选（不取最近的当唯一归因）"
            )
            self._add_ambiguous_edge(
                node_id, candidates, EdgeBasis.TIME_WINDOW, payload
            )

    # ------------------------------------------------------------------ #
    # 13. 进程 → 容器
    # ------------------------------------------------------------------ #

    def _build_process_container_edges(self) -> None:
        for run_id in sorted(self._container_nodes):
            container_node_id = self._container_nodes[run_id]
            info = self._container_infos[run_id]
            host_pid = info["host_pid"]
            cgroup_id = info["cgroup_id"]
            for node in sorted(self._proc_nodes.values(), key=lambda item: item.node_id):
                if node.attributes["run_id"] != run_id:
                    continue
                evidence: list[str] = []
                confidence = Confidence.CERTAIN
                if cgroup_id is not None and node.attributes.get("cgroup_id") == cgroup_id:
                    evidence.append(
                        f"ContainerResolver.resolve_cgroup_id({info['container_id']!r})"
                        f"={cgroup_id} 与进程 cgroup_id 精确相同"
                    )
                if host_pid is not None and node.attributes["pid"] == host_pid:
                    siblings = self._pid_nodes(run_id, host_pid)
                    evidence.append(
                        f"ContainerResolver.resolve_host_pid({info['container_id']!r})"
                        f"={host_pid} 与该进程的 pid 命中"
                    )
                    if len(siblings) > 1:
                        confidence = compose_confidence(confidence, Confidence.PROBABLE)
                        evidence.append(
                            f"PID 复用：run 内 pid={host_pid} 有 {len(siblings)} 个进程"
                            "实例，无法确定哪一个是容器入口"
                        )
                if not evidence:
                    continue
                self._add_edge(
                    node.node_id,
                    container_node_id,
                    EdgeBasis.CONTAINER_MAPPING,
                    confidence,
                    evidence,
                )


def build_graph(
    *,
    events: Sequence[Event],
    calls: Sequence[LlmCallRecord],
    tasks: Sequence[Any],
    markers: AssistantMarkers | None,
    config: CorrelationConfig,
    container_resolver: ContainerResolver | None,
) -> GraphBuild:
    """构建证据图（纯函数：无 IO、无网络、无全局状态）。"""

    return _GraphBuilder(
        events=events,
        calls=calls,
        tasks=tasks,
        markers=markers,
        config=config,
        container_resolver=container_resolver,
    ).build()
