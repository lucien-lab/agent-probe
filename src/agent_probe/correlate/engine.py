"""关联引擎门面：``correlate`` / ``explain`` / 真值评估 / 消融报告。

算法在 :mod:`agent_probe.correlate.graph`，数据模型在
:mod:`agent_probe.correlate.model`。本模块只做三件事：

1. **任务级归因合成**（:func:`resolve_attribution`）：在证据图上自下而上走边，
   把"节点 → 任务"的路径合成成
   :class:`~agent_probe.correlate.model.NodeAttribution`。合成规则是"取最弱
   一环"，且**候选唯一性优先于强度**：两个 CERTAIN 候选仍然是 AMBIGUOUS。
2. **统计口径**（:func:`evaluate_against_truth`）：精确率/召回率只在真值存在时
   计算；确定归因覆盖率与歧义率的分母是"除 TASK 之外的全部节点"，未知归因
   **不得**从召回分母里删除。
3. **消融**（:func:`ablation_report`）：全开基线 vs 逐个关闭一个开关，
   输出每项的 :class:`~agent_probe.correlate.model.AttributionStats`。

本模块**不做因果推断**：所有结论都以边上的 ``basis``/``evidence`` 为依据，
没有证据就是 ``UNKNOWN``。
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from typing import Any

from agent_probe.events import Event
from agent_probe.llm import LlmCallRecord

from .errors import CorrelationInputError, CorrelationNotFoundError
from .graph import build_graph
from .markers import AssistantMarkers
from .model import (
    BASIS_EXPLANATIONS,
    CONFIDENCE_BY_RANK,
    CONFIDENCE_EXPLANATIONS,
    CONFIDENCE_RANK,
    Ambiguity,
    AttributionStats,
    Confidence,
    ContainerResolver,
    CorrelationConfig,
    CorrelationResult,
    EdgeBasis,
    EvidenceEdge,
    EvidenceNode,
    EvidenceNodeKind,
    NodeAttribution,
    Task,
    compose_confidence,
)

__all__ = [
    "CorrelationEngine",
    "explain",
    "resolve_attribution",
    "node_attribution",
    "evaluate_against_truth",
    "ablation_report",
    "ABLATION_SWITCHES",
]

#: 消融开关的固定顺序（报告中键名与顺序都来自它）。
ABLATION_SWITCHES: tuple[str, ...] = (
    "use_time_window",
    "use_process_lineage",
    "use_connection_id",
    "use_container_mapping",
    "use_assisted_markers",
)

#: 归因路径的最大深度（防护性上限；正常证据图深度 ≤ 5）。
_MAX_PATH_DEPTH = 12


# --------------------------------------------------------------------------- #
# 归因合成
# --------------------------------------------------------------------------- #


def resolve_attribution(
    nodes: Mapping[str, EvidenceNode] | Sequence[EvidenceNode],
    edges: Sequence[EvidenceEdge],
) -> dict[str, NodeAttribution]:
    """把证据图合成为"节点 → 任务"的归因结论。

    合成规则：

    * 路径置信 = 路径上各边置信的**最弱一环**（:func:`compose_confidence`）。
    * 到达同一个任务的多条路径取最强的一条（同强度取更短的）。
    * 最终：最高强度的候选**唯一**时才是有唯一归因；两个同等强度的候选
      → ``AMBIGUOUS``（即使两个都是 ``CERTAIN``）。全部候选都是
      ``UNKNOWN`` → ``UNKNOWN``。
    """

    node_map = (
        dict(nodes) if isinstance(nodes, Mapping) else {node.node_id: node for node in nodes}
    )
    task_ids = {
        node_id for node_id, node in node_map.items() if node.kind is EvidenceNodeKind.TASK
    }
    outgoing: dict[str, list[EvidenceEdge]] = {}
    for edge in edges:
        outgoing.setdefault(edge.src_node_id, []).append(edge)
    for bucket in outgoing.values():
        bucket.sort(key=lambda item: item.edge_id)

    attributions: dict[str, NodeAttribution] = {}
    for node_id in sorted(node_map):
        node = node_map[node_id]
        if node.kind is EvidenceNodeKind.TASK:
            attributions[node_id] = NodeAttribution(
                node_id=node_id,
                confidence=Confidence.CERTAIN,
                targets=(node_id,),
                primary=node_id,
                path=(),
            )
            continue

        reached: dict[str, tuple[Confidence, tuple[str, ...]]] = {}
        stack: list[tuple[str, Confidence, tuple[str, ...], frozenset[str], int]] = [
            (node_id, Confidence.CERTAIN, (), frozenset({node_id}), 0)
        ]
        while stack:
            current, confidence, path, visited, depth = stack.pop()
            if current != node_id and current in task_ids:
                previous = reached.get(current)
                candidate = (confidence, path)
                if (
                    previous is None
                    or CONFIDENCE_RANK[candidate[0]] > CONFIDENCE_RANK[previous[0]]
                    or (
                        CONFIDENCE_RANK[candidate[0]] == CONFIDENCE_RANK[previous[0]]
                        and len(candidate[1]) < len(previous[1])
                    )
                ):
                    reached[current] = candidate
                continue
            if depth >= _MAX_PATH_DEPTH:
                continue
            for edge in outgoing.get(current, ()):
                if edge.dst_node_id in visited or edge.dst_node_id not in node_map:
                    continue
                stack.append(
                    (
                        edge.dst_node_id,
                        compose_confidence(confidence, edge.confidence),
                        path + (edge.edge_id,),
                        visited | {edge.dst_node_id},
                        depth + 1,
                    )
                )

        if not reached:
            attributions[node_id] = NodeAttribution(
                node_id=node_id,
                confidence=Confidence.UNKNOWN,
                targets=(),
                primary=None,
                path=(),
            )
            continue
        top_rank = max(CONFIDENCE_RANK[value[0]] for value in reached.values())
        winners = tuple(
            sorted(
                target
                for target, value in reached.items()
                if CONFIDENCE_RANK[value[0]] == top_rank
            )
        )
        strongest = next(iter(winners))
        if top_rank == CONFIDENCE_RANK[Confidence.UNKNOWN]:
            confidence = Confidence.UNKNOWN
        elif len(winners) == 1:
            confidence = CONFIDENCE_BY_RANK[top_rank]
        else:
            confidence = Confidence.AMBIGUOUS
        attributions[node_id] = NodeAttribution(
            node_id=node_id,
            confidence=confidence,
            targets=winners,
            primary=strongest,
            path=reached[strongest][1],
        )
    return attributions


def node_attribution(result: CorrelationResult, node_id: str) -> NodeAttribution:
    """单个节点的任务级归因（查不到抛 :class:`CorrelationNotFoundError`）。"""

    nodes = result.node_by_id()
    if node_id not in nodes:
        raise CorrelationNotFoundError(f"结果中没有节点 {node_id!r}")
    return resolve_attribution(nodes, result.edges)[node_id]


# --------------------------------------------------------------------------- #
# 统计
# --------------------------------------------------------------------------- #


def _build_stats(
    nodes: Sequence[EvidenceNode], edges: Sequence[EvidenceEdge]
) -> AttributionStats:
    attributions = resolve_attribution({node.node_id: node for node in nodes}, edges)
    task_total = sum(1 for node in nodes if node.kind is EvidenceNodeKind.TASK)
    counts = {confidence: 0 for confidence in Confidence}
    total = 0
    for node in nodes:
        if node.kind is EvidenceNodeKind.TASK:
            continue
        total += 1
        counts[attributions[node.node_id].confidence] += 1
    determinate = counts[Confidence.CERTAIN] + counts[Confidence.PROBABLE]
    edge_counts = {confidence: 0 for confidence in Confidence}
    for edge in edges:
        edge_counts[edge.confidence] += 1
    return AttributionStats(
        tasks_total=task_total,
        nodes_total=total,
        nodes_certain=counts[Confidence.CERTAIN],
        nodes_probable=counts[Confidence.PROBABLE],
        nodes_ambiguous=counts[Confidence.AMBIGUOUS],
        nodes_unknown=counts[Confidence.UNKNOWN],
        determinate_coverage=0.0 if total == 0 else determinate / total,
        ambiguity_rate=0.0 if total == 0 else counts[Confidence.AMBIGUOUS] / total,
        precision=None,
        recall=None,
        f1=None,
        edges_total=len(edges),
        edges_certain=edge_counts[Confidence.CERTAIN],
        edges_probable=edge_counts[Confidence.PROBABLE],
        edges_ambiguous=edge_counts[Confidence.AMBIGUOUS],
        edges_unknown=edge_counts[Confidence.UNKNOWN],
    )


def _collect_ambiguities(
    nodes: Sequence[EvidenceNode],
    edges: Sequence[EvidenceEdge],
    attributions: Mapping[str, NodeAttribution],
) -> tuple[Ambiguity, ...]:
    items: list[Ambiguity] = []
    for node in nodes:
        attribution = attributions[node.node_id]
        if node.kind is EvidenceNodeKind.TASK:
            continue
        if attribution.confidence is Confidence.AMBIGUOUS and len(attribution.targets) >= 2:
            items.append(
                Ambiguity(
                    node_id=node.node_id,
                    candidates=attribution.targets,
                    reason=(
                        "任务级归因存在 "
                        f"{len(attribution.targets)} 个同等强度的候选任务"
                        f"（{list(attribution.targets)}）；候选全部保留"
                    ),
                )
            )
    for edge in edges:
        if edge.confidence is not Confidence.AMBIGUOUS:
            continue
        candidates = tuple(sorted({edge.dst_node_id, *edge.candidates}))
        items.append(
            Ambiguity(
                edge_id=edge.edge_id,
                candidates=candidates,
                reason=(
                    f"basis={edge.basis}：{len(candidates)} 个候选无法区分"
                    f"（src={edge.src_node_id}）；dst 只是确定性占位"
                ),
            )
        )
    items.sort(
        key=lambda item: (
            0 if item.node_id is not None else 1,
            item.node_id or item.edge_id or "",
            item.reason,
        )
    )
    return tuple(items)


# --------------------------------------------------------------------------- #
# 真值评估
# --------------------------------------------------------------------------- #


def _truth_aliases(nodes: Mapping[str, EvidenceNode]) -> dict[str, str]:
    """真值里可以用 ``node_id`` / ``run_id`` / ``label`` 指代任务。"""

    aliases: dict[str, str] = {}
    for node_id in sorted(nodes):
        node = nodes[node_id]
        if node.kind is not EvidenceNodeKind.TASK:
            continue
        aliases[node_id] = node_id
        run_id = node.attributes.get("run_id")
        if isinstance(run_id, str):
            aliases.setdefault(run_id, node_id)
        label = node.attributes.get("label")
        if isinstance(label, str) and label:
            aliases.setdefault(label, node_id)
    return aliases


def evaluate_against_truth(
    result: CorrelationResult, truth: Mapping[str, str]
) -> AttributionStats:
    """用真值给结果打分，返回**填好** precision/recall/f1 的统计。

    真值形如 ``{node_id: 任务}``，任务可以是任务 ``node_id``、``run_id`` 或
    ``label``。

    口径（必须与覆盖率一起解释）：

    * 分母：真值里除 TASK 节点以外的**全部**条目（结果里不存在的算漏检，
      ``UNKNOWN`` 归因的算错，二者都不从分母里删除）。
    * precision 分母：真值里存在的节点中"给出了唯一归因"的那些；一个都没给出
      时 precision 为 ``None``（没有给出关联，不是 0 精确率）。
    * recall 分母：全部真值条目数；没有真值时 precision/recall/f1 均为 ``None``。
    """

    nodes = result.node_by_id()
    attributions = resolve_attribution(nodes, result.edges)
    aliases = _truth_aliases(nodes)

    entries: list[tuple[str, str]] = []
    for node_id in sorted(truth):
        node = nodes.get(node_id)
        if node is not None and node.kind is EvidenceNodeKind.TASK:
            continue
        entries.append((node_id, aliases.get(truth[node_id], truth[node_id])))
    if not entries:
        return replace(result.stats, precision=None, recall=None, f1=None)

    claimed = 0
    correct = 0
    for node_id, target in entries:
        node = nodes.get(node_id)
        if node is None:
            continue
        attribution = attributions[node_id]
        if not attribution.determinate:
            continue
        claimed += 1
        if attribution.primary == target:
            correct += 1

    recall = correct / len(entries)
    precision = None if claimed == 0 else correct / claimed
    return result.stats.with_scores(precision=precision, recall=recall)


# --------------------------------------------------------------------------- #
# 引擎
# --------------------------------------------------------------------------- #


class CorrelationEngine:
    """可解释行为关联引擎（用户态、离线可测、无 IO）。

    典型用法::

        engine = CorrelationEngine(
            CorrelationConfig(use_assisted_markers=True),
            container_resolver=my_resolver,   # 可选，属于调用方
        )
        result = engine.correlate(events, calls=[call], tasks=[task], markers=markers)
        result.stats.determinate_coverage, result.stats.ambiguity_rate
        engine.explain(result, node_id=some_node_id)

    容器归属**只**通过注入的
    :class:`~agent_probe.correlate.model.ContainerResolver` 获得；本类不会
    import ``agent_probe.container``，也不会自己去查 Docker。
    """

    def __init__(
        self,
        config: CorrelationConfig | None = None,
        container_resolver: ContainerResolver | None = None,
    ) -> None:
        self._config = config if config is not None else CorrelationConfig()
        if not isinstance(self._config, CorrelationConfig):
            raise CorrelationInputError(
                f"config 必须是 CorrelationConfig，实际为 {type(config).__name__}"
            )
        if container_resolver is not None and not isinstance(
            container_resolver, ContainerResolver
        ):
            raise CorrelationInputError(
                "container_resolver 必须实现 ContainerResolver（resolve_host_pid / "
                "resolve_cgroup_id）"
            )
        self._resolver = container_resolver

    # -- 访问器 ------------------------------------------------------------- #

    @property
    def config(self) -> CorrelationConfig:
        return self._config

    @property
    def container_resolver(self) -> ContainerResolver | None:
        return self._resolver

    # -- 主入口 ------------------------------------------------------------- #

    def correlate(
        self,
        events: Sequence[Event] | None,
        calls: Sequence[LlmCallRecord] = (),
        tasks: Sequence[Task] = (),
        markers: AssistantMarkers | None = None,
    ) -> CorrelationResult:
        """构建证据图并返回可序列化的结果。

        ``events``/``calls``/``tasks`` 的元素类型会被显式校验；不匹配就抛
        :class:`~agent_probe.correlate.errors.CorrelationInputError`（不做宽容
        转换，避免"看起来能跑"的错误输入静默产出错误结论）。
        """

        event_list = _validate_events(events)
        call_list = _validate_calls(calls)
        task_list = _validate_tasks(tasks)
        marker_set = _validate_markers(markers)

        build = build_graph(
            events=event_list,
            calls=call_list,
            tasks=task_list,
            markers=marker_set,
            config=self._config,
            container_resolver=self._resolver,
        )
        attributions = resolve_attribution(
            {node.node_id: node for node in build.nodes}, build.edges
        )
        stats = _build_stats(build.nodes, build.edges)
        ambiguities = _collect_ambiguities(build.nodes, build.edges, attributions)
        return CorrelationResult(
            nodes=build.nodes,
            edges=build.edges,
            ambiguities=ambiguities,
            stats=stats,
            config=self._config,
            notes=build.notes,
        )

    # -- 解释 --------------------------------------------------------------- #

    def explain(
        self,
        result: CorrelationResult,
        *,
        node_id: str | None = None,
        edge_id: str | None = None,
    ) -> dict[str, Any]:
        """解释整份结果、某个节点或某条边（返回 JSON 可序列化字典）。"""

        return explain(result, node_id=node_id, edge_id=edge_id)

    # -- 消融 --------------------------------------------------------------- #

    def ablation_report(
        self,
        events: Sequence[Event] | None,
        calls: Sequence[LlmCallRecord] = (),
        tasks: Sequence[Task] = (),
        truths: Mapping[str, str] | None = None,
        *,
        markers: AssistantMarkers | None = None,
    ) -> dict[str, AttributionStats]:
        """全开基线 vs 逐个关闭一个开关，返回每项的统计。"""

        return ablation_report(
            events,
            calls,
            tasks,
            truths,
            markers=markers,
            config=self._config,
            container_resolver=self._resolver,
        )


def _validate_events(events: Sequence[Event] | None) -> tuple[Event, ...]:
    if events is None:
        return ()
    result = tuple(events)
    for index, item in enumerate(result):
        if not isinstance(item, Event):
            raise CorrelationInputError(
                f"events[{index}] 必须是 Event，实际为 {type(item).__name__}"
            )
    return result


def _validate_calls(calls: Sequence[LlmCallRecord] | None) -> tuple[LlmCallRecord, ...]:
    if calls is None:
        return ()
    result = tuple(calls)
    for index, item in enumerate(result):
        if not isinstance(item, LlmCallRecord):
            raise CorrelationInputError(
                f"calls[{index}] 必须是 LlmCallRecord，实际为 {type(item).__name__}"
            )
    return result


def _validate_tasks(tasks: Sequence[Task] | None) -> tuple[Task, ...]:
    if tasks is None:
        return ()
    result = tuple(tasks)
    for index, item in enumerate(result):
        if not isinstance(item, Task):
            raise CorrelationInputError(
                f"tasks[{index}] 必须是 Task，实际为 {type(item).__name__}"
            )
    return result


def _validate_markers(markers: AssistantMarkers | None) -> AssistantMarkers | None:
    if markers is None:
        return None
    if isinstance(markers, AssistantMarkers):
        return markers
    if isinstance(markers, Mapping) or isinstance(markers, Iterable) and not isinstance(
        markers, (str, bytes)
    ):
        raise CorrelationInputError(
            "markers 必须是 AssistantMarkers；请先用 AssistantMarkers.from_records(...) "
            "或 AssistantMarkers.from_dict(...) 显式构造"
        )
    raise CorrelationInputError(
        f"markers 必须是 AssistantMarkers 或 None，实际为 {type(markers).__name__}"
    )


# --------------------------------------------------------------------------- #
# 消融
# --------------------------------------------------------------------------- #


def ablation_report(
    events: Sequence[Event] | None,
    calls: Sequence[LlmCallRecord] = (),
    tasks: Sequence[Task] = (),
    truths: Mapping[str, str] | None = None,
    *,
    markers: AssistantMarkers | None = None,
    config: CorrelationConfig | None = None,
    container_resolver: ContainerResolver | None = None,
) -> dict[str, AttributionStats]:
    """消融实验：``baseline``（全部开关打开）+ 每个开关单独关闭一项。

    键名固定为 ``baseline`` 与 ``without_<开关名>``（见 :data:`ABLATION_SWITCHES`），
    顺序与 :data:`ABLATION_SWITCHES` 一致，便于 M6 直接落表。

    注意：基线是"全部打开"，因此 ``use_assisted_markers`` 在基线里也是打开的
    （配置默认值是关闭——默认值服务常规关联，基线服务消融对比）。
    """

    base = config if config is not None else CorrelationConfig()
    if not isinstance(base, CorrelationConfig):
        raise CorrelationInputError("config 必须是 CorrelationConfig")
    baseline = replace(base, use_assisted_markers=True)

    report: dict[str, AttributionStats] = {}
    engine = CorrelationEngine(baseline, container_resolver)
    result = engine.correlate(events, calls, tasks, markers)
    report["baseline"] = (
        result.stats
        if truths is None
        else evaluate_against_truth(result, truths)
    )
    for name in ABLATION_SWITCHES:
        variant = baseline.with_switch(name, False)
        variant_engine = CorrelationEngine(variant, container_resolver)
        variant_result = variant_engine.correlate(events, calls, tasks, markers)
        report[f"without_{name}"] = (
            variant_result.stats
            if truths is None
            else evaluate_against_truth(variant_result, truths)
        )
    return report


# --------------------------------------------------------------------------- #
# explain
# --------------------------------------------------------------------------- #


def _node_view(node: EvidenceNode) -> dict[str, Any]:
    return {
        "node_id": node.node_id,
        "kind": str(node.kind),
        "key": node.key,
        "monotonic_ns": node.monotonic_ns,
        "attributes": node.attributes,
    }


def _edge_view(result: CorrelationResult, edge: EvidenceEdge) -> dict[str, Any]:
    nodes = result.node_by_id()
    return {
        "edge_id": edge.edge_id,
        "direction": "边的方向是'被归属者 → 归属者'（自下而上）：src 归属于 dst",
        "src": _node_view(nodes[edge.src_node_id])
        if edge.src_node_id in nodes
        else {"node_id": edge.src_node_id},
        "dst": _node_view(nodes[edge.dst_node_id])
        if edge.dst_node_id in nodes
        else {"node_id": edge.dst_node_id},
        "basis": str(edge.basis),
        "basis_explanation": BASIS_EXPLANATIONS[edge.basis],
        "method_version": edge.method_version,
        "confidence": str(edge.confidence),
        "confidence_explanation": CONFIDENCE_EXPLANATIONS[edge.confidence],
        "evidence": list(edge.evidence),
        "candidates": [
            _node_view(nodes[item]) if item in nodes else {"node_id": item}
            for item in edge.candidates
        ],
        "candidate_ids": list(edge.candidates),
        "meaning": _edge_meaning(edge),
    }


def _edge_meaning(edge: EvidenceEdge) -> str:
    if edge.confidence is Confidence.CERTAIN:
        return "精确标识匹配且候选唯一，可以当作确定归因使用。"
    if edge.confidence is Confidence.PROBABLE:
        return "系统证据方向一致、候选唯一，但不是精确标识匹配；报告里必须与覆盖率一起看。"
    if edge.confidence is Confidence.AMBIGUOUS:
        return (
            "存在多个同等强度候选：不得择一使用。dst 只是确定性占位，"
            f"真实候选为 {[edge.dst_node_id, *edge.candidates]}。"
        )
    return "证据不足：这条边只表示'方向可能成立'，不能当作归因结论。"


def _summary_view(result: CorrelationResult) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    for node in result.nodes:
        by_kind[str(node.kind)] = by_kind.get(str(node.kind), 0) + 1
    by_basis: dict[str, int] = {}
    by_confidence: dict[str, int] = {}
    for edge in result.edges:
        by_basis[str(edge.basis)] = by_basis.get(str(edge.basis), 0) + 1
        by_confidence[str(edge.confidence)] = by_confidence.get(str(edge.confidence), 0) + 1
    return {
        "mode": result.mode,
        "method_version": result.config.method_version,
        "nodes_by_kind": {key: by_kind[key] for key in sorted(by_kind)},
        "edges_by_basis": {key: by_basis[key] for key in sorted(by_basis)},
        "edges_by_confidence": {
            key: by_confidence[key] for key in sorted(by_confidence)
        },
        "ambiguities": len(result.ambiguities),
        "stats": result.stats.to_dict(),
        "notes": list(result.notes),
    }


def explain(
    result: CorrelationResult,
    *,
    node_id: str | None = None,
    edge_id: str | None = None,
) -> dict[str, Any]:
    """解释整份结果、某个节点或某条边。

    * 都不给 → 结果摘要（模式、方法版本、各类计数、统计、notes）。
    * ``node_id`` → 节点内容、任务级归因（含路径）、出边/入边逐条解释、
      与该节点相关的歧义记录。
    * ``edge_id`` → 该边完整内容、依据与置信度的定义、全部候选及其节点摘要。

    每一类边（7 种 ``basis``）都能被解释：``basis_explanation`` 直接来自
    :data:`~agent_probe.correlate.model.BASIS_EXPLANATIONS`。
    """

    if node_id is not None and edge_id is not None:
        raise CorrelationInputError("explain 一次只能解释一个 node_id 或 edge_id")
    nodes = result.node_by_id()
    edges = result.edge_by_id()
    payload: dict[str, Any] = {
        "method_version": result.config.method_version,
        "mode": result.mode,
        "config": result.config.to_dict(),
        "summary": _summary_view(result),
        "basis_guide": {str(key): BASIS_EXPLANATIONS[key] for key in EdgeBasis},
        "confidence_guide": {
            str(key): CONFIDENCE_EXPLANATIONS[key] for key in Confidence
        },
    }

    if edge_id is not None:
        edge = edges.get(edge_id)
        if edge is None:
            raise CorrelationNotFoundError(f"结果中没有边 {edge_id!r}")
        payload["edge"] = _edge_view(result, edge)
        return payload

    if node_id is not None:
        node = nodes.get(node_id)
        if node is None:
            raise CorrelationNotFoundError(f"结果中没有节点 {node_id!r}")
        attribution = resolve_attribution(nodes, result.edges)[node_id]
        payload["node"] = _node_view(node)
        payload["attribution"] = {
            "confidence": str(attribution.confidence),
            "confidence_explanation": CONFIDENCE_EXPLANATIONS[attribution.confidence],
            "determinate": attribution.determinate,
            "targets": list(attribution.targets),
            "primary": attribution.primary,
            "path_edge_ids": list(attribution.path),
            "path": [
                {
                    "edge_id": item,
                    "src_node_id": edges[item].src_node_id,
                    "dst_node_id": edges[item].dst_node_id,
                    "basis": str(edges[item].basis),
                    "confidence": str(edges[item].confidence),
                    "evidence": list(edges[item].evidence),
                }
                for item in attribution.path
                if item in edges
            ],
            "note": (
                "UNKNOWN 表示没有可用证据；AMBIGUOUS 表示多个同等强度候选，"
                "primary 只是确定性占位，不代表归因成立。"
            ),
        }
        payload["outgoing"] = [
            _edge_view(result, edge) for edge in result.outgoing(node_id)
        ]
        payload["incoming"] = [
            _edge_view(result, edge) for edge in result.incoming(node_id)
        ]
        related_edges = {edge.edge_id for edge in result.outgoing(node_id)} | {
            edge.edge_id for edge in result.incoming(node_id)
        }
        payload["ambiguities"] = [
            item.to_dict()
            for item in result.ambiguities
            if item.node_id == node_id or item.edge_id in related_edges
        ]
        payload["attribution_candidates"] = [
            _node_view(nodes[item]) if item in nodes else {"node_id": item}
            for item in attribution.targets
        ]
        return payload

    payload["hint"] = (
        "传入 node_id 或 edge_id 可以展开单个节点/边的证据；"
        "attribution.determinate=False 时不得把 primary 当成唯一归因。"
    )
    return payload
