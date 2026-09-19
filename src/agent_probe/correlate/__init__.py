"""``agent_probe.correlate``：M3 的可解释行为关联引擎（库层，不接入 CLI）。

回答的问题：**"这条系统事件/这次 LLM 调用，属于哪个任务？依据是什么？
有多确定？"** 本子包只做**带证据的关联**，不做因果推断，也不做容器查询本身
（Docker 查询由调用方通过 :class:`ContainerResolver` 注入）。

模块划分
--------

``model``
    证据图数据模型：:class:`Task`、:class:`EvidenceNode`、
    :class:`EvidenceEdge`、:class:`Confidence`、:class:`EdgeBasis`、
    :class:`CorrelationConfig`、:class:`CorrelationResult`、
    :class:`AttributionStats`、:class:`ContainerResolver`。
``markers``
    辅助模式的输入：:class:`AssistantMarkers` / :class:`MarkerDeclaration`
    （应用侧**声明**，必须与系统事件交叉核验）。
``graph``
    证据图构建算法（外部模式 + 辅助模式）。
``engine``
    门面：:class:`CorrelationEngine`、:func:`evaluate_against_truth`、
    :func:`ablation_report`、:func:`explain`。

最小用法::

    from agent_probe.correlate import (
        AssistantMarkers, CorrelationConfig, CorrelationEngine, Task,
    )

    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    result = engine.correlate(events, calls=[call], tasks=[task], markers=markers)
    result.stats.determinate_coverage, result.stats.ambiguity_rate
    engine.explain(result, node_id=result.nodes[0].node_id)

三条硬约束（代码与文档同源，见 ``docs/03-correlation.md``）：

1. 每条边都带 ``basis`` + ``method_version`` + ``confidence`` + ``evidence``。
2. 不确定就输出 ``AMBIGUOUS``/``UNKNOWN``，且 ``AMBIGUOUS`` 必须保留全部候选；
   禁止"取时间最近的那个"当唯一归因。
3. 同输入产出逐字节相同的结果（ID 由内容哈希派生，无 ``id()``/时间/随机数/
   字典顺序依赖）。

容器归属**只**来自注入的 :class:`ContainerResolver`；本包不 import
``agent_probe.container``，也不调用 Docker。
"""

from __future__ import annotations

from .engine import (
    ABLATION_SWITCHES,
    CorrelationEngine,
    ablation_report,
    evaluate_against_truth,
    explain,
    node_attribution,
    resolve_attribution,
)
from .errors import (
    CorrelationError,
    CorrelationInputError,
    CorrelationLimitError,
    CorrelationNotFoundError,
)
from .graph import IGNORED_EVENT_TYPES, GraphBuild, build_graph
from .markers import AssistantMarkers, MarkerDeclaration
from .model import (
    BASIS_EXPLANATIONS,
    CONFIDENCE_EXPLANATIONS,
    CONFIDENCE_RANK,
    METHOD_VERSION,
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
    edge_identity,
    stable_id,
)

__all__ = [
    # model
    "METHOD_VERSION",
    "stable_id",
    "edge_identity",
    "CONFIDENCE_RANK",
    "BASIS_EXPLANATIONS",
    "CONFIDENCE_EXPLANATIONS",
    "EvidenceNodeKind",
    "EdgeBasis",
    "Confidence",
    "compose_confidence",
    "Task",
    "EvidenceNode",
    "EvidenceEdge",
    "Ambiguity",
    "NodeAttribution",
    "CorrelationConfig",
    "AttributionStats",
    "CorrelationResult",
    "ContainerResolver",
    # markers
    "MarkerDeclaration",
    "AssistantMarkers",
    # graph
    "IGNORED_EVENT_TYPES",
    "GraphBuild",
    "build_graph",
    # engine
    "CorrelationEngine",
    "ABLATION_SWITCHES",
    "explain",
    "resolve_attribution",
    "node_attribution",
    "evaluate_against_truth",
    "ablation_report",
    # errors
    "CorrelationError",
    "CorrelationInputError",
    "CorrelationLimitError",
    "CorrelationNotFoundError",
]
