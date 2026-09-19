"""同进程并发交错：外部模式必须保留歧义，辅助模式必须交叉核验。

这是 M3 最关键的一组语义：

* 无标记时，同进程多路并发调用**无法**唯一归因 → ``AMBIGUOUS`` 且候选完整；
* 加上可交叉核验的应用声明后才允许收敛为 ``CERTAIN``；
* 声明与系统证据冲突时必须降级，且 ``evidence`` 里同时保留"声明"和"系统证据"。
"""

from __future__ import annotations

from agent_probe.correlate import (
    AssistantMarkers,
    Confidence,
    CorrelationConfig,
    CorrelationEngine,
    EdgeBasis,
    EvidenceNodeKind,
    node_attribution,
)

from correlate.fixtures import (
    TIGHT_TIME_WINDOW_NS,
    TOOL_OFFSET,
    T0,
    concurrent_scenario,
)

T0_TOOL = T0 + TOOL_OFFSET


def _call_ids(result) -> set[str]:
    return {node.node_id for node in result.nodes_of_kind(EvidenceNodeKind.LLM_CALL)}


def _file_nodes(result) -> list:
    return sorted(result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT), key=lambda n: n.attributes["paths"][0])


def _ambiguous_edges(result) -> list:
    return [edge for edge in result.edges if edge.confidence is Confidence.AMBIGUOUS]


def test_two_way_concurrency_without_markers_is_ambiguous_with_all_candidates() -> None:
    events, calls, tasks, _ = concurrent_scenario(2)
    result = CorrelationEngine().correlate(events, calls, tasks)

    assert len(_call_ids(result)) == 2
    ambiguous = _ambiguous_edges(result)
    assert len(ambiguous) == 2  # 两个工具写事件各一条
    for edge in ambiguous:
        assert edge.basis is EdgeBasis.TIME_WINDOW
        assert {edge.dst_node_id, *edge.candidates} == _call_ids(result)
        assert any("不取最近的" in item for item in edge.evidence)
    assert result.stats.edges_ambiguous == 2
    assert len(result.ambiguities) == 2
    assert all(item.edge_id is not None for item in result.ambiguities)


def test_five_way_concurrency_candidates_are_complete() -> None:
    events, calls, tasks, _ = concurrent_scenario(5)
    result = CorrelationEngine().correlate(events, calls, tasks)

    assert len(_call_ids(result)) == 5
    ambiguous = _ambiguous_edges(result)
    assert len(ambiguous) == 5
    for edge in ambiguous:
        assert len({edge.dst_node_id, *edge.candidates}) == 5
        assert {edge.dst_node_id, *edge.candidates} == _call_ids(result)


def test_concurrency_never_forces_a_single_attribution_at_call_level() -> None:
    events, calls, tasks, _ = concurrent_scenario(5)
    result = CorrelationEngine().correlate(events, calls, tasks)

    for node in _file_nodes(result):
        time_edges = [
            edge
            for edge in result.outgoing(node.node_id)
            if edge.basis is EdgeBasis.TIME_WINDOW
        ]
        assert time_edges
        assert all(edge.confidence is Confidence.AMBIGUOUS for edge in time_edges)
        # 任务级仍然是确定的（进程身份），这正说明"调用级歧义"与"任务级承诺"是两件事。
        assert node_attribution(result, node.node_id).confidence is Confidence.CERTAIN


def test_concurrency_with_distinct_connections_is_not_ambiguous() -> None:
    events, calls, tasks, _ = concurrent_scenario(3, shared_connection=False)
    result = CorrelationEngine(
        CorrelationConfig(time_window_ns=TIGHT_TIME_WINDOW_NS)
    ).correlate(events, calls, tasks)

    assert result.stats.edges_ambiguous == 0
    for node in _file_nodes(result):
        edges = [
            edge
            for edge in result.outgoing(node.node_id)
            if edge.basis is EdgeBasis.TIME_WINDOW
        ]
        assert len(edges) == 1
        assert edges[0].confidence is Confidence.PROBABLE


def test_assisted_markers_resolve_concurrency_to_certain() -> None:
    events, calls, tasks, markers = concurrent_scenario(5, declaration_limit=5)
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    result = engine.correlate(events, calls, tasks, markers)

    assert result.mode == "assisted"
    assert result.stats.edges_ambiguous == 0
    assert result.stats.nodes_ambiguous == 0
    assert result.ambiguities == ()
    assert result.stats.determinate_coverage == 1.0

    tool_nodes = result.nodes_of_kind(EvidenceNodeKind.TOOL_CALL)
    assert len(tool_nodes) == 5
    for node in _file_nodes(result):
        marker_edges = [
            edge
            for edge in result.outgoing(node.node_id)
            if edge.basis is EdgeBasis.TOOL_ID_MARKER
        ]
        assert len(marker_edges) == 1
        assert marker_edges[0].confidence is Confidence.CERTAIN
        assert any("交叉核验通过" in item for item in marker_edges[0].evidence)


def test_assisted_markers_do_not_increase_ambiguity_over_external_baseline() -> None:
    events, calls, tasks, markers = concurrent_scenario(5, declaration_limit=5)
    external = CorrelationEngine(CorrelationConfig()).correlate(events, calls, tasks)
    assisted = CorrelationEngine(
        CorrelationConfig(use_assisted_markers=True)
    ).correlate(events, calls, tasks, markers)

    assert external.stats.edges_ambiguous == 5
    assert assisted.stats.edges_ambiguous == 0
    assert assisted.stats.ambiguity_rate <= external.stats.ambiguity_rate


def test_assisted_conflict_downgrades_and_keeps_both_evidences() -> None:
    # 声明声称工具跑在不存在的 pid 上 → 与系统证据冲突。
    events, calls, tasks, markers = concurrent_scenario(
        2, declaration_limit=2, declared_pid=4242, declared_start=999_999
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, tasks, markers
    )

    marker_edges = [
        edge
        for edge in result.edges
        if edge.basis is EdgeBasis.TOOL_ID_MARKER and edge.src_node_id in {
            node.node_id for node in _file_nodes(result)
        }
    ]
    assert marker_edges
    assert all(edge.confidence is Confidence.AMBIGUOUS for edge in marker_edges)
    for edge in marker_edges:
        declared = [item for item in edge.evidence if item.startswith("declared:")]
        system = [item for item in edge.evidence if item.startswith("system:")]
        assert declared, "声明证据必须保留"
        assert any("pid=4242 在系统事件中不存在" in item for item in system), system
        assert len({edge.dst_node_id, *edge.candidates}) >= 2
    # 冲突不得被当成"确定了"，但也不得丢掉候选。
    assert result.stats.edges_ambiguous >= len(marker_edges)


def test_assisted_conflict_keeps_the_conflicting_declaration_among_candidates() -> None:
    # 单路调用 + 冲突的进程声明：替代候选就是那次调用本身 → AMBIGUOUS 且两个候选
    # （声明的工具、系统时间窗给出的调用）都保留，不挑一个当答案。
    events, calls, tasks, markers = concurrent_scenario(
        1, declaration_limit=1, declared_pid=4242, declared_start=999_999
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, tasks, markers
    )
    call_ids = _call_ids(result)
    tool_ids = {node.node_id for node in result.nodes_of_kind(EvidenceNodeKind.TOOL_CALL)}
    file_marker_edges = [
        edge
        for edge in result.edges
        if edge.basis is EdgeBasis.TOOL_ID_MARKER
        and edge.src_node_id in {node.node_id for node in _file_nodes(result)}
    ]
    assert file_marker_edges
    for edge in file_marker_edges:
        assert edge.confidence is Confidence.AMBIGUOUS
        assert {edge.dst_node_id, *edge.candidates} == call_ids | tool_ids
        assert any("冲突" in item or "不一致" in item for item in edge.evidence)


def test_assisted_declaration_without_identity_bridge_stays_probable() -> None:
    # 只有 tool_id + pid + 时间（没有 connection_id、系统侧也没有 correlation_id）：
    # 声明不能被单独当成确定结论。
    events, calls, tasks, markers = concurrent_scenario(1, declaration_limit=1)
    markers = AssistantMarkers.from_records(
        [
            {
                "tool_id": "tool-0",
                "task_label": "concurrent",
                "pid": 1000,
                "process_start_id": 555,
                "monotonic_ns": T0_TOOL,
            }
        ]
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, tasks, markers
    )
    file_edges = [
        edge
        for edge in result.edges
        if edge.src_node_id in {node.node_id for node in _file_nodes(result)}
        and edge.basis is EdgeBasis.TOOL_ID_MARKER
    ]
    assert file_edges
    assert all(edge.confidence is Confidence.PROBABLE for edge in file_edges)
    assert any(
        "没有可用的身份桥" in item for edge in file_edges for item in edge.evidence
    )
    tool = result.nodes_of_kind(EvidenceNodeKind.TOOL_CALL)[0]
    assert node_attribution(result, tool.node_id).confidence is Confidence.PROBABLE


def test_tool_call_nodes_are_attributed_to_the_declared_task_label() -> None:
    events, calls, tasks, markers = concurrent_scenario(2, declaration_limit=2)
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, tasks, markers
    )
    task_id = result.nodes_of_kind(EvidenceNodeKind.TASK)[0].node_id
    for node in result.nodes_of_kind(EvidenceNodeKind.TOOL_CALL):
        attribution = node_attribution(result, node.node_id)
        assert attribution.confidence is Confidence.CERTAIN
        assert attribution.targets == (task_id,)
        assert node.attributes["verification"]["checks"]["task_label"] == "verified"


def test_markers_are_ignored_when_switch_is_off_with_explicit_note() -> None:
    events, calls, tasks, markers = concurrent_scenario(2, declaration_limit=2)
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=False)).correlate(
        events, calls, tasks, markers
    )
    assert result.nodes_of_kind(EvidenceNodeKind.TOOL_CALL) == ()
    assert any("已全部忽略" in note for note in result.notes)
    assert result.stats.edges_ambiguous == 2


def test_marker_declarations_without_time_produce_no_effect_segment_edges() -> None:
    events, calls, tasks, markers = concurrent_scenario(
        2, declaration_limit=2, marker_times=False
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, tasks, markers
    )
    assert result.nodes_of_kind(EvidenceNodeKind.TOOL_CALL)
    assert all(edge.basis is not EdgeBasis.TOOL_ID_MARKER for edge in result.edges if edge.src_node_id in {
        node.node_id for node in _file_nodes(result)
    })


def test_assistant_markers_round_trip() -> None:
    _, _, _, markers = concurrent_scenario(2, declaration_limit=2)
    assert markers is not None
    restored = AssistantMarkers.from_dict(markers.to_dict())
    assert restored == markers
    assert restored.to_dict() == markers.to_dict()
