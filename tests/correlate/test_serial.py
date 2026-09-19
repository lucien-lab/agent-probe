"""串行任务：一个任务、一个进程、若干 file/net/llm 事件。

期望（plan.md M3 验收口径）：全部节点有唯一归因、确定归因覆盖率 1.0、歧义率 0。
"""

from __future__ import annotations

from agent_probe.correlate import (
    Confidence,
    CorrelationConfig,
    CorrelationEngine,
    EdgeBasis,
    EvidenceNodeKind,
    node_attribution,
    resolve_attribution,
)


def _task_node_id(result: object) -> str:
    nodes = result.nodes_of_kind(EvidenceNodeKind.TASK)  # type: ignore[attr-defined]
    assert len(nodes) == 1
    return nodes[0].node_id


def test_serial_all_nodes_have_unique_attribution(serial) -> None:
    events, calls, tasks = serial
    result = CorrelationEngine().correlate(events, calls, tasks)

    assert result.stats.tasks_total == 1
    assert result.stats.nodes_total == len(result.nodes) - 1
    assert result.stats.nodes_certain == result.stats.nodes_total
    assert result.stats.nodes_probable == 0
    assert result.stats.nodes_ambiguous == 0
    assert result.stats.nodes_unknown == 0
    assert result.stats.determinate_coverage == 1.0
    assert result.stats.ambiguity_rate == 0.0
    assert result.ambiguities == ()


def test_serial_external_mode_has_no_call_level_ambiguity(serial) -> None:
    events, calls, tasks = serial
    result = CorrelationEngine(CorrelationConfig()).correlate(events, calls, tasks)

    assert result.mode == "external"
    # 只有一个调用候选，时间窗边可以存在，但不得是 AMBIGUOUS。
    assert result.stats.edges_ambiguous == 0
    time_edges = [edge for edge in result.edges if edge.basis is EdgeBasis.TIME_WINDOW]
    assert time_edges
    assert all(edge.confidence is Confidence.PROBABLE for edge in time_edges)
    assert all(edge.candidates == () for edge in time_edges)


def test_serial_call_attributed_certainly_via_connection_id(serial) -> None:
    events, calls, tasks = serial
    result = CorrelationEngine().correlate(events, calls, tasks)
    task_id = _task_node_id(result)

    call_nodes = result.nodes_of_kind(EvidenceNodeKind.LLM_CALL)
    assert len(call_nodes) == 1
    attribution = node_attribution(result, call_nodes[0].node_id)
    assert attribution.confidence is Confidence.CERTAIN
    assert attribution.targets == (task_id,)

    connection_edges = [edge for edge in result.edges if edge.basis is EdgeBasis.CONNECTION_ID]
    assert len(connection_edges) == 1
    assert connection_edges[0].confidence is Confidence.CERTAIN
    assert connection_edges[0].method_version == CorrelationConfig().method_version
    assert connection_edges[0].evidence


def test_serial_file_events_aggregate_per_path_and_are_certain(serial) -> None:
    events, calls, tasks = serial
    result = CorrelationEngine().correlate(events, calls, tasks)
    task_id = _task_node_id(result)

    file_nodes = result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT)
    assert len(file_nodes) == 1
    node = file_nodes[0]
    assert node.attributes["paths"] == ["/work/a.txt"]
    assert node.attributes["event_types"] == ["file.open", "file.read", "file.write"]
    assert node.attributes["event_count"] == 3
    assert node.attributes["bytes_written"] == 5
    assert node.attributes["bytes_read"] == 12
    assert node.attributes["results"] == {"ok": 3}
    attribution = node_attribution(result, node.node_id)
    assert attribution.confidence is Confidence.CERTAIN
    assert attribution.targets == (task_id,)


def test_serial_net_nodes_cover_connect_and_tls(serial) -> None:
    events, calls, tasks = serial
    result = CorrelationEngine().correlate(events, calls, tasks)

    net_nodes = result.nodes_of_kind(EvidenceNodeKind.NET_EFFECT)
    identities = sorted(node.attributes["identity"] for node in net_nodes)
    assert identities == ["net:tcp:203.0.113.10:443", "tls:conn-1"]
    tls_node = next(node for node in net_nodes if node.attributes["connection_id"] == "conn-1")
    assert tls_node.attributes["directions"] == ["read", "write"]
    assert tls_node.attributes["bytes_total"] == 128 + 256


def test_serial_every_edge_declares_basis_version_confidence_and_evidence(serial) -> None:
    events, calls, tasks = serial
    result = CorrelationEngine().correlate(events, calls, tasks)

    assert result.edges
    for edge in result.edges:
        assert edge.basis in set(EdgeBasis)
        assert edge.method_version == result.config.method_version
        assert edge.confidence in set(Confidence)
        assert edge.evidence and all(item for item in edge.evidence)
        # AMBIGUOUS ⇔ 有候选：两个方向都不允许含糊。
        if edge.confidence is Confidence.AMBIGUOUS:
            assert edge.candidates
        else:
            assert edge.candidates == ()


def test_serial_without_tasks_everything_is_unknown(serial) -> None:
    events, calls, _ = serial
    result = CorrelationEngine().correlate(events, calls, (), None)

    assert result.stats.tasks_total == 0
    assert result.stats.nodes_unknown == result.stats.nodes_total
    assert result.stats.determinate_coverage == 0.0
    assert any("未提供任务声明" in note for note in result.notes)
    for node in result.nodes:
        if node.kind is EvidenceNodeKind.TASK:
            continue
        assert resolve_attribution(
            {item.node_id: item for item in result.nodes}, result.edges
        )[node.node_id].confidence is Confidence.UNKNOWN
