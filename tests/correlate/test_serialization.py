"""确定性、JSON 往返与解释接口。

brief 要求：*"同输入必须产出逐字节相同的结果（node_id/edge_id 由内容哈希派生，
不得包含 id()、时间戳、随机数或字典迭代顺序依赖）；结果要能离线重算
（to_dict → from_dict → 再计算一致）"*。
"""

from __future__ import annotations

import json

import pytest

from agent_probe.correlate import (
    BASIS_EXPLANATIONS,
    CONFIDENCE_EXPLANATIONS,
    Confidence,
    CorrelationConfig,
    CorrelationEngine,
    CorrelationInputError,
    CorrelationNotFoundError,
    CorrelationResult,
    EdgeBasis,
    EvidenceNodeKind,
)

from correlate.fixtures import concurrent_scenario


def _assisted(events, calls, tasks, markers):
    return CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, tasks, markers
    )


def test_result_round_trips_through_dict_and_json(corpus) -> None:
    events, calls, tasks, markers = corpus
    result = _assisted(events, calls, tasks, markers)
    assert CorrelationResult.from_dict(result.to_dict()) == result
    restored = CorrelationResult.from_json(result.to_json())
    assert restored == result
    assert restored.to_json() == result.to_json()


def test_same_input_yields_byte_identical_json(corpus) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    first = engine.correlate(events, calls, tasks, markers)
    second = engine.correlate(events, calls, tasks, markers)
    assert first.to_json() == second.to_json()


def test_input_order_does_not_change_the_result(corpus) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    forward = engine.correlate(events, calls, tasks, markers)
    reversed_markers = type(markers).from_records(
        list(reversed(markers.to_dict()["declarations"]))
    )
    backward = engine.correlate(
        tuple(reversed(events)), tuple(reversed(calls)), tuple(reversed(tasks)), reversed_markers
    )
    assert forward.to_json() == backward.to_json()


def test_json_is_canonical_and_has_no_non_json_values(corpus) -> None:
    from agent_probe.events import canonical_json

    events, calls, tasks, markers = corpus
    result = _assisted(events, calls, tasks, markers)
    payload = result.to_dict()
    assert canonical_json(payload) == result.to_json()
    for node in result.nodes:
        json.dumps(node.attributes)  # 必须可序列化（round-trip 的前提）
    for edge in result.edges:
        assert isinstance(edge.evidence, tuple)
        assert isinstance(edge.candidates, tuple)


def test_node_and_edge_ids_are_content_derived_and_stable() -> None:
    events_a, calls_a, tasks_a, markers_a = concurrent_scenario(2, declaration_limit=2)
    events_b, calls_b, tasks_b, markers_b = concurrent_scenario(2, declaration_limit=2)
    result_a = _assisted(events_a, calls_a, tasks_a, markers_a)
    result_b = _assisted(events_b, calls_b, tasks_b, markers_b)

    keys_a = {node.key: node.node_id for node in result_a.nodes}
    keys_b = {node.key: node.node_id for node in result_b.nodes}
    assert keys_a == keys_b
    assert {edge.edge_id for edge in result_a.edges} == {
        edge.edge_id for edge in result_b.edges
    }
    # 同一 key 在不同输入批次中得到同一 node_id（内容哈希，不含随机数）。
    assert all(key.startswith(("run:", "tool:", "container:", "req-")) for key in keys_a)


def test_explain_summary_lists_modes_and_guides(corpus) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    result = engine.correlate(events, calls, tasks, markers)
    payload = engine.explain(result)

    assert payload["mode"] == "assisted"
    assert payload["method_version"] == result.config.method_version
    assert payload["config"]["use_assisted_markers"] is True
    assert payload["summary"]["nodes_by_kind"]["task"] == 1
    assert payload["summary"]["edges_by_confidence"]
    assert set(payload["basis_guide"]) == {str(basis) for basis in EdgeBasis}
    assert set(payload["confidence_guide"]) == {str(item) for item in Confidence}
    assert "hint" in payload


def test_explain_node_reports_attribution_path_and_edges(corpus) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    result = engine.correlate(events, calls, tasks, markers)
    task_id = result.nodes_of_kind(EvidenceNodeKind.TASK)[0].node_id
    file_node = result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT)[0]

    payload = engine.explain(result, node_id=file_node.node_id)
    assert payload["node"]["node_id"] == file_node.node_id
    attribution = payload["attribution"]
    assert attribution["determinate"] is True
    assert attribution["targets"] == [task_id]
    assert attribution["primary"] == task_id
    assert attribution["path_edge_ids"]
    assert attribution["path"]
    assert payload["outgoing"]
    assert payload["attribution_candidates"][0]["node_id"] == task_id
    for edge_view in payload["outgoing"]:
        assert edge_view["basis_explanation"]
        assert edge_view["confidence_explanation"]
        assert edge_view["direction"]
        assert edge_view["meaning"]


def test_explain_every_edge_including_all_bases(corpus) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    result = engine.correlate(events, calls, tasks, markers)

    seen_bases: set[EdgeBasis] = set()
    for edge in result.edges:
        payload = engine.explain(result, edge_id=edge.edge_id)
        view = payload["edge"]
        assert view["edge_id"] == edge.edge_id
        assert view["basis"] == str(edge.basis)
        assert view["basis_explanation"] == BASIS_EXPLANATIONS[edge.basis]
        assert view["confidence_explanation"] == CONFIDENCE_EXPLANATIONS[edge.confidence]
        assert view["evidence"] == list(edge.evidence)
        assert view["src"]["node_id"] == edge.src_node_id
        assert view["dst"]["node_id"] == edge.dst_node_id
        assert [item["node_id"] for item in view["candidates"]] == list(edge.candidates)
        assert view["method_version"] == result.config.method_version
        seen_bases.add(edge.basis)
    assert EdgeBasis.PROCESS_LINEAGE in seen_bases
    assert EdgeBasis.RUN_ID_MARKER in seen_bases or EdgeBasis.CONNECTION_ID in seen_bases


def test_explain_ambiguous_edge_shows_all_candidates() -> None:
    events, calls, tasks, _ = concurrent_scenario(3)
    engine = CorrelationEngine()
    result = engine.correlate(events, calls, tasks)
    ambiguous = next(
        edge for edge in result.edges if edge.confidence is Confidence.AMBIGUOUS
    )
    payload = engine.explain(result, edge_id=ambiguous.edge_id)
    assert len(payload["edge"]["candidates"]) == len(ambiguous.candidates)
    assert "不得择一使用" in payload["edge"]["meaning"]

    node_id = ambiguous.src_node_id
    node_payload = engine.explain(result, node_id=node_id)
    assert node_payload["ambiguities"]
    assert node_payload["ambiguities"][0]["candidates"]


def test_explain_unknown_ids_raise_and_mixing_ids_is_rejected(corpus) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    result = engine.correlate(events, calls, tasks, markers)
    with pytest.raises(CorrelationNotFoundError):
        engine.explain(result, node_id="n:missing")
    with pytest.raises(CorrelationNotFoundError):
        engine.explain(result, edge_id="e:missing")
    with pytest.raises(CorrelationInputError):
        engine.explain(
            result,
            node_id=result.nodes[0].node_id,
            edge_id=result.edges[0].edge_id,
        )


def test_explain_is_json_serialisable(corpus) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    result = engine.correlate(events, calls, tasks, markers)
    node_id = result.nodes_of_kind(EvidenceNodeKind.PROCESS)[0].node_id
    for payload in (
        engine.explain(result),
        engine.explain(result, node_id=node_id),
        engine.explain(result, edge_id=result.edges[0].edge_id),
    ):
        json.dumps(payload, sort_keys=True)


def test_engine_can_be_reused_and_is_stateless_between_runs(corpus) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    first = engine.correlate(events, calls, tasks, markers)
    second = engine.correlate(events, calls, tasks)
    third = engine.correlate(events, calls, tasks, markers)
    assert second.to_json() != first.to_json()
    assert third.to_json() == first.to_json()
    assert engine.config.use_assisted_markers is True


def test_result_from_dict_rejects_tampered_ids(corpus) -> None:
    events, calls, tasks, markers = corpus
    result = _assisted(events, calls, tasks, markers)
    payload = result.to_dict()
    payload["nodes"][0] = {**payload["nodes"][0], "node_id": "n:deadbeef"}
    with pytest.raises(CorrelationInputError):
        CorrelationResult.from_dict(payload)


def test_result_from_dict_rejects_missing_or_unknown_keys(corpus) -> None:
    events, calls, tasks, markers = corpus
    result = _assisted(events, calls, tasks, markers)
    payload = result.to_dict()
    for broken in (
        {key: value for key, value in payload.items() if key != "nodes"},
        {**payload, "extra": 1},
    ):
        with pytest.raises(CorrelationInputError):
            CorrelationResult.from_dict(broken)
