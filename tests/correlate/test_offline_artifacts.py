"""离线可复算：把结果与声明落盘再读回，结论必须一致。

对应 brief 的 *"结果要能离线重算"*：序列化视图必须自足——只有 JSON 文件和
注入的 resolver，不需要重新采集事件，也能得到同样的关联结论。
"""

from __future__ import annotations

import json

from agent_probe.correlate import (
    AssistantMarkers,
    CorrelationConfig,
    CorrelationEngine,
    CorrelationResult,
    EvidenceNodeKind,
    evaluate_against_truth,
)


def test_result_survives_a_file_round_trip(corpus, tmp_path) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    result = engine.correlate(events, calls, tasks, markers)

    path = tmp_path / "correlation.json"
    path.write_text(result.to_json(), encoding="utf-8")
    restored = CorrelationResult.from_json(path.read_text(encoding="utf-8"))

    assert restored == result
    assert restored.to_json() == result.to_json()
    # 结果自带 config 与 method_version，离线也能知道"这是哪一版方法算出来的"。
    assert restored.config.method_version == CorrelationConfig().method_version
    assert restored.mode == "assisted"


def test_offline_result_can_be_scored_without_events(corpus, tmp_path) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    result = engine.correlate(events, calls, tasks, markers)

    path = tmp_path / "result.json"
    path.write_text(result.to_json(), encoding="utf-8")
    restored = CorrelationResult.from_json(path.read_text(encoding="utf-8"))

    truth = {
        node.node_id: "corpus"
        for node in restored.nodes
        if node.kind is not EvidenceNodeKind.TASK
    }
    stats = evaluate_against_truth(restored, truth)
    assert stats.precision == 1.0
    assert stats.recall == 1.0
    assert stats.determinate_coverage == restored.stats.determinate_coverage


def test_marker_declarations_can_be_loaded_from_a_file(corpus, write_text_file) -> None:
    events, calls, tasks, markers = corpus
    path = write_text_file("markers.json", json.dumps(markers.to_dict(), sort_keys=True))
    loaded = AssistantMarkers.from_dict(json.loads(path.read_text(encoding="utf-8")))
    assert loaded == markers

    baseline = CorrelationEngine(
        CorrelationConfig(use_assisted_markers=True)
    ).correlate(events, calls, tasks, markers)
    from_file = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, tasks, loaded
    )
    assert from_file.to_json() == baseline.to_json()


def test_explain_output_can_be_persisted(corpus, write_text_file) -> None:
    events, calls, tasks, markers = corpus
    engine = CorrelationEngine(CorrelationConfig(use_assisted_markers=True))
    result = engine.correlate(events, calls, tasks, markers)
    explanations = [
        engine.explain(result),
        engine.explain(result, node_id=result.nodes_of_kind(EvidenceNodeKind.PROCESS)[0].node_id),
        engine.explain(result, edge_id=result.edges[0].edge_id),
    ]
    path = write_text_file(
        "explain.json", json.dumps(explanations, sort_keys=True, ensure_ascii=False)
    )
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert len(loaded) == 3
    assert loaded[1]["attribution"]["confidence"] in {"certain", "probable", "ambiguous", "unknown"}
