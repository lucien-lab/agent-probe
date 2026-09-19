"""消融：每个开关都能独立关闭，``ablation_report`` 给出逐项统计。

M6 的消融实验直接消费这里：``baseline``（全开）对比 ``without_<开关>``。
"""

from __future__ import annotations

from agent_probe.correlate import (
    ABLATION_SWITCHES,
    AttributionStats,
    Confidence,
    CorrelationConfig,
    CorrelationEngine,
    EdgeBasis,
    EvidenceNodeKind,
    ablation_report,
    evaluate_against_truth,
)

from correlate.fixtures import (
    FakeContainerResolver,
    concurrent_scenario,
    corpus_scenario,
)


def _truth(result) -> dict[str, str]:
    return {
        node.node_id: "corpus"
        for node in result.nodes
        if node.kind is not EvidenceNodeKind.TASK
    }


def test_ablation_report_has_baseline_and_one_entry_per_switch(corpus) -> None:
    events, calls, tasks, markers = corpus
    report = ablation_report(events, calls, tasks, markers=markers)
    assert list(report) == ["baseline", *[f"without_{name}" for name in ABLATION_SWITCHES]]
    assert all(isinstance(value, AttributionStats) for value in report.values())
    assert report["baseline"].tasks_total == 1
    # 没有真值时不编造精确率。
    assert report["baseline"].precision is None
    assert report["baseline"].recall is None
    assert report["baseline"].f1 is None


def test_baseline_turns_every_switch_on(corpus) -> None:
    events, calls, tasks, markers = corpus
    baseline = ablation_report(events, calls, tasks, markers=markers)["baseline"]
    assisted = CorrelationEngine(
        CorrelationConfig(use_assisted_markers=True)
    ).correlate(events, calls, tasks, markers).stats
    assert baseline == assisted


def test_disabling_assisted_markers_removes_tool_calls_and_reintroduces_ambiguity(corpus) -> None:
    events, calls, tasks, markers = corpus
    report = ablation_report(events, calls, tasks, markers=markers)
    baseline = report["baseline"]
    without = report["without_use_assisted_markers"]

    assert baseline.edges_ambiguous == 0
    assert without.edges_ambiguous > 0
    assert without.edges_total < baseline.edges_total
    # 任务级覆盖率不应因此崩掉：歧义发生在调用级。
    assert without.determinate_coverage == baseline.determinate_coverage


def test_disabling_connection_id_makes_calls_unattributable(corpus) -> None:
    events, calls, tasks, markers = corpus
    report = ablation_report(events, calls, tasks, markers=markers)
    without = report["without_use_connection_id"]

    assert without.determinate_coverage < report["baseline"].determinate_coverage
    assert without.nodes_unknown > 0
    assert not [
        edge
        for edge in CorrelationEngine(
            CorrelationConfig(use_assisted_markers=True, use_connection_id=False)
        )
        .correlate(events, calls, tasks, markers)
        .edges
        if edge.basis is EdgeBasis.CONNECTION_ID
    ]


def test_disabling_process_lineage_keeps_coverage_but_loses_certainty(corpus) -> None:
    events, calls, tasks, markers = corpus
    report = ablation_report(events, calls, tasks, markers=markers)
    without = report["without_use_process_lineage"]

    assert without.nodes_certain < report["baseline"].nodes_certain
    assert without.nodes_probable > 0
    assert without.determinate_coverage == report["baseline"].determinate_coverage
    assert not [
        edge
        for edge in CorrelationEngine(
            CorrelationConfig(use_assisted_markers=True, use_process_lineage=False)
        )
        .correlate(events, calls, tasks, markers)
        .edges
        if edge.basis is EdgeBasis.PROCESS_LINEAGE
        and "process.fork" in " ".join(edge.evidence)
    ]


def test_disabling_time_window_removes_time_window_edges(corpus) -> None:
    events, calls, tasks, markers = corpus
    without = CorrelationEngine(
        CorrelationConfig(use_assisted_markers=True, use_time_window=False)
    ).correlate(events, calls, tasks, markers)
    assert not [edge for edge in without.edges if edge.basis is EdgeBasis.TIME_WINDOW]

    # 纯外部模式下时间窗是调用级关联的唯一依据：关掉它，调用级边必须消失。
    ext_events, ext_calls, ext_tasks, _ = concurrent_scenario(3)
    with_window = CorrelationEngine().correlate(ext_events, ext_calls, ext_tasks)
    assert [edge for edge in with_window.edges if edge.basis is EdgeBasis.TIME_WINDOW]

    report = ablation_report(ext_events, ext_calls, ext_tasks)
    assert report["baseline"].edges_ambiguous > 0
    assert report["without_use_time_window"].edges_ambiguous == 0
    assert report["without_use_time_window"].edges_total < report["baseline"].edges_total


def test_disabling_container_mapping_removes_container_edges() -> None:
    events, calls, tasks, markers = corpus_scenario()
    resolver = FakeContainerResolver(host_pids={"ctr-1": 1000}, cgroup_ids={"ctr-1": None})
    with_container = CorrelationEngine(
        CorrelationConfig(use_assisted_markers=True), resolver
    ).correlate(events, calls, tasks, markers)
    assert [
        edge for edge in with_container.edges if edge.basis is EdgeBasis.CONTAINER_MAPPING
    ]

    report = ablation_report(
        events,
        calls,
        tasks,
        markers=markers,
        container_resolver=resolver,
    )
    without = report["without_use_container_mapping"]
    assert without.edges_total < report["baseline"].edges_total
    assert without.nodes_certain < report["baseline"].nodes_certain


def test_ablation_report_with_truth_fills_precision_and_recall(corpus) -> None:
    events, calls, tasks, markers = corpus
    baseline_result = CorrelationEngine(
        CorrelationConfig(use_assisted_markers=True)
    ).correlate(events, calls, tasks, markers)
    truth = _truth(baseline_result)

    report = ablation_report(events, calls, tasks, truth, markers=markers)
    assert report["baseline"].precision == 1.0
    assert report["baseline"].recall == 1.0
    assert report["baseline"].f1 == 1.0
    for value in report.values():
        assert value.precision is not None
        assert value.recall is not None


def test_ablation_switches_are_independent_and_composable() -> None:
    config = CorrelationConfig()
    combined = config.with_switch("use_time_window", False).with_switch(
        "use_connection_id", False
    )
    assert combined.use_time_window is False
    assert combined.use_connection_id is False
    assert combined.use_process_lineage is True
    assert combined.enabled_switches == (
        "use_process_lineage",
        "use_container_mapping",
    )
    try:
        config.with_switch("nope", False)
    except Exception as exc:  # noqa: BLE001
        assert type(exc).__name__ == "CorrelationInputError"
    else:  # pragma: no cover
        raise AssertionError("未知开关必须报错")


def test_single_switch_off_matches_manual_engine(corpus) -> None:
    events, calls, tasks, markers = corpus
    manual = CorrelationEngine(
        CorrelationConfig(use_assisted_markers=True, use_time_window=False)
    ).correlate(events, calls, tasks, markers)
    report = ablation_report(events, calls, tasks, markers=markers)
    assert report["without_use_time_window"] == manual.stats


def test_evaluate_against_truth_marks_unknown_attribution_as_miss(corpus) -> None:
    events, calls, tasks, markers = corpus
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, tasks, markers
    )
    # 真值把某个节点的任务写成另一个不存在的标签 → 该节点算错，但仍在召回分母里。
    truth = _truth(result)
    some_node = sorted(truth)[0]
    truth[some_node] = "not-a-task"
    stats = evaluate_against_truth(result, truth)
    assert stats.precision is not None and stats.precision < 1.0
    assert stats.recall is not None and stats.recall < 1.0

    # 空真值 → 不计算 P/R/F1。
    empty = evaluate_against_truth(result, {})
    assert empty.precision is None and empty.recall is None and empty.f1 is None


def test_truth_can_refer_to_tasks_by_run_id_or_label(corpus) -> None:
    events, calls, tasks, markers = corpus
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, tasks, markers
    )
    nodes = {node.node_id: node for node in result.nodes}
    truth = {
        node_id: "corpus"
        for node_id, node in nodes.items()
        if node.kind is not EvidenceNodeKind.TASK
    }
    by_label = evaluate_against_truth(result, truth)
    by_run = evaluate_against_truth(
        result,
        {node_id: tasks[0].run_id for node_id in truth},
    )
    by_node = evaluate_against_truth(
        result,
        {
            node_id: result.nodes_of_kind(EvidenceNodeKind.TASK)[0].node_id
            for node_id in truth
        },
    )
    assert by_label == by_run == by_node
    assert by_label.precision == 1.0


def test_confidence_ordering_is_documented_and_monotone() -> None:
    from agent_probe.correlate import CONFIDENCE_RANK, compose_confidence

    assert CONFIDENCE_RANK[Confidence.UNKNOWN] < CONFIDENCE_RANK[Confidence.AMBIGUOUS]
    assert CONFIDENCE_RANK[Confidence.AMBIGUOUS] < CONFIDENCE_RANK[Confidence.PROBABLE]
    assert CONFIDENCE_RANK[Confidence.PROBABLE] < CONFIDENCE_RANK[Confidence.CERTAIN]
    assert (
        compose_confidence(Confidence.CERTAIN, Confidence.PROBABLE)
        is Confidence.PROBABLE
    )
    assert (
        compose_confidence(Confidence.AMBIGUOUS, Confidence.CERTAIN)
        is Confidence.AMBIGUOUS
    )
    assert compose_confidence() is Confidence.UNKNOWN
