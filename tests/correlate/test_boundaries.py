"""边界与失败模式：空输入、半输入、时钟混用、规模上限、输入校验。

原则：**宁可显式报错/显式 UNKNOWN，也不静默给一个看起来合理的答案**。
"""

from __future__ import annotations

import pytest

from agent_probe.correlate import (
    AssistantMarkers,
    Confidence,
    CorrelationConfig,
    CorrelationEngine,
    CorrelationInputError,
    CorrelationLimitError,
    EdgeBasis,
    EvidenceNodeKind,
    Task,
    node_attribution,
)
from agent_probe.events import EventType

from correlate.fixtures import (
    PID,
    PROC_START,
    RUN_A,
    T0,
    WALL_OFFSET,
    make_call,
    make_event,
    make_task,
    payload_file_write,
    payload_process_exec,
    payload_quality_counter,
    payload_tls,
)


def test_empty_input_produces_empty_result_with_notes() -> None:
    result = CorrelationEngine().correlate((), (), ())
    assert result.nodes == ()
    assert result.edges == ()
    assert result.ambiguities == ()
    assert result.stats.nodes_total == 0
    assert result.stats.determinate_coverage == 0.0
    assert result.stats.ambiguity_rate == 0.0
    assert result.stats.precision is None
    assert any("未提供任务声明" in note for note in result.notes)
    assert any("未提供系统事件" in note for note in result.notes)
    # 空结果也要能往返。
    from agent_probe.correlate import CorrelationResult

    assert CorrelationResult.from_dict(result.to_dict()) == result


def test_events_only_no_calls_still_attributes_at_task_level(serial) -> None:
    events, _, tasks = serial
    result = CorrelationEngine().correlate(events, (), tasks)
    assert result.nodes_of_kind(EvidenceNodeKind.LLM_CALL) == ()
    assert result.stats.determinate_coverage == 1.0
    assert any("未提供调用记录" in note for note in result.notes)


def test_calls_only_without_events_leaves_everything_unknown() -> None:
    calls = (make_call("req-1", "conn-1"),)
    result = CorrelationEngine().correlate((), calls, (make_task(),))
    assert [node.kind for node in result.nodes].count(EvidenceNodeKind.LLM_CALL) == 1
    assert result.stats.determinate_coverage == 0.0
    assert result.stats.nodes_unknown == 1
    call = result.nodes_of_kind(EvidenceNodeKind.LLM_CALL)[0]
    assert node_attribution(result, call.node_id).confidence is Confidence.UNKNOWN
    assert any("未提供系统事件" in note for note in result.notes)


def test_events_without_tasks_are_unknown_not_guessed(serial) -> None:
    events, calls, _ = serial
    result = CorrelationEngine().correlate(events, calls, ())
    assert result.stats.nodes_unknown == result.stats.nodes_total
    assert result.stats.nodes_total > 0


def test_quality_events_are_ignored_and_create_no_nodes() -> None:
    events = (
        make_event(1, EventType.FILE_WRITE, payload_file_write("/work/x"), monotonic_ns=T0 + 2),
        make_event(
            2,
            EventType.QUALITY_COUNTER_SNAPSHOT,
            payload_quality_counter(),
            monotonic_ns=T0 + 3,
            pid=999_999,  # 采集器自己的 pid：不得被当成 agent 进程
            process_start_id=None,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))
    pids = {node.attributes["pid"] for node in result.nodes_of_kind(EvidenceNodeKind.PROCESS)}
    assert pids == {PID}
    assert not [edge for edge in result.edges if "quality" in " ".join(edge.evidence)]


def test_node_limit_raises_instead_of_truncating(serial) -> None:
    events, calls, tasks = serial
    with pytest.raises(CorrelationLimitError) as excinfo:
        CorrelationEngine(CorrelationConfig(max_nodes=3)).correlate(events, calls, tasks)
    assert "max_nodes" in str(excinfo.value)


def test_edge_limit_raises_instead_of_truncating(serial) -> None:
    events, calls, tasks = serial
    with pytest.raises(CorrelationLimitError) as excinfo:
        CorrelationEngine(CorrelationConfig(max_edges=2)).correlate(events, calls, tasks)
    assert "max_edges" in str(excinfo.value)


def test_candidate_limit_truncates_with_explicit_evidence_and_note() -> None:
    calls = tuple(make_call(f"req-{i}", "conn-1", index=i) for i in range(6))
    events = tuple(
        [
            make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
            make_event(2, EventType.TLS_BYTES, payload_tls("conn-1"), monotonic_ns=T0 + 2_000_000),
            make_event(3, EventType.FILE_WRITE, payload_file_write("/work/x"), monotonic_ns=T0 + 3_000_000),
        ]
    )
    result = CorrelationEngine(CorrelationConfig(max_candidates=3)).correlate(
        events, calls, (make_task(),)
    )
    ambiguous = [edge for edge in result.edges if edge.confidence is Confidence.AMBIGUOUS]
    assert ambiguous
    for edge in ambiguous:
        assert len(edge.candidates) == 2  # dst + 2 = max_candidates
        assert any("candidates_truncated" in item for item in edge.evidence)
        # 被截断的候选仍完整记录在同一条边的证据里（不丢信息）。
        assert any("同一进程内有 6 个调用候选" in item for item in edge.evidence)
    assert any("已截断" in note for note in result.notes)


def test_max_candidates_must_be_at_least_one() -> None:
    with pytest.raises(CorrelationInputError):
        CorrelationConfig(max_candidates=0)
    with pytest.raises(CorrelationInputError):
        CorrelationConfig(max_nodes=0)
    with pytest.raises(CorrelationInputError):
        CorrelationConfig(time_window_ns=-1)


def test_wall_clock_consistent_with_boot_is_probable_with_explicit_marker() -> None:
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(2, EventType.FILE_WRITE, payload_file_write("/work/x"), monotonic_ns=T0 + 2_000_000),
    )
    calls = (make_call("req-1", "conn-1"),)
    markers = AssistantMarkers.from_records(
        [
            {
                "call_id": "req-1",
                "pid": PID,
                "process_start_id": PROC_START,
                "run_id": RUN_A,
                "wall_time_ns": (T0 + 2_000_000) + WALL_OFFSET,
            }
        ]
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, (make_task(),), markers
    )
    link_edges = [
        edge
        for edge in result.edges
        if edge.basis in (EdgeBasis.CALL_ID_MARKER, EdgeBasis.TIME_WINDOW)
    ]
    assert link_edges
    assert all(edge.confidence is Confidence.PROBABLE for edge in link_edges)
    assert any(
        "wall_clock_fallback" in item for edge in link_edges for item in edge.evidence
    )
    assert any(
        "弱证据" in item for edge in link_edges for item in edge.evidence
    )


def test_wall_clock_from_another_boot_is_refused_not_silently_compared() -> None:
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(2, EventType.FILE_WRITE, payload_file_write("/work/x"), monotonic_ns=T0 + 2_000_000),
    )
    calls = (make_call("req-1", "conn-1"),)
    markers = AssistantMarkers.from_records(
        [
            {
                "call_id": "req-1",
                "pid": PID,
                "process_start_id": PROC_START,
                "run_id": RUN_A,
                # 偏移比本 boot 多 1e12 ns → 疑似跨 boot。
                "wall_time_ns": (T0 + 2_000_000) + WALL_OFFSET + 10**12,
            }
        ]
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, (make_task(),), markers
    )
    assert any("疑似跨 boot" in note for note in result.notes)
    assert not [edge for edge in result.edges if edge.basis is EdgeBasis.TIME_WINDOW]
    for edge in result.edges:
        if edge.basis is EdgeBasis.CALL_ID_MARKER:
            assert edge.confidence is not Confidence.CERTAIN


def test_wall_clock_without_run_id_cannot_be_converted() -> None:
    events = (make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1),)
    calls = (make_call("req-1", "conn-1"),)
    markers = AssistantMarkers.from_records(
        [{"call_id": "req-1", "wall_time_ns": T0 + 5_000_000}]
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, (make_task(),), markers
    )
    assert not [edge for edge in result.edges if edge.basis is EdgeBasis.TIME_WINDOW]
    # 拒绝换算的原因必须出现在结果级 notes 里（否则"为什么没有归因"无法解释）。
    assert any("无法确定所属 boot" in note for note in result.notes)


def test_wrong_input_types_are_rejected_explicitly() -> None:
    with pytest.raises(CorrelationInputError):
        CorrelationEngine().correlate("not a sequence")  # type: ignore[arg-type]
    with pytest.raises(CorrelationInputError):
        CorrelationEngine().correlate((), ("not a call",))  # type: ignore[arg-type]
    with pytest.raises(CorrelationInputError):
        CorrelationEngine().correlate((), (), ("not a task",))  # type: ignore[arg-type]
    with pytest.raises(CorrelationInputError):
        CorrelationEngine().correlate((), (), (), {"call_id": "c"})  # type: ignore[arg-type]


def test_duplicate_physical_request_id_is_deduplicated_with_note() -> None:
    events = (
        make_event(1, EventType.TLS_BYTES, payload_tls("conn-1"), monotonic_ns=T0 + 1_000_000),
    )
    calls = (make_call("req-1", "conn-1"), make_call("req-1", "conn-1", index=1))
    result = CorrelationEngine().correlate(events, calls, (make_task(),))
    assert len(result.nodes_of_kind(EvidenceNodeKind.LLM_CALL)) == 1
    assert any("出现多次" in note for note in result.notes)


def test_task_validation_rejects_bad_values() -> None:
    with pytest.raises(CorrelationInputError):
        make_task(ended_monotonic_ns=T0 - 1)
    with pytest.raises(CorrelationInputError):
        Task(run_id="", process_start_ids=frozenset())
    with pytest.raises(CorrelationInputError):
        Task(run_id=RUN_A, started_monotonic_ns=-1)


def test_engine_rejects_non_config_and_non_resolver() -> None:
    with pytest.raises(CorrelationInputError):
        CorrelationEngine("nope")  # type: ignore[arg-type]
    with pytest.raises(CorrelationInputError):
        CorrelationEngine(CorrelationConfig(), container_resolver=object())


def test_process_fork_with_contradictory_payload_is_downgraded() -> None:
    events = (
        make_event(
            1,
            EventType.PROCESS_FORK,
            {"child_pid": 1001, "parent_pid": 4321, "child_start_id": 777},
            monotonic_ns=T0 + 1_000_000,
            pid=1000,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))
    fork_edges = [
        edge
        for edge in result.edges
        if any("process.fork 事件" in item for item in edge.evidence)
    ]
    assert len(fork_edges) == 1
    assert fork_edges[0].confidence is Confidence.PROBABLE
    assert any("数据自相矛盾" in item for item in fork_edges[0].evidence)


def test_files_without_path_fall_back_to_fd_identity() -> None:
    events = (
        make_event(
            1,
            EventType.FILE_TRUNCATE,
            {"path": None, "fd": 7, "length": 0},
            monotonic_ns=T0 + 1_000_000,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))
    node = result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT)[0]
    assert node.attributes["identity"] == "fd:7"
    assert node.attributes["paths"] == []


def test_rename_aggregates_old_and_new_paths() -> None:
    events = (
        make_event(
            1,
            EventType.FILE_RENAME,
            {"old_path": "/work/old", "new_path": "/work/new", "flags": None},
            monotonic_ns=T0 + 1_000_000,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))
    node = result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT)[0]
    assert node.attributes["paths"] == ["/work/new", "/work/old"]
    assert node.attributes["event_types"] == ["file.rename"]


def test_error_events_keep_result_breakdown(serial) -> None:
    from agent_probe.events import EventResult

    events = (
        make_event(
            1,
            EventType.FILE_OPEN,
            {"path": "/work/denied", "flags": 0, "fd": None},
            monotonic_ns=T0 + 1_000_000,
            result=EventResult.ERROR,
            error_code=13,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))
    node = result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT)[0]
    assert node.attributes["results"] == {"error": 1}
    assert node.attributes["event_count"] == 1
