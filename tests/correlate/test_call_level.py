"""调用级关联：连接身份 vs 时间接近。

* ``tls.bytes.payload.connection_id`` 与 ``LlmCallRecord.connection_id`` 精确相等
  → ``CONNECTION_ID`` + ``CERTAIN``；
* 只有时间接近（或只有声明时间）→ 最高 ``PROBABLE``，绝不能当唯一归因的确定证据；
* 没有时间锚点也没有连接 → ``UNKNOWN``（不猜）。
"""

from __future__ import annotations

from agent_probe.correlate import (
    AssistantMarkers,
    Confidence,
    CorrelationConfig,
    CorrelationEngine,
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
    RUN_B,
    T0,
    make_call,
    make_event,
    make_task,
    payload_file_write,
    payload_process_exec,
    payload_tls,
)


def _call_node(result):
    nodes = result.nodes_of_kind(EvidenceNodeKind.LLM_CALL)
    assert len(nodes) == 1
    return nodes[0]


def _only_file_node(result):
    nodes = result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT)
    assert len(nodes) == 1
    return nodes[0]


def test_connection_id_exact_match_is_certain() -> None:
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(2, EventType.TLS_BYTES, payload_tls("conn-1"), monotonic_ns=T0 + 2_000_000),
    )
    calls = (make_call("req-1", "conn-1"),)
    result = CorrelationEngine().correlate(events, calls, (make_task(),))

    call = _call_node(result)
    attribution = node_attribution(result, call.node_id)
    assert attribution.confidence is Confidence.CERTAIN
    connection_edges = [
        edge for edge in result.edges if edge.basis is EdgeBasis.CONNECTION_ID
    ]
    assert len(connection_edges) == 1
    assert connection_edges[0].confidence is Confidence.CERTAIN
    assert "精确相等" in " ".join(connection_edges[0].evidence)


def test_connection_id_mismatch_leaves_the_call_unknown() -> None:
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(2, EventType.TLS_BYTES, payload_tls("conn-other"), monotonic_ns=T0 + 2_000_000),
    )
    calls = (make_call("req-1", "conn-1"),)
    result = CorrelationEngine().correlate(events, calls, (make_task(),))

    call = _call_node(result)
    assert node_attribution(result, call.node_id).confidence is Confidence.UNKNOWN
    assert not [
        edge for edge in result.edges if edge.basis is EdgeBasis.CONNECTION_ID
    ]
    assert call.attributes["anchor_monotonic_ns"] is None
    assert call.attributes["anchor_run_ids"] == []


def test_time_proximity_alone_never_exceeds_probable() -> None:
    # 声明只给出 call_id + pid + 时间（没有 connection_id，系统里也没有该调用的
    # tls.bytes 事件）：每一项虽能单独核验到"存在"，但没有任何东西证明"这一对"，
    # 因此最高只能 PROBABLE。
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(2, EventType.FILE_WRITE, payload_file_write("/work/a.txt"), monotonic_ns=T0 + 3_000_000),
    )
    calls = (make_call("req-1", "conn-1"),)
    markers = AssistantMarkers.from_records(
        [
            {
                "call_id": "req-1",
                "pid": PID,
                "process_start_id": PROC_START,
                "run_id": RUN_A,
                "monotonic_ns": T0 + 3_000_000,
            }
        ]
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, (make_task(),), markers
    )

    call = _call_node(result)
    attribution = node_attribution(result, call.node_id)
    assert attribution.confidence is Confidence.PROBABLE
    assert attribution.determinate is True
    assert not [edge for edge in result.edges if edge.basis is EdgeBasis.CONNECTION_ID]
    link_edges = [
        edge
        for edge in result.outgoing(call.node_id)
        if edge.basis in (EdgeBasis.CALL_ID_MARKER, EdgeBasis.RUN_ID_MARKER, EdgeBasis.TIME_WINDOW)
    ]
    assert link_edges
    assert all(edge.confidence is Confidence.PROBABLE for edge in link_edges)
    assert any(
        "没有可用的身份桥" in item
        for edge in link_edges
        for item in edge.evidence
    )


def test_effect_to_call_edge_is_only_probable_even_with_one_candidate() -> None:
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(2, EventType.TLS_BYTES, payload_tls("conn-1"), monotonic_ns=T0 + 2_000_000),
        make_event(3, EventType.FILE_WRITE, payload_file_write("/work/a.txt"), monotonic_ns=T0 + 3_000_000),
    )
    calls = (make_call("req-1", "conn-1"),)
    result = CorrelationEngine().correlate(events, calls, (make_task(),))

    edge = [
        edge
        for edge in result.outgoing(_only_file_node(result).node_id)
        if edge.basis is EdgeBasis.TIME_WINDOW
    ][0]
    assert edge.confidence is Confidence.PROBABLE
    assert any("时间接近本身不足以给出确定性归因" in item for item in edge.evidence)


def test_calls_without_any_event_have_no_anchor() -> None:
    events = (make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),)
    calls = (make_call("req-1", "conn-1"),)
    result = CorrelationEngine().correlate(events, calls, (make_task(),))

    call = _call_node(result)
    assert node_attribution(result, call.node_id).confidence is Confidence.UNKNOWN
    assert call.attributes["tls_event_nodes"] == []


def test_connection_shared_by_two_tasks_makes_the_call_ambiguous() -> None:
    # 同一个 connection_id 被两个任务（两个 run）的进程使用 → 连接身份不再指向
    # 唯一任务，必须保留两个候选。
    events = (
        make_event(1, EventType.TLS_BYTES, payload_tls("conn-1"), monotonic_ns=T0 + 1_000_000),
        make_event(
            2,
            EventType.TLS_BYTES,
            payload_tls("conn-1", direction="read", byte_count=64),
            monotonic_ns=T0 + 2_000_000,
            run_id=RUN_B,
            pid=2000,
            tid=2000,
            process_start_id=999_001,
        ),
    )
    calls = (make_call("req-1", "conn-1"),)
    tasks = (
        make_task(run_id=RUN_A, label="task-a"),
        make_task(run_id=RUN_B, label="task-b", process_start_ids=frozenset({999_001})),
    )
    result = CorrelationEngine().correlate(events, calls, tasks)

    call = _call_node(result)
    attribution = node_attribution(result, call.node_id)
    assert attribution.confidence is Confidence.AMBIGUOUS
    assert len(attribution.targets) == 2
    assert attribution.determinate is False
    assert len(call.attributes["tls_event_nodes"]) == 2
    assert call.attributes["anchor_run_ids"] == [RUN_A, RUN_B]



def test_connection_nodes_are_not_attributed_to_a_single_call() -> None:
    # 连接节点代表连接本身（可被多个调用复用）→ 不产生 effect→call 的 TIME_WINDOW 边。
    events = (
        make_event(1, EventType.TLS_BYTES, payload_tls("conn-1"), monotonic_ns=T0 + 1_000_000),
        make_event(2, EventType.TLS_BYTES, payload_tls("conn-1", direction="read", byte_count=8), monotonic_ns=T0 + 2_000_000),
    )
    calls = (make_call("req-1", "conn-1"), make_call("req-2", "conn-1", index=1))
    result = CorrelationEngine().correlate(events, calls, (make_task(),))

    tls_node = next(
        node
        for node in result.nodes_of_kind(EvidenceNodeKind.NET_EFFECT)
        if node.attributes["connection_id"] == "conn-1"
    )
    outgoing = result.outgoing(tls_node.node_id)
    assert all(edge.basis is EdgeBasis.PROCESS_LINEAGE for edge in outgoing)
    assert result.stats.edges_ambiguous == 0


def test_call_time_anchor_comes_from_matching_connection_events_only() -> None:
    events = (
        make_event(1, EventType.TLS_BYTES, payload_tls("conn-1"), monotonic_ns=T0 + 5_000_000),
        make_event(2, EventType.TLS_BYTES, payload_tls("conn-1", direction="read", byte_count=4), monotonic_ns=T0 + 9_000_000),
        make_event(3, EventType.TLS_BYTES, payload_tls("conn-2"), monotonic_ns=T0 + 1_000_000),
    )
    calls = (make_call("req-1", "conn-1"),)
    result = CorrelationEngine().correlate(events, calls, (make_task(),))
    call = _call_node(result)
    assert call.attributes["anchor_monotonic_ns"] == T0 + 5_000_000
    assert call.attributes["anchor_run_ids"] == [RUN_A]


def test_assisted_call_marker_without_identity_bridge_is_probable() -> None:
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
    )
    calls = (make_call("req-1", "conn-1"),)
    markers = AssistantMarkers.from_records(
        [
            {
                "call_id": "req-1",
                "task_label": "assisted-task",
                "pid": PID,
                "process_start_id": PROC_START,
                "monotonic_ns": T0 + 1_500_000,
            }
        ]
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, (make_task(label="assisted-task"),), markers
    )
    call = _call_node(result)
    attribution = node_attribution(result, call.node_id)
    # 任务归属确定（唯一），但置信度被"没有身份桥"压在 PROBABLE。
    assert attribution.confidence is Confidence.PROBABLE
    assert attribution.targets == (result.nodes_of_kind(EvidenceNodeKind.TASK)[0].node_id,)
    bases = {edge.basis for edge in result.outgoing(call.node_id)}
    assert EdgeBasis.RUN_ID_MARKER in bases
    assert EdgeBasis.CALL_ID_MARKER in bases
    assert all(
        edge.confidence is Confidence.PROBABLE
        for edge in result.outgoing(call.node_id)
        if edge.basis in (EdgeBasis.RUN_ID_MARKER, EdgeBasis.CALL_ID_MARKER)
    )


def test_assisted_call_marker_with_connection_bridge_is_certain() -> None:
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(2, EventType.TLS_BYTES, payload_tls("conn-1"), monotonic_ns=T0 + 2_000_000),
    )
    calls = (make_call("req-1", "conn-1"),)
    markers = AssistantMarkers.from_records(
        [
            {
                "call_id": "req-1",
                "connection_id": "conn-1",
                "task_label": "assisted-task",
                "pid": PID,
                "process_start_id": PROC_START,
                "monotonic_ns": T0 + 1_500_000,
            }
        ]
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, (make_task(label="assisted-task"),), markers
    )
    call = _call_node(result)
    assert node_attribution(result, call.node_id).confidence is Confidence.CERTAIN
    assert any(
        edge.confidence is Confidence.CERTAIN
        for edge in result.outgoing(call.node_id)
        if edge.basis is EdgeBasis.CALL_ID_MARKER
    )


def test_assisted_marker_with_unknown_call_id_is_not_certain() -> None:
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
    )
    calls = (make_call("req-1", "conn-1"),)
    markers = AssistantMarkers.from_records([{"call_id": "req-unknown", "tool_id": "t1"}])
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, (make_task(),), markers
    )
    tool = result.nodes_of_kind(EvidenceNodeKind.TOOL_CALL)[0]
    assert node_attribution(result, tool.node_id).confidence is Confidence.UNKNOWN
    assert result.outgoing(tool.node_id) == ()
    assert tool.attributes["verification"]["checks"]["call_id"] == "unverifiable"


def test_correlation_id_on_system_events_is_a_second_verification_source() -> None:
    # 系统侧事件带 correlation_id，与声明一致 → 双向核验通过（CERTAIN）。
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(
            2,
            EventType.FILE_WRITE,
            payload_file_write("/work/propagated.txt"),
            monotonic_ns=T0 + 1_000_000_000,  # 故意远离声明的工具时间片
            correlation_id="tool-1",
        ),
    )
    calls = (make_call("req-1", "conn-1"),)
    markers = AssistantMarkers.from_records(
        [
            {
                "call_id": "req-1",
                "tool_id": "tool-1",
                "pid": PID,
                "process_start_id": PROC_START,
                "monotonic_ns": T0 + 2_000_000,
            }
        ]
    )
    result = CorrelationEngine(CorrelationConfig(use_assisted_markers=True)).correlate(
        events, calls, (make_task(),), markers
    )
    file_node = _only_file_node(result)
    edges = [
        edge
        for edge in result.outgoing(file_node.node_id)
        if edge.basis is EdgeBasis.TOOL_ID_MARKER
    ]
    assert len(edges) == 1
    assert edges[0].confidence is Confidence.CERTAIN
    assert any("correlation_id" in item for item in edges[0].evidence)
    assert node_attribution(result, file_node.node_id).confidence is Confidence.CERTAIN


def test_task_declaration_validation_rejects_duplicate_run_ids() -> None:
    task_a = make_task(label="a")
    task_b = Task(
        run_id=RUN_A,
        label="b",
        process_start_ids=frozenset({PROC_START}),
        started_monotonic_ns=T0,
    )
    events = (make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1),)
    try:
        CorrelationEngine().correlate(events, (), (task_a, task_b))
    except Exception as exc:  # noqa: BLE001 - 明确断言异常类型
        assert type(exc).__name__ == "CorrelationInputError"
    else:  # pragma: no cover - 必须抛异常
        raise AssertionError("重复且内容不同的 run_id 任务声明必须报错")
