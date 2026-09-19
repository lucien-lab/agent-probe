"""进程血缘：fork/exec、短命子进程、PID 复用、run 前已存在的进程。

要求（见 brief）：

* ``process.fork`` 的 ``parent_pid``/``child_pid``/``child_start_id`` 用来建立
  父子关系，子进程的文件/网络事件归到同一任务；
* 同一 pid 不同 ``process_start_id`` 视为**不同进程**，不得串味；
* run 开始前就存在、且无法确定父链的进程 → ``UNKNOWN``，不猜。
"""

from __future__ import annotations

from agent_probe.correlate import (
    Confidence,
    CorrelationConfig,
    CorrelationEngine,
    EdgeBasis,
    EvidenceNodeKind,
    node_attribution,
)
from agent_probe.events import EventType

from correlate.fixtures import (
    CHILD_PID,
    CHILD_START,
    PID,
    PROC_START,
    RUN_A,
    RUN_B,
    T0,
    make_event,
    make_task,
    payload_file_write,
    payload_process_exec,
    payload_process_exit,
    payload_process_fork,
)


def _process_node(result, pid: int, start_id: int | None):
    matches = [
        node
        for node in result.nodes_of_kind(EvidenceNodeKind.PROCESS)
        if node.attributes["pid"] == pid and node.attributes["process_start_id"] == start_id
    ]
    assert len(matches) == 1, (pid, start_id, matches)
    return matches[0]


def _fork_edges(result) -> list:
    """只匹配 process.fork 造出的父子边（排除"经 fork 链到达根进程"的归属边）。"""

    return [
        edge
        for edge in result.edges
        if any("process.fork 事件" in item for item in edge.evidence)
    ]


def _task_id(result) -> str:
    nodes = result.nodes_of_kind(EvidenceNodeKind.TASK)
    assert len(nodes) == 1
    return nodes[0].node_id


def _child_task_scenario():
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000),
        make_event(
            2,
            EventType.PROCESS_FORK,
            payload_process_fork(),
            monotonic_ns=T0 + 2_000_000,
        ),
        make_event(
            3,
            EventType.PROCESS_EXEC,
            payload_process_exec("/bin/sh"),
            monotonic_ns=T0 + 3_000_000,
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=CHILD_START,
        ),
        make_event(
            4,
            EventType.FILE_WRITE,
            payload_file_write("/work/child.txt"),
            monotonic_ns=T0 + 4_000_000,
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=CHILD_START,
        ),
        make_event(
            5,
            EventType.TLS_BYTES,
            {"direction": "write", "bytes": 32, "connection_id": "conn-child", "plaintext_included": False, "truncated": False},
            monotonic_ns=T0 + 5_000_000,
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=CHILD_START,
        ),
        make_event(
            6,
            EventType.PROCESS_EXIT,
            payload_process_exit(exit_code=3),
            monotonic_ns=T0 + 6_000_000,
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=CHILD_START,
        ),
    )
    return events, (make_task(),)


def test_fork_child_effects_belong_to_the_same_task() -> None:
    events, tasks = _child_task_scenario()
    result = CorrelationEngine().correlate(events, (), tasks)
    task_id = _task_id(result)

    child = _process_node(result, CHILD_PID, CHILD_START)
    assert node_attribution(result, child.node_id).confidence is Confidence.CERTAIN
    assert node_attribution(result, child.node_id).targets == (task_id,)

    for node in result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT):
        attribution = node_attribution(result, node.node_id)
        assert attribution.confidence is Confidence.CERTAIN
        assert attribution.targets == (task_id,)

    child_lineage = [
        edge
        for edge in result.outgoing(child.node_id)
        if edge.basis is EdgeBasis.PROCESS_LINEAGE
    ]
    assert any(edge.confidence is Confidence.CERTAIN for edge in child_lineage)
    assert any(
        edge.dst_node_id == _process_node(result, PID, PROC_START).node_id
        and edge.confidence is Confidence.CERTAIN
        for edge in child_lineage
    )


def test_short_lived_child_keeps_exec_and_exit_evidence() -> None:
    events, tasks = _child_task_scenario()
    result = CorrelationEngine().correlate(events, (), tasks)

    child = _process_node(result, CHILD_PID, CHILD_START)
    assert child.attributes["exec_count"] == 1
    assert child.attributes["exe"] == "/bin/sh"
    assert child.attributes["has_process_exit"] is True
    assert child.attributes["exit_code"] == 3
    assert child.attributes["event_count"] == 4  # exec + file.write + tls.bytes + exit
    assert child.attributes["observed_via"] == ["event"]
    parent = _process_node(result, PID, PROC_START)
    assert parent.node_id != child.node_id
    # fork 事件造出的父子边存在且指向正确的两个实例。
    fork_edges = _fork_edges(result)
    assert [(edge.src_node_id, edge.dst_node_id) for edge in fork_edges] == [
        (child.node_id, parent.node_id)
    ]


def test_child_with_no_events_of_its_own_still_gets_a_process_node() -> None:
    # 短命子进程：fork 之后立刻 exit，且中间没有任何其他事件（探针可能只抓到这两条）。
    events = (
        make_event(
            1,
            EventType.PROCESS_FORK,
            payload_process_fork(child_start_id=None),
            monotonic_ns=T0 + 1_000_000,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))
    children = [
        node
        for node in result.nodes_of_kind(EvidenceNodeKind.PROCESS)
        if node.attributes["process_start_id"] is None
    ]
    assert len(children) == 1
    assert "fork_child" in children[0].attributes["observed_via"]
    assert children[0].attributes["event_count"] == 0


def test_pid_reuse_creates_two_processes_and_no_cross_talk() -> None:
    other_start = 999
    events = (
        make_event(
            1,
            EventType.FILE_WRITE,
            payload_file_write("/work/reused.txt"),
            monotonic_ns=T0 - 50_000_000,  # 任务窗口开始前就已存在
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=other_start,
        ),
        make_event(
            2,
            EventType.PROCESS_FORK,
            payload_process_fork(),
            monotonic_ns=T0 + 1_000_000,
        ),
        make_event(
            3,
            EventType.FILE_WRITE,
            payload_file_write("/work/child.txt"),
            monotonic_ns=T0 + 2_000_000,
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=CHILD_START,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))
    task_id = _task_id(result)

    older = _process_node(result, CHILD_PID, other_start)
    child = _process_node(result, CHILD_PID, CHILD_START)
    assert older.node_id != child.node_id

    older_attribution = node_attribution(result, older.node_id)
    assert older_attribution.confidence is Confidence.UNKNOWN
    assert older_attribution.determinate is False

    child_attribution = node_attribution(result, child.node_id)
    assert child_attribution.confidence is Confidence.CERTAIN
    assert child_attribution.targets == (task_id,)

    # 两个同 pid 不同 start_id 的文件事件不得合并成一个节点。
    file_nodes = {
        node.attributes["paths"][0]: node
        for node in result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT)
    }
    assert set(file_nodes) == {"/work/reused.txt", "/work/child.txt"}
    assert node_attribution(result, file_nodes["/work/child.txt"].node_id).confidence is Confidence.CERTAIN
    assert node_attribution(result, file_nodes["/work/reused.txt"].node_id).confidence is Confidence.UNKNOWN


def test_fork_edge_uses_child_start_id_to_pick_the_right_instance() -> None:
    other_start = 111
    events = (
        make_event(
            1,
            EventType.FILE_WRITE,
            payload_file_write("/work/other.txt"),
            monotonic_ns=T0 + 500_000,
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=other_start,
        ),
        make_event(2, EventType.PROCESS_FORK, payload_process_fork(), monotonic_ns=T0 + 1_000_000),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))

    child = _process_node(result, CHILD_PID, CHILD_START)
    parent = _process_node(result, PID, PROC_START)
    fork_edges = _fork_edges(result)
    assert len(fork_edges) == 1
    edge = fork_edges[0]
    assert edge.src_node_id == child.node_id
    assert edge.dst_node_id == parent.node_id
    assert edge.confidence is Confidence.CERTAIN
    assert "start_id=777" in edge.evidence[0]


def test_fork_without_child_start_id_is_only_probable() -> None:
    payload = payload_process_fork(child_start_id=None)
    events = (
        make_event(1, EventType.PROCESS_FORK, payload, monotonic_ns=T0 + 1_000_000),
        make_event(
            2,
            EventType.FILE_WRITE,
            payload_file_write("/work/child.txt"),
            monotonic_ns=T0 + 2_000_000,
            pid=CHILD_PID,
            tid=CHILD_PID,
            process_start_id=None,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))

    fork_edges = _fork_edges(result)
    assert len(fork_edges) == 1
    assert fork_edges[0].confidence is Confidence.PROBABLE
    assert any("child_start_id 未采集" in item for item in fork_edges[0].evidence)

    child = _process_node(result, CHILD_PID, None)
    assert child.attributes["start_id_known"] is False
    file_edge = [
        edge
        for edge in result.edges
        if edge.src_node_id
        in {node.node_id for node in result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT)}
    ]
    assert file_edge and all(edge.confidence is Confidence.PROBABLE for edge in file_edge)


def test_fork_event_without_parent_start_id_is_probable() -> None:
    events = (
        make_event(
            1,
            EventType.PROCESS_FORK,
            payload_process_fork(),
            monotonic_ns=T0 + 1_000_000,
            process_start_id=None,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))
    fork_edges = _fork_edges(result)
    assert len(fork_edges) == 1
    assert fork_edges[0].confidence is Confidence.PROBABLE
    assert any("process_start_id 未采集" in item for item in fork_edges[0].evidence)


def test_process_matching_task_cgroup_is_certain_without_container_resolver() -> None:
    events = (
        make_event(
            1,
            EventType.FILE_WRITE,
            payload_file_write("/work/cg.txt"),
            monotonic_ns=T0 - 10_000_000,  # 比任务窗口更早：cgroup 命中必须仍然给 CERTAIN
            process_start_id=None,
            cgroup_id=4242,
        ),
    )
    task = make_task(process_start_ids=frozenset(), cgroup_id=4242)
    result = CorrelationEngine().correlate(events, (), (task,))
    node = result.nodes_of_kind(EvidenceNodeKind.PROCESS)[0]
    attribution = node_attribution(result, node.node_id)
    assert attribution.confidence is Confidence.CERTAIN
    edge = [
        edge
        for edge in result.outgoing(node.node_id)
        if edge.basis is EdgeBasis.RUN_ID_MARKER
    ][0]
    assert "cgroup_id=4242" in edge.evidence[0]


def test_process_started_before_task_window_without_evidence_is_unknown() -> None:
    events = (
        make_event(
            1,
            EventType.FILE_WRITE,
            payload_file_write("/work/old.txt"),
            monotonic_ns=T0 - 1_000_000,
            process_start_id=None,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(),))
    node = result.nodes_of_kind(EvidenceNodeKind.PROCESS)[0]
    attribution = node_attribution(result, node.node_id)
    assert attribution.confidence is Confidence.UNKNOWN
    edge = result.outgoing(node.node_id)[0]
    assert edge.confidence is Confidence.UNKNOWN
    assert any("不猜测" in item for item in edge.evidence)


def test_process_seen_during_window_without_birth_event_is_only_probable() -> None:
    events = (
        make_event(
            1,
            EventType.FILE_WRITE,
            payload_file_write("/work/maybe.txt"),
            monotonic_ns=T0 + 1_000_000,
            pid=7000,
            tid=7000,
            process_start_id=4321,
        ),
    )
    # 任务根集合里没有 4321，也没有 cgroup/血缘证据。
    result = CorrelationEngine().correlate(
        events, (), (make_task(process_start_ids=frozenset({PROC_START})),)
    )
    node = result.nodes_of_kind(EvidenceNodeKind.PROCESS)[0]
    attribution = node_attribution(result, node.node_id)
    assert attribution.confidence is Confidence.PROBABLE
    assert attribution.determinate is True


def test_lineage_switch_off_downgrades_root_process_to_probable() -> None:
    events, tasks = _child_task_scenario()
    baseline = CorrelationEngine().correlate(events, (), tasks)
    ablated = CorrelationEngine(
        CorrelationConfig(use_process_lineage=False)
    ).correlate(events, (), tasks)

    assert baseline.stats.nodes_certain > 0
    assert ablated.stats.nodes_certain == 0
    assert ablated.stats.nodes_probable > 0
    # 关闭血缘后不再有"根进程/后代"边，fork 链本身也一并关闭。
    assert _fork_edges(ablated) == []


def test_events_from_another_run_do_not_leak_into_the_task() -> None:
    events = (
        make_event(
            1,
            EventType.FILE_WRITE,
            payload_file_write("/work/other-run.txt"),
            monotonic_ns=T0 + 1_000_000,
            run_id=RUN_B,
            process_start_id=PROC_START,
        ),
    )
    result = CorrelationEngine().correlate(events, (), (make_task(run_id=RUN_A),))
    node = result.nodes_of_kind(EvidenceNodeKind.FILE_EFFECT)[0]
    attribution = node_attribution(result, node.node_id)
    assert attribution.confidence is Confidence.UNKNOWN
    assert attribution.targets == ()
