"""容器归因：只在注入 ContainerResolver 且命中时才建立容器边。

brief 原文：*"只有在注入 ContainerResolver 且 cgroup_id/pid 命中时才建立
CONTAINER 边；没有 resolver 时不得假装知道容器归属，相关节点保持原状并在
evidence 里说明未启用。"*
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
    PID,
    T0,
    FakeContainerResolver,
    make_event,
    make_task,
    payload_file_write,
    payload_process_exec,
)

CONTAINER_ID = "ctr-abc"


def _scenario(*, cgroup_id: int | None = None):
    events = (
        make_event(1, EventType.PROCESS_EXEC, payload_process_exec(), monotonic_ns=T0 + 1_000_000, cgroup_id=cgroup_id),
        make_event(
            2,
            EventType.FILE_WRITE,
            payload_file_write("/work/inside.txt"),
            monotonic_ns=T0 + 2_000_000,
            cgroup_id=cgroup_id,
        ),
    )
    task = make_task(labels={"container_id": CONTAINER_ID})
    return events, task


def _container_edges(result):
    return [edge for edge in result.edges if edge.basis is EdgeBasis.CONTAINER_MAPPING]


def test_resolver_host_pid_hit_creates_container_edges() -> None:
    events, task = _scenario()
    resolver = FakeContainerResolver(host_pids={CONTAINER_ID: PID})
    result = CorrelationEngine(CorrelationConfig(), resolver).correlate(events, (), (task,))

    containers = result.nodes_of_kind(EvidenceNodeKind.CONTAINER)
    assert len(containers) == 1
    assert containers[0].attributes["container_id"] == CONTAINER_ID
    assert containers[0].attributes["resolved_host_pid"] == PID

    edges = _container_edges(result)
    assert len(edges) == 2  # PROCESS → CONTAINER 与 CONTAINER → TASK
    assert all(edge.confidence is Confidence.CERTAIN for edge in edges)
    assert all("ContainerResolver" in " ".join(edge.evidence) for edge in edges)

    # 容器 → 任务 → 进程：进程最终也能归到任务（经容器）。
    process = result.nodes_of_kind(EvidenceNodeKind.PROCESS)[0]
    attribution = node_attribution(result, process.node_id)
    assert attribution.confidence is Confidence.CERTAIN
    assert attribution.targets == (containers[0].node_id,) or attribution.targets == (
        result.nodes_of_kind(EvidenceNodeKind.TASK)[0].node_id,
    )
    assert resolver.queries == [("host_pid", CONTAINER_ID), ("cgroup_id", CONTAINER_ID)]


def test_resolver_cgroup_hit_creates_container_edge() -> None:
    events, task = _scenario(cgroup_id=4242)
    resolver = FakeContainerResolver(cgroup_ids={CONTAINER_ID: 4242})
    result = CorrelationEngine(CorrelationConfig(), resolver).correlate(events, (), (task,))

    edges = _container_edges(result)
    assert edges
    assert any(
        "resolve_cgroup_id" in " ".join(edge.evidence) for edge in edges
    )
    task_id = result.nodes_of_kind(EvidenceNodeKind.TASK)[0].node_id
    container_id = result.nodes_of_kind(EvidenceNodeKind.CONTAINER)[0].node_id
    assert node_attribution(result, container_id).targets == (task_id,)


def test_resolver_miss_creates_no_container_node() -> None:
    events, task = _scenario(cgroup_id=4242)
    resolver = FakeContainerResolver()
    result = CorrelationEngine(CorrelationConfig(), resolver).correlate(events, (), (task,))

    assert result.nodes_of_kind(EvidenceNodeKind.CONTAINER) == ()
    assert _container_edges(result) == []
    assert any("未能解析" in note for note in result.notes)
    task_node = result.nodes_of_kind(EvidenceNodeKind.TASK)[0]
    assert task_node.attributes["container_mapping"] == "unresolved"
    # 进程本身仍然按血缘/cgroup 正常归属，不被容器缺失影响。
    assert result.stats.determinate_coverage == 1.0


def test_without_resolver_no_container_attribution_at_all() -> None:
    events, task = _scenario(cgroup_id=4242)
    result = CorrelationEngine(CorrelationConfig(), None).correlate(events, (), (task,))

    assert result.nodes_of_kind(EvidenceNodeKind.CONTAINER) == ()
    assert _container_edges(result) == []
    assert any("未注入 ContainerResolver" in note for note in result.notes)
    task_node = result.nodes_of_kind(EvidenceNodeKind.TASK)[0]
    assert task_node.attributes["container_mapping"] == "no_resolver"
    assert all(
        edge.basis is not EdgeBasis.CONTAINER_MAPPING for edge in result.edges
    )


def test_container_mapping_switch_off_skips_resolver_entirely() -> None:
    events, task = _scenario()
    resolver = FakeContainerResolver(host_pids={CONTAINER_ID: PID})
    result = CorrelationEngine(
        CorrelationConfig(use_container_mapping=False), resolver
    ).correlate(events, (), (task,))

    assert result.nodes_of_kind(EvidenceNodeKind.CONTAINER) == ()
    assert resolver.queries == []  # 关掉开关就不要去查询
    assert any("use_container_mapping=False" in note for note in result.notes)


def test_task_without_container_label_is_not_queried() -> None:
    events = (
        make_event(1, EventType.FILE_WRITE, payload_file_write("/work/x"), monotonic_ns=T0 + 1),
    )
    resolver = FakeContainerResolver(host_pids={"whatever": PID})
    result = CorrelationEngine(CorrelationConfig(), resolver).correlate(
        events, (), (make_task(),)
    )
    assert resolver.queries == []
    assert result.nodes_of_kind(EvidenceNodeKind.CONTAINER) == ()
    task_node = result.nodes_of_kind(EvidenceNodeKind.TASK)[0]
    assert task_node.attributes["container_mapping"] == "no_container_label"


def test_resolver_returns_none_for_both_lookups_is_reported_not_guessed() -> None:
    events, task = _scenario()
    resolver = FakeContainerResolver(host_pids={CONTAINER_ID: None}, cgroup_ids={CONTAINER_ID: None})
    result = CorrelationEngine(CorrelationConfig(), resolver).correlate(events, (), (task,))
    assert _container_edges(result) == []
    assert any("未能解析" in note for note in result.notes)


def test_pid_reuse_during_container_pid_match_is_only_probable() -> None:
    events = (
        make_event(
            1,
            EventType.FILE_WRITE,
            payload_file_write("/work/one.txt"),
            monotonic_ns=T0 - 10_000_000,
            process_start_id=111,
        ),
        make_event(
            2,
            EventType.FILE_WRITE,
            payload_file_write("/work/two.txt"),
            monotonic_ns=T0 + 1_000_000,
            process_start_id=222,
        ),
    )
    task = make_task(process_start_ids=frozenset({111, 222}), labels={"container_id": CONTAINER_ID})
    resolver = FakeContainerResolver(host_pids={CONTAINER_ID: PID})
    result = CorrelationEngine(CorrelationConfig(), resolver).correlate(events, (), (task,))

    process_edges = [
        edge
        for edge in _container_edges(result)
        if result.node_by_id()[edge.src_node_id].kind is EvidenceNodeKind.PROCESS
    ]
    assert len(process_edges) == 2  # 两个同 pid 实例都被 pid 命中
    assert all(edge.confidence is Confidence.PROBABLE for edge in process_edges)
    assert all(
        any("PID 复用" in item for item in edge.evidence) for edge in process_edges
    )


def test_container_label_keys_are_case_insensitive_and_prioritised() -> None:
    events = (
        make_event(1, EventType.FILE_WRITE, payload_file_write("/work/x"), monotonic_ns=T0 + 1),
    )
    resolver = FakeContainerResolver(host_pids={"docker-9": PID})
    task = make_task(labels={"Docker": "docker-9"})
    result = CorrelationEngine(CorrelationConfig(), resolver).correlate(events, (), (task,))
    containers = result.nodes_of_kind(EvidenceNodeKind.CONTAINER)
    assert len(containers) == 1
    assert containers[0].attributes["container_id"] == "docker-9"
    assert resolver.queries[0] == ("host_pid", "docker-9")


def test_container_resolver_must_implement_the_protocol() -> None:
    import pytest

    from agent_probe.correlate import CorrelationInputError

    with pytest.raises(CorrelationInputError):
        CorrelationEngine(CorrelationConfig(), container_resolver=object())
