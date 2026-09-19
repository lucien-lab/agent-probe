"""``ContainerTaskMapper``：四种 outcome、时间窗竞态、有界候选与证据。

原则：容器由 Docker daemon 创建，**不是** agent 的子进程。因此这里只验证
"label + inspect 真值字段 + 调用方时间窗" 这条链路，绝不出现进程树推断，
也不把"最近创建/最近退出"当成唯一映射。
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_probe.container import (
    MAX_EVIDENCE_ITEMS,
    ContainerQueryError,
    ContainerState,
    ContainerTaskMapper,
    ContainerValidationError,
    MappingOutcome,
    MountType,
    canonical_json,
)

from fake_container_query import (
    BASE_NS,
    LABEL,
    LABEL_KEY,
    MINUTE_NS,
    SECOND_NS,
    FakeContainerQuery,
    container_id,
    inspect_payload,
    mount_entry,
    short_id,
)

#: 观测时刻（单调时钟纳秒，显式传入保证可复现）。
NOW_NS = 9_000_000_000


def mapper_for(query: Any, **kwargs: Any) -> ContainerTaskMapper:
    return ContainerTaskMapper(query, **kwargs)


def labelled(
    query: FakeContainerQuery,
    seed: int,
    *,
    label: str = LABEL,
    listed_id: str | None = None,
    **payload_kwargs: Any,
) -> str:
    """登记一个带任务标签的容器。"""

    full = container_id(seed)
    query.add(
        inspect_payload(full, labels={LABEL_KEY: label}, **payload_kwargs),
        listed_id=listed_id,
    )
    return full


# --------------------------------------------------------------------------- #
# MAPPED
# --------------------------------------------------------------------------- #


def test_unique_label_match_is_mapped() -> None:
    query = FakeContainerQuery()
    full = labelled(query, 0x01)
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.MAPPED
    assert mapping.reason is None
    assert mapping.mapping is not None and mapping.mapping.container_id == full
    assert mapping.candidates == (mapping.mapping,)
    assert mapping.mounts == ()
    assert mapping.observed_monotonic_ns == NOW_NS
    assert mapping.task_label == LABEL


def test_mapped_carries_mounts_and_resolver_works() -> None:
    query = FakeContainerQuery()
    labelled(
        query,
        0x02,
        mounts=[mount_entry(source="/host/data", destination="/data")],
    )
    mapper = mapper_for(query)
    mapping = mapper.map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.MAPPED
    assert len(mapping.mounts) == 1
    assert mapping.mounts[0].destination == "/data"
    resolver = mapper.resolver_for(mapping)
    assert resolver.to_host("/data/report.json") == "/host/data/report.json"
    assert resolver.container_id == mapping.mapping.container_id  # type: ignore[union-attr]


def test_mapped_container_without_mounts_has_empty_mounts() -> None:
    query = FakeContainerQuery()
    labelled(query, 0x03)
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert mapping.mounts == ()


def test_mapped_exited_container_within_window_is_kept() -> None:
    """已退出但仍处于时间窗内的容器必须如实进入候选（不因为"退出"而被丢弃）。"""

    query = FakeContainerQuery()
    full = labelled(
        query,
        0x04,
        status="exited",
        pid=0,
        created_ns=BASE_NS,
        started_ns=BASE_NS,
        finished_ns=BASE_NS + MINUTE_NS,
    )
    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_after_ns=BASE_NS - SECOND_NS,
        container_created_before_ns=BASE_NS + SECOND_NS,
        observed_monotonic_ns=NOW_NS,
    )
    assert mapping.outcome is MappingOutcome.MAPPED
    assert mapping.mapping is not None
    assert mapping.mapping.container_id == full
    assert mapping.mapping.state is ContainerState.EXITED
    assert mapping.mapping.finished_at_ns == BASE_NS + MINUTE_NS


def test_mapped_only_considers_matching_label_value() -> None:
    query = FakeContainerQuery()
    other = labelled(query, 0x05, label="other-task")
    wanted = labelled(query, 0x06)
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert mapping.outcome is MappingOutcome.MAPPED
    assert mapping.mapping is not None
    assert mapping.mapping.container_id == wanted != other


def test_mapped_when_list_uses_short_id() -> None:
    query = FakeContainerQuery()
    full = labelled(query, 0x07, listed_id=short_id(container_id(0x07)))
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert mapping.outcome is MappingOutcome.MAPPED
    assert mapping.mapping is not None and mapping.mapping.container_id == full


def test_observed_monotonic_ns_defaults_to_current_clock() -> None:
    query = FakeContainerQuery()
    labelled(query, 0x08)
    mapping = mapper_for(query).map_label(LABEL)
    assert isinstance(mapping.observed_monotonic_ns, int)
    assert mapping.observed_monotonic_ns > 0


# --------------------------------------------------------------------------- #
# UNMAPPED
# --------------------------------------------------------------------------- #


def test_no_containers_at_all_is_unmapped() -> None:
    mapping = mapper_for(FakeContainerQuery()).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert mapping.outcome is MappingOutcome.UNMAPPED
    assert mapping.mapping is None
    assert mapping.candidates == ()
    assert mapping.mounts == ()
    assert mapping.reason is not None and LABEL in mapping.reason
    assert any("命中 0 个容器" in note for note in mapping.evidence)


def test_containers_without_the_label_are_unmapped() -> None:
    query = FakeContainerQuery()
    labelled(query, 0x09, label="other-task")
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert mapping.outcome is MappingOutcome.UNMAPPED


def test_missing_label_key_is_unmapped() -> None:
    query = FakeContainerQuery()
    query.add(inspect_payload(container_id(0x0A), labels={"unrelated": "1"}))
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert mapping.outcome is MappingOutcome.UNMAPPED


def test_empty_label_value_never_matches_non_empty_label() -> None:
    query = FakeContainerQuery()
    labelled(query, 0x0B, label="")
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert mapping.outcome is MappingOutcome.UNMAPPED


def test_empty_label_query_is_rejected() -> None:
    with pytest.raises(ContainerValidationError, match="label 不能为空"):
        mapper_for(FakeContainerQuery()).map_label("", observed_monotonic_ns=NOW_NS)


@pytest.mark.parametrize("label", [None, 7, b"task"])
def test_non_string_label_is_rejected(label: Any) -> None:
    with pytest.raises(ContainerValidationError):
        mapper_for(FakeContainerQuery()).map_label(label, observed_monotonic_ns=NOW_NS)


def test_exited_container_created_before_window_with_unknown_finish_stays_candidate() -> None:
    """已退出、创建早于窗口起点、且结束时间未知：无法证明它没跨越窗口。

    真值不足时必须保留候选并标注不确定（降级为 AMBIGUOUS），
    既不丢弃真值也不假装确定。
    """

    query = FakeContainerQuery()
    old = labelled(query, 0x0C, created_ns=BASE_NS - MINUTE_NS, status="exited", pid=0)
    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_after_ns=BASE_NS,
        observed_monotonic_ns=NOW_NS,
    )
    assert mapping.outcome is MappingOutcome.AMBIGUOUS
    assert [item.container_id for item in mapping.candidates] == [old]
    assert mapping.reason is not None and "创建时间约束不满足" in mapping.reason
    assert any("finished_at_ns=None" in note for note in mapping.evidence)


def test_excluded_container_is_recorded_in_evidence_not_silently_dropped() -> None:
    query = FakeContainerQuery()
    old = labelled(
        query,
        0x0C,
        created_ns=BASE_NS - MINUTE_NS,
        started_ns=BASE_NS - MINUTE_NS,
        finished_ns=BASE_NS - SECOND_NS,
        status="exited",
        pid=0,
    )
    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_after_ns=BASE_NS,
        observed_monotonic_ns=NOW_NS,
    )
    assert mapping.outcome is MappingOutcome.UNMAPPED
    assert mapping.candidates == ()
    # 被排除的容器仍然出现在证据里，不是静默丢弃。
    assert any(old in note and "排除" in note for note in mapping.evidence)
    assert mapping.reason is not None and "时间" in mapping.reason


def test_container_created_after_window_upper_bound_is_excluded() -> None:
    query = FakeContainerQuery()
    late = labelled(query, 0x0D, created_ns=BASE_NS + 10 * MINUTE_NS)
    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_before_ns=BASE_NS,
        observed_monotonic_ns=NOW_NS,
    )
    assert mapping.outcome is MappingOutcome.UNMAPPED
    assert any(late in note and "上界" in note for note in mapping.evidence)


def test_container_finished_before_window_start_is_excluded() -> None:
    query = FakeContainerQuery()
    finished = labelled(
        query,
        0x0E,
        created_ns=BASE_NS - 2 * MINUTE_NS,
        started_ns=BASE_NS - 2 * MINUTE_NS,
        finished_ns=BASE_NS - MINUTE_NS,
        status="exited",
        pid=0,
    )
    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_after_ns=BASE_NS,
        observed_monotonic_ns=NOW_NS,
    )
    assert mapping.outcome is MappingOutcome.UNMAPPED
    assert any(finished in note and "就已结束" in note for note in mapping.evidence)


def test_short_lived_container_same_second_is_mapped_within_window() -> None:
    """短命任务：created/started/finished 落在同一秒内。

    纳秒精度必须保留（不能被截断成秒），且窗口判定按纳秒比较。
    """

    same_second = BASE_NS + 123_456_789
    query = FakeContainerQuery()
    full = labelled(
        query,
        0x10,
        status="exited",
        pid=0,
        created_ns=same_second,
        started_ns=same_second,
        finished_ns=same_second,
    )
    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_after_ns=BASE_NS,
        container_created_before_ns=BASE_NS + SECOND_NS,
        observed_monotonic_ns=NOW_NS,
    )

    assert mapping.outcome is MappingOutcome.MAPPED
    assert mapping.mapping is not None
    assert mapping.mapping.container_id == full
    assert mapping.mapping.created_at_ns == same_second
    assert mapping.mapping.started_at_ns == same_second
    assert mapping.mapping.finished_at_ns == same_second


def test_short_lived_container_same_second_outside_window_is_excluded() -> None:
    """同一秒内创建并结束的容器，若窗口在它之后，则按结束时间排除。"""

    same_second = BASE_NS + 123_456_789
    query = FakeContainerQuery()
    full = labelled(
        query,
        0x10,
        status="exited",
        pid=0,
        created_ns=same_second,
        started_ns=same_second,
        finished_ns=same_second,
    )
    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_after_ns=BASE_NS + 2 * SECOND_NS,
        observed_monotonic_ns=NOW_NS,
    )

    assert mapping.outcome is MappingOutcome.UNMAPPED
    assert any(
        full in note and "就已结束" in note for note in mapping.evidence
    )


def test_short_lived_container_same_second_window_boundary_is_inclusive() -> None:
    """窗口是闭区间：created_at 恰好等于窗口端点时仍然命中。"""

    exact = BASE_NS + 500_000_000
    query = FakeContainerQuery()
    labelled(
        query,
        0x10,
        status="exited",
        pid=0,
        created_ns=exact,
        started_ns=exact,
        finished_ns=exact,
    )
    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_after_ns=exact,
        container_created_before_ns=exact,
        observed_monotonic_ns=NOW_NS,
    )
    assert mapping.outcome is MappingOutcome.MAPPED


# --------------------------------------------------------------------------- #
# AMBIGUOUS
# --------------------------------------------------------------------------- #


def test_two_containers_with_same_label_are_ambiguous_and_complete() -> None:
    query = FakeContainerQuery()
    first = labelled(query, 0x11)
    second = labelled(query, 0x22, status="exited", pid=0)

    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.AMBIGUOUS
    assert mapping.mapping is None
    assert mapping.mounts == ()
    assert mapping.reason is not None and "2 个候选" in mapping.reason
    # 候选完整性：两个都在，且按 container_id 升序（报告可复现）。
    assert [item.container_id for item in mapping.candidates] == sorted([first, second])
    assert {item.container_id for item in mapping.candidates} == {first, second}


def test_ambiguous_candidates_include_exited_container_in_window() -> None:
    query = FakeContainerQuery()
    running = labelled(query, 0x33)
    exited = labelled(
        query,
        0x44,
        status="exited",
        pid=0,
        created_ns=BASE_NS,
        started_ns=BASE_NS,
        finished_ns=BASE_NS + SECOND_NS,
    )
    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_after_ns=BASE_NS - SECOND_NS,
        container_created_before_ns=BASE_NS + SECOND_NS,
        observed_monotonic_ns=NOW_NS,
    )
    assert mapping.outcome is MappingOutcome.AMBIGUOUS
    ids = {item.container_id for item in mapping.candidates}
    assert ids == {running, exited}


def test_ambiguous_is_sorted_and_independent_of_query_order() -> None:
    forward = FakeContainerQuery()
    labelled(forward, 0x55)
    labelled(forward, 0x66)
    backward = FakeContainerQuery()
    labelled(backward, 0x66)
    labelled(backward, 0x55)
    first = mapper_for(forward).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    second = mapper_for(backward).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert [item.container_id for item in first.candidates] == [
        item.container_id for item in second.candidates
    ]
    assert canonical_json(first.to_dict()) == canonical_json(second.to_dict())


def test_max_candidates_truncates_and_records_evidence() -> None:
    query = FakeContainerQuery()
    full_ids = [labelled(query, seed) for seed in range(1, 6)]

    mapping = mapper_for(query, max_candidates=2).map_label(
        LABEL, observed_monotonic_ns=NOW_NS
    )

    assert mapping.outcome is MappingOutcome.AMBIGUOUS
    assert len(mapping.candidates) == 2
    assert mapping.reason is not None and "截断" in mapping.reason
    assert any("截断" in note and "max_candidates=2" in note for note in mapping.evidence)
    # 截断保留 container_id 最小的前两个。
    assert [item.container_id for item in mapping.candidates] == sorted(full_ids)[:2]


def test_single_candidate_with_unknown_created_at_is_ambiguous_not_mapped() -> None:
    query = FakeContainerQuery()
    full = labelled(query, 0x77, created_ns=None)

    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_after_ns=BASE_NS,
        observed_monotonic_ns=NOW_NS,
    )

    assert mapping.outcome is MappingOutcome.AMBIGUOUS
    assert mapping.mapping is None
    assert len(mapping.candidates) == 1
    assert mapping.candidates[0].container_id == full
    assert mapping.reason is not None and "无法验证" in mapping.reason
    assert any("created_at_ns 缺失" in note for note in mapping.evidence)


def test_single_candidate_created_before_window_but_alive_is_ambiguous() -> None:
    query = FakeContainerQuery()
    full = labelled(query, 0x88, created_ns=BASE_NS - SECOND_NS, status="running")

    mapping = mapper_for(query).map_label(
        LABEL,
        container_created_after_ns=BASE_NS,
        observed_monotonic_ns=NOW_NS,
    )

    assert mapping.outcome is MappingOutcome.AMBIGUOUS
    assert [item.container_id for item in mapping.candidates] == [full]
    assert mapping.reason is not None and "创建时间约束不满足" in mapping.reason


def test_unknown_created_at_without_window_is_still_mapped() -> None:
    """没有时间窗时，created_at 缺失不影响唯一匹配（不引入无谓歧义）。"""

    query = FakeContainerQuery()
    labelled(query, 0x99, created_ns=None)
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert mapping.outcome is MappingOutcome.MAPPED


# --------------------------------------------------------------------------- #
# ERROR
# --------------------------------------------------------------------------- #


def test_list_failure_is_error_not_unmapped() -> None:
    query = FakeContainerQuery()
    query.fail_list(ContainerQueryError("Cannot connect to the Docker daemon"))
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.ERROR
    assert mapping.mapping is None
    assert mapping.candidates == ()
    assert mapping.reason is not None and "list_container_ids() 失败" in mapping.reason
    assert any("Docker daemon" in note for note in mapping.evidence)


def test_inspect_failure_is_error_and_names_container() -> None:
    query = FakeContainerQuery()
    full = labelled(query, 0xAA)
    query.fail_inspect(full, ContainerQueryError("No such object"))
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.ERROR
    assert mapping.reason is not None
    assert full in mapping.reason and "No such object" in mapping.reason


def test_malformed_inspect_is_error_not_silently_skipped() -> None:
    query = FakeContainerQuery()
    payload = inspect_payload(container_id(0xBB), labels={LABEL_KEY: LABEL})
    payload.pop("State")
    query.add(payload)
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.ERROR
    assert mapping.reason is not None and "State" in mapping.reason


def test_id_mismatch_between_list_and_inspect_is_error() -> None:
    query = FakeContainerQuery()
    listed = container_id(0xCC)
    payload = inspect_payload(container_id(0xDD), labels={LABEL_KEY: LABEL})
    query.ids.append(listed)
    query.payloads[listed] = payload
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.ERROR
    assert mapping.reason is not None and "可能查错了容器" in mapping.reason


def test_duplicate_listed_ids_are_inspected_once() -> None:
    query = FakeContainerQuery()
    full = labelled(query, 0xEE)
    query.ids.append(full)
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.MAPPED
    assert query.inspect_calls() == (full,)
    assert any("重复列出" in note for note in mapping.evidence)


def test_illegal_container_id_from_list_is_error() -> None:
    query = FakeContainerQuery()
    query.ids.append("not-a-valid-id")
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    # fake 直接返回非法 ID，parse_inspect 拒绝 → ERROR（不静默跳过）。
    assert mapping.outcome is MappingOutcome.ERROR


# --------------------------------------------------------------------------- #
# 缺失值不伪造 + 证据
# --------------------------------------------------------------------------- #


def test_missing_host_pid_and_cgroup_are_null_and_noted() -> None:
    query = FakeContainerQuery()
    labelled(query, 0xF0, status="running", pid=None, cgroup_id=None, cgroup_path=None)
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.MAPPED
    assert mapping.mapping is not None
    assert mapping.mapping.host_pid is None
    assert mapping.mapping.cgroup_id is None
    assert mapping.mapping.cgroup_path is None
    assert any("host_pid=null" in note for note in mapping.evidence)


def test_unknown_state_is_recorded_in_evidence() -> None:
    query = FakeContainerQuery()
    labelled(query, 0xF1, status="dead", pid=None)
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.MAPPED
    assert mapping.mapping is not None
    assert mapping.mapping.state is ContainerState.UNKNOWN
    assert any("state=unknown" in note for note in mapping.evidence)


def test_cgroup_path_without_id_is_recorded_in_evidence() -> None:
    query = FakeContainerQuery()
    labelled(query, 0xF2, pid=4242, cgroup_path="/system.slice/docker-x.scope")
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.MAPPED
    assert any("cgroup_id=null" in note for note in mapping.evidence)


def test_pid_zero_is_not_used_for_cgroup_and_noted() -> None:
    query = FakeContainerQuery()
    labelled(query, 0xF3, status="exited", pid=0)
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.MAPPED
    assert mapping.mapping is not None and mapping.mapping.host_pid is None
    assert any("Pid=0" in note for note in mapping.evidence)


def test_evidence_is_bounded() -> None:
    query = FakeContainerQuery()
    for seed in range(1, 61):
        labelled(
            query,
            seed,
            status="restarting",
            pid=None,
            cgroup_path="/system.slice/docker-x.scope",
        )
    mapping = mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    assert mapping.outcome is MappingOutcome.AMBIGUOUS
    assert len(mapping.evidence) <= MAX_EVIDENCE_ITEMS + 1
    assert any("evidence 已截断" in note for note in mapping.evidence)


# --------------------------------------------------------------------------- #
# 时间窗参数校验
# --------------------------------------------------------------------------- #


def test_inverted_window_is_rejected() -> None:
    query = FakeContainerQuery()
    labelled(query, 0xF4)
    with pytest.raises(ContainerValidationError, match="时间窗不合法"):
        mapper_for(query).map_label(
            LABEL,
            container_created_after_ns=BASE_NS + 1,
            container_created_before_ns=BASE_NS,
            observed_monotonic_ns=NOW_NS,
        )


@pytest.mark.parametrize("field", ["after", "before", "observed"])
def test_window_arguments_must_be_non_negative_ints(field: str) -> None:
    query = FakeContainerQuery()
    labelled(query, 0xF5)
    mapper = mapper_for(query)
    kwargs: dict[str, Any] = {"observed_monotonic_ns": NOW_NS}
    if field == "after":
        kwargs["container_created_after_ns"] = "x"
    elif field == "before":
        kwargs["container_created_before_ns"] = -1
    else:
        kwargs["observed_monotonic_ns"] = True
    with pytest.raises(ContainerValidationError):
        mapper.map_label(LABEL, **kwargs)


# --------------------------------------------------------------------------- #
# label_key / max_candidates / query 契约
# --------------------------------------------------------------------------- #


def test_custom_label_key_is_used() -> None:
    query = FakeContainerQuery()
    query.add(inspect_payload(container_id(0xF6), labels={"custom.key": "run-7"}))
    mapper = mapper_for(query, label_key="custom.key")
    mapping = mapper.map_label("run-7", observed_monotonic_ns=NOW_NS)
    assert mapping.outcome is MappingOutcome.MAPPED
    assert mapper.label_key == "custom.key"

    other = mapper_for(query).map_label("run-7", observed_monotonic_ns=NOW_NS)
    assert other.outcome is MappingOutcome.UNMAPPED


@pytest.mark.parametrize("label_key", ["", "a\x00b", 7, None])
def test_invalid_label_key_is_rejected(label_key: Any) -> None:
    with pytest.raises(ContainerValidationError):
        mapper_for(FakeContainerQuery(), label_key=label_key)


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "8", 100_000])
def test_invalid_max_candidates_is_rejected(value: Any) -> None:
    with pytest.raises(ContainerValidationError):
        mapper_for(FakeContainerQuery(), max_candidates=value)


def test_query_must_expose_container_query_methods() -> None:
    class _OnlyList:
        def list_container_ids(self) -> tuple[str, ...]:
            return ()

    with pytest.raises(ContainerValidationError, match="inspect"):
        ContainerTaskMapper(_OnlyList())  # type: ignore[arg-type]


def test_query_is_not_called_more_than_needed() -> None:
    query = FakeContainerQuery()
    labelled(query, 0xF7)
    mapper_for(query).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert query.list_call_count() == 1
    assert query.inspect_calls() == (container_id(0xF7),)


# --------------------------------------------------------------------------- #
# map_labels / resolver_for / 序列化
# --------------------------------------------------------------------------- #


def test_map_labels_preserves_order_and_shares_observed_time() -> None:
    query = FakeContainerQuery()
    query.add(
        inspect_payload(
            container_id(0xF8), labels={LABEL_KEY: "task-a"}, mounts=[mount_entry()]
        )
    )
    query.add(inspect_payload(container_id(0xF9), labels={LABEL_KEY: "task-b"}))
    mapper = mapper_for(query)
    results = mapper.map_labels(["task-b", "task-a"], observed_monotonic_ns=NOW_NS)

    assert [item.task_label for item in results] == ["task-b", "task-a"]
    assert [item.outcome for item in results] == [
        MappingOutcome.MAPPED,
        MappingOutcome.MAPPED,
    ]
    assert {item.observed_monotonic_ns for item in results} == {NOW_NS}
    assert results[1].mounts[0].mount_type is MountType.BIND


def test_map_labels_rejects_non_iterable_and_bare_string() -> None:
    mapper = mapper_for(FakeContainerQuery())
    with pytest.raises(ContainerValidationError):
        mapper.map_labels("task-a", observed_monotonic_ns=NOW_NS)
    with pytest.raises(ContainerValidationError):
        mapper.map_labels(3, observed_monotonic_ns=NOW_NS)  # type: ignore[arg-type]


def test_resolver_for_rejects_ambiguous_mapping() -> None:
    query = FakeContainerQuery()
    labelled(query, 0xFA)
    labelled(query, 0xFB)
    mapper = mapper_for(query)
    mapping = mapper.map_label(LABEL, observed_monotonic_ns=NOW_NS)
    with pytest.raises(ContainerValidationError, match="只有 outcome=mapped"):
        mapper.resolver_for(mapping)


def test_mapping_roundtrip_with_candidates_and_mounts() -> None:
    ambiguous_query = FakeContainerQuery()
    labelled(ambiguous_query, 0xFC)
    labelled(ambiguous_query, 0xFD)
    ambiguous = mapper_for(ambiguous_query).map_label(LABEL, observed_monotonic_ns=NOW_NS)

    from agent_probe.container import ContainerMapping

    restored = ContainerMapping.from_dict(ambiguous.to_dict())
    assert restored == ambiguous
    assert ambiguous.to_json() == restored.to_json()
    assert len(restored.candidates) == 2

    mapped_query = FakeContainerQuery()
    labelled(mapped_query, 0xFE, mounts=[mount_entry(source="/host/w", destination="/w")])
    mapped = mapper_for(mapped_query).map_label(LABEL, observed_monotonic_ns=NOW_NS)
    mapped_restored = ContainerMapping.from_dict(mapped.to_dict())
    assert mapped_restored == mapped
    assert mapped_restored.mounts[0].source == "/host/w"
    assert mapped.to_json() == mapped_restored.to_json()


def test_mapping_json_is_deterministic_across_calls() -> None:
    query = FakeContainerQuery()
    labelled(query, 0xFF, mounts=[mount_entry()])
    mapper = mapper_for(query)
    first = mapper.map_label(LABEL, observed_monotonic_ns=NOW_NS)
    second = mapper.map_label(LABEL, observed_monotonic_ns=NOW_NS)
    assert first == second
    assert first.to_json() == second.to_json()
