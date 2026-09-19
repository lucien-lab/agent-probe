"""容器/挂载/映射模型：严格校验、显式未知、round-trip 与 JSON 确定性。"""

from __future__ import annotations

import json
from typing import Any

import pytest

from agent_probe.container import (
    CGROUP_ID_KEY,
    CGROUP_NOTE_KEY,
    CGROUP_PATH_KEY,
    MAX_LABELS,
    MAX_MOUNTS,
    ContainerInfo,
    ContainerMapping,
    ContainerMount,
    ContainerState,
    ContainerValidationError,
    MappingOutcome,
    MountType,
    canonical_json,
    format_rfc3339_ns,
    parse_container_state,
    parse_inspect,
    parse_mounts,
    parse_rfc3339_ns,
    validate_container_id,
)

from fake_container_query import (
    LABEL,
    LABEL_KEY,
    BASE_NS,
    SECOND_NS,
    ZERO_TIME,
    container_id,
    inspect_payload,
    mount_entry,
    rfc3339_ns,
    short_id,
)

FULL_ID = container_id(0xA1)


def make_info(**overrides: Any) -> ContainerInfo:
    payload: dict[str, Any] = {
        "container_id": FULL_ID,
        "name": "task",
        "labels": {LABEL_KEY: LABEL},
        "state": ContainerState.RUNNING,
        "host_pid": 4242,
    }
    payload.update(overrides)
    return ContainerInfo(**payload)


def make_mount(**overrides: Any) -> ContainerMount:
    payload: dict[str, Any] = {
        "mount_type": MountType.BIND,
        "source": "/host/data",
        "destination": "/data",
        "read_write": True,
        "raw_type": "bind",
    }
    payload.update(overrides)
    return ContainerMount(**payload)


# --------------------------------------------------------------------------- #
# 容器 ID
# --------------------------------------------------------------------------- #


def test_container_id_accepts_12_and_64_hex_and_lowercases() -> None:
    assert validate_container_id("a" * 64) == "a" * 64
    assert validate_container_id("ABC123def456") == "abc123def456"
    assert validate_container_id(short_id(FULL_ID)) == short_id(FULL_ID)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "abc",
        "a" * 11,
        "a" * 13,
        "a" * 63,
        "a" * 65,
        "0x" + "a" * 10,
        "g" * 12,
        "a" * 11 + "-",
        " a" * 6,
        12345,
        None,
        b"a" * 12,
    ],
)
def test_container_id_rejects_bad_shapes(value: Any) -> None:
    with pytest.raises(ContainerValidationError):
        validate_container_id(value)


def test_container_id_error_message_names_allowed_lengths() -> None:
    with pytest.raises(ContainerValidationError, match="12 或 64 位十六进制"):
        validate_container_id("abc")


# --------------------------------------------------------------------------- #
# 状态
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("created", ContainerState.CREATED),
        ("running", ContainerState.RUNNING),
        ("exited", ContainerState.EXITED),
        ("paused", ContainerState.PAUSED),
    ],
)
def test_known_states_parse(raw: str, expected: ContainerState) -> None:
    state, note = parse_container_state(raw)
    assert state is expected
    assert note is None


@pytest.mark.parametrize("raw", ["restarting", "removing", "dead", "", "Running"])
def test_unknown_state_strings_fold_to_unknown_with_note(raw: str) -> None:
    state, note = parse_container_state(raw)
    assert state is ContainerState.UNKNOWN
    assert note is not None and raw in note


def test_missing_state_is_unknown_not_running() -> None:
    state, note = parse_container_state(None)
    assert state is ContainerState.UNKNOWN
    assert note is not None and "缺失" in note
    assert state is not ContainerState.RUNNING


def test_non_string_state_is_rejected() -> None:
    with pytest.raises(ContainerValidationError):
        parse_container_state(3)


def test_inspect_with_restarting_status_is_unknown_and_noted() -> None:
    view = parse_inspect(inspect_payload(FULL_ID, status="restarting"))
    assert view.info.state is ContainerState.UNKNOWN
    assert any("restarting" in note for note in view.notes)


# --------------------------------------------------------------------------- #
# 时间戳
# --------------------------------------------------------------------------- #


def test_rfc3339_nanosecond_precision_is_preserved() -> None:
    assert parse_rfc3339_ns("2023-11-14T22:13:20.123456789Z", field="t") == BASE_NS + 123456789
    assert format_rfc3339_ns(BASE_NS + 123456789) == "2023-11-14T22:13:20.123456789Z"


def test_rfc3339_without_fraction_is_second_precision() -> None:
    assert parse_rfc3339_ns("2023-11-14T22:13:20Z", field="t") == BASE_NS


@pytest.mark.parametrize(
    ("text", "delta_seconds"),
    [
        ("2023-11-15T00:13:20Z", 2 * 3600),
        ("2023-11-14T20:13:20Z", -2 * 3600),
    ],
)
def test_rfc3339_offsets_are_converted_to_utc(text: str, delta_seconds: int) -> None:
    # 基准时间 22:13:20Z 用 +02:00 / -02:00 表示应得到同一时刻。
    signed = "+02:00" if delta_seconds > 0 else "-02:00"
    local = format_rfc3339_ns(BASE_NS + delta_seconds * SECOND_NS).replace("Z", signed)
    assert parse_rfc3339_ns(local, field="t") == BASE_NS
    assert parse_rfc3339_ns(text, field="t") == BASE_NS + delta_seconds * SECOND_NS


@pytest.mark.parametrize(
    "text",
    [
        "2023-11-14T22:13:20",  # 无时区
        "2023-11-14 22:13:20.5",  # 无时区（允许空格分隔，但仍需时区）
        "2023-13-01T00:00:00Z",  # 月份非法
        "2023-02-30T00:00:00Z",  # 日期非法
        "not-a-time",
        "2023-11-14T22:13:20.1234567890Z",  # 小数位超过 9 位
        "1969-01-01T00:00:00Z",  # 早于 epoch
    ],
)
def test_rfc3339_rejects_unparsable_input(text: str) -> None:
    with pytest.raises(ContainerValidationError):
        parse_rfc3339_ns(text, field="t")


def test_zero_timestamp_is_none_not_year_one() -> None:
    assert parse_rfc3339_ns(ZERO_TIME, field="t") is None
    assert parse_rfc3339_ns(None, field="t") is None


def test_inspect_zero_times_become_null_with_note() -> None:
    payload = inspect_payload(FULL_ID, created_ns=None, status="running")
    view = parse_inspect(payload)
    assert view.info.created_at_ns is None
    assert view.info.started_at_ns is None
    assert view.info.finished_at_ns is None
    assert any("零时间" in note for note in view.notes)


def test_inspect_keeps_nanosecond_times_exactly() -> None:
    created = BASE_NS + 1
    started = BASE_NS + 2
    finished = BASE_NS + 3
    view = parse_inspect(
        inspect_payload(
            FULL_ID,
            status="exited",
            created_ns=created,
            started_ns=started,
            finished_ns=finished,
        )
    )
    assert view.info.created_at_ns == created
    assert view.info.started_at_ns == started
    assert view.info.finished_at_ns == finished


# --------------------------------------------------------------------------- #
# inspect 结构
# --------------------------------------------------------------------------- #


def test_inspect_full_payload_is_parsed() -> None:
    view = parse_inspect(
        inspect_payload(
            FULL_ID,
            name="probe-task",
            labels={LABEL_KEY: LABEL, "other": "x"},
            status="running",
            pid=777,
            cgroup_id=99,
            cgroup_path="/system.slice/docker-abc.scope",
            cgroup_note="cgroup v2 统一层级",
        )
    )
    assert view.info.container_id == FULL_ID
    assert view.info.name == "probe-task"
    assert view.info.labels == {"other": "x", LABEL_KEY: LABEL}
    assert view.info.state is ContainerState.RUNNING
    assert view.info.host_pid == 777
    assert view.info.cgroup_id == 99
    assert view.info.cgroup_path == "/system.slice/docker-abc.scope"
    assert any("cgroup v2" in note for note in view.notes)


@pytest.mark.parametrize("key", ["Id", "Name", "State", "Mounts"])
def test_inspect_missing_required_key_is_rejected(key: str) -> None:
    payload = inspect_payload(FULL_ID)
    payload.pop(key)
    with pytest.raises(ContainerValidationError, match=key):
        parse_inspect(payload)


def test_inspect_state_not_an_object_is_rejected() -> None:
    payload = inspect_payload(FULL_ID)
    payload["State"] = "running"
    with pytest.raises(ContainerValidationError):
        parse_inspect(payload)


def test_inspect_non_mapping_is_rejected() -> None:
    with pytest.raises(ContainerValidationError):
        parse_inspect(["not", "an", "object"])  # type: ignore[arg-type]


def test_inspect_name_leading_slash_stripped() -> None:
    view = parse_inspect(inspect_payload(FULL_ID, name="task"))
    assert view.info.name == "task"
    assert not view.info.name.startswith("/")


def test_inspect_unknown_top_level_keys_are_ignored() -> None:
    payload = inspect_payload(FULL_ID)
    payload["GraphDriver"] = {"Name": "overlay2"}
    payload["NetworkSettings"] = {"IPAddress": "172.17.0.2"}
    view = parse_inspect(payload)
    assert view.info.container_id == FULL_ID


def test_container_info_from_inspect_matches_parse_inspect() -> None:
    payload = inspect_payload(FULL_ID, labels={LABEL_KEY: LABEL})
    assert ContainerInfo.from_inspect(payload) == parse_inspect(payload).info


# --------------------------------------------------------------------------- #
# host_pid / cgroup 的缺失语义
# --------------------------------------------------------------------------- #


def test_pid_zero_becomes_null_with_note() -> None:
    view = parse_inspect(inspect_payload(FULL_ID, status="exited", pid=0))
    assert view.info.host_pid is None
    assert any("Pid=0" in note for note in view.notes)


def test_missing_pid_becomes_null() -> None:
    view = parse_inspect(inspect_payload(FULL_ID, pid=None))
    assert view.info.host_pid is None
    assert any("State.Pid 缺失" in note for note in view.notes)


def test_exited_container_without_pid_is_null_without_running_note() -> None:
    view = parse_inspect(inspect_payload(FULL_ID, status="exited", pid=0))
    assert view.info.host_pid is None


@pytest.mark.parametrize("bad", [-1, "4242", 1.5, True])
def test_invalid_pid_type_or_range_is_rejected(bad: Any) -> None:
    payload = inspect_payload(FULL_ID)
    payload["State"]["Pid"] = bad
    with pytest.raises(ContainerValidationError):
        parse_inspect(payload)


def test_missing_cgroup_keys_are_null_and_not_invented() -> None:
    view = parse_inspect(inspect_payload(FULL_ID))
    assert view.info.cgroup_id is None
    assert view.info.cgroup_path is None


def test_cgroup_id_zero_is_null_with_note() -> None:
    payload = inspect_payload(FULL_ID)
    payload[CGROUP_ID_KEY] = 0
    view = parse_inspect(payload)
    assert view.info.cgroup_id is None
    assert any("CgroupID=0" in note for note in view.notes)


def test_cgroup_path_empty_string_is_null_with_note() -> None:
    payload = inspect_payload(FULL_ID)
    payload[CGROUP_PATH_KEY] = ""
    view = parse_inspect(payload)
    assert view.info.cgroup_path is None
    assert any("空串" in note for note in view.notes)


def test_cgroup_extension_values_invalid_are_rejected() -> None:
    payload = inspect_payload(FULL_ID)
    payload[CGROUP_ID_KEY] = -1
    with pytest.raises(ContainerValidationError):
        parse_inspect(payload)

    payload = inspect_payload(FULL_ID)
    payload[CGROUP_PATH_KEY] = "relative/path"
    with pytest.raises(ContainerValidationError):
        parse_inspect(payload)


def test_cgroup_probe_note_flows_into_parse_notes() -> None:
    payload = inspect_payload(FULL_ID)
    payload[CGROUP_NOTE_KEY] = "无法读取 /proc/1/cgroup"
    view = parse_inspect(payload)
    assert any("无法读取 /proc/1/cgroup" in note for note in view.notes)


def test_container_info_rejects_host_pid_zero() -> None:
    with pytest.raises(ContainerValidationError, match="host_pid=0"):
        make_info(host_pid=0)


def test_container_info_rejects_cgroup_id_zero() -> None:
    with pytest.raises(ContainerValidationError, match="cgroup_id=0"):
        make_info(cgroup_id=0)


def test_container_info_rejects_bad_cgroup_path() -> None:
    with pytest.raises(ContainerValidationError):
        make_info(cgroup_path="relative/path")


# --------------------------------------------------------------------------- #
# labels
# --------------------------------------------------------------------------- #


def test_missing_config_is_empty_labels_with_note() -> None:
    payload = inspect_payload(FULL_ID, include_config=False)
    view = parse_inspect(payload)
    assert dict(view.info.labels) == {}
    assert any("Config/Labels 缺失" in note for note in view.notes)


def test_null_labels_are_empty() -> None:
    payload = inspect_payload(FULL_ID)
    payload["Config"]["Labels"] = None
    view = parse_inspect(payload)
    assert dict(view.info.labels) == {}


def test_empty_label_value_is_kept_as_data() -> None:
    view = parse_inspect(inspect_payload(FULL_ID, labels={LABEL_KEY: ""}))
    assert view.info.labels[LABEL_KEY] == ""


@pytest.mark.parametrize("labels", [{"a": 1}, {1: "a"}, {"a": None}])
def test_non_string_labels_are_rejected(labels: Any) -> None:
    payload = inspect_payload(FULL_ID, labels=labels)
    with pytest.raises(ContainerValidationError):
        parse_inspect(payload)


def test_labels_are_sorted_and_frozen() -> None:
    info = make_info(labels={"z": "1", "a": "2", LABEL_KEY: LABEL})
    assert list(info.labels) == sorted(info.labels)
    with pytest.raises(TypeError):
        info.labels["new"] = "x"  # type: ignore[index]


def test_too_many_labels_rejected() -> None:
    with pytest.raises(ContainerValidationError, match=str(MAX_LABELS)):
        make_info(labels={f"k{index}": "v" for index in range(MAX_LABELS + 1)})


# --------------------------------------------------------------------------- #
# 挂载项解析
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw_type", "expected"),
    [
        ("bind", MountType.BIND),
        ("volume", MountType.VOLUME),
        ("tmpfs", MountType.TMPFS),
        ("Bind", MountType.BIND),
        ("npipe", MountType.OTHER),
        ("cluster", MountType.OTHER),
        ("", MountType.OTHER),
        ("overlay", MountType.OTHER),
    ],
)
def test_mount_type_parsing(raw_type: str, expected: MountType) -> None:
    mount = ContainerMount.from_inspect(
        mount_entry(mount_type=raw_type, source="/host/x", destination="/x")
    )
    assert mount.mount_type is expected
    assert mount.raw_type == raw_type


def test_mount_tmpfs_without_source_is_allowed() -> None:
    mount = ContainerMount.from_inspect(
        mount_entry(mount_type="tmpfs", source=None, destination="/tmp/x")
    )
    assert mount.mount_type is MountType.TMPFS
    assert mount.source is None


def test_mount_empty_source_string_is_none_not_a_path() -> None:
    mount = ContainerMount.from_inspect(
        mount_entry(mount_type="tmpfs", source="", destination="/tmp/x")
    )
    assert mount.source is None


def test_mount_read_write_flag_is_preserved() -> None:
    assert ContainerMount.from_inspect(mount_entry(rw=False)).read_write is False
    assert ContainerMount.from_inspect(mount_entry(rw=True)).read_write is True


def test_mount_trailing_and_duplicate_slashes_are_cleaned() -> None:
    mount = ContainerMount.from_inspect(
        mount_entry(source="/host//data/", destination="/data//sub/")
    )
    assert mount.source == "/host/data"
    assert mount.destination == "/data/sub"


@pytest.mark.parametrize(
    "entry",
    [
        mount_entry(destination="relative/path"),
        mount_entry(destination="/data/../etc"),
        mount_entry(source="relative/source"),
        mount_entry(source="/host/../host"),
        mount_entry(destination=""),
    ],
)
def test_mount_relative_or_dotdot_paths_are_rejected(entry: dict[str, Any]) -> None:
    with pytest.raises(ContainerValidationError):
        ContainerMount.from_inspect(entry)


@pytest.mark.parametrize("key", ["Type", "Destination", "RW"])
def test_mount_missing_required_key_is_rejected(key: str) -> None:
    entry = mount_entry()
    entry.pop(key)
    with pytest.raises(ContainerValidationError, match=key):
        ContainerMount.from_inspect(entry)


def test_mount_rw_must_be_bool() -> None:
    entry = mount_entry()
    entry["RW"] = "true"
    with pytest.raises(ContainerValidationError):
        ContainerMount.from_inspect(entry)


def test_mounts_missing_or_not_a_list_is_rejected() -> None:
    with pytest.raises(ContainerValidationError, match="Mounts"):
        parse_mounts({})
    with pytest.raises(ContainerValidationError):
        parse_mounts({"Mounts": "bind"})


def test_mounts_over_limit_is_rejected_not_truncated() -> None:
    entries = [mount_entry(destination=f"/m{index}") for index in range(MAX_MOUNTS + 1)]
    with pytest.raises(ContainerValidationError, match=str(MAX_MOUNTS)):
        parse_mounts({"Mounts": entries})


def test_container_mount_requires_clean_absolute_destination() -> None:
    with pytest.raises(ContainerValidationError):
        make_mount(destination="/data/")
    with pytest.raises(ContainerValidationError):
        make_mount(source="host/data")
    with pytest.raises(ContainerValidationError):
        make_mount(source="")


# --------------------------------------------------------------------------- #
# 序列化
# --------------------------------------------------------------------------- #


def test_container_mount_roundtrip() -> None:
    mount = make_mount(source=None, mount_type=MountType.TMPFS, raw_type="tmpfs")
    assert ContainerMount.from_dict(mount.to_dict()) == mount
    assert canonical_json(mount.to_dict()) == canonical_json(
        ContainerMount.from_dict(mount.to_dict()).to_dict()
    )


def test_container_info_roundtrip_is_json_deterministic() -> None:
    info = make_info(
        labels={"b": "2", "a": "1"},
        cgroup_id=7,
        cgroup_path="/system.slice/docker-x.scope",
        created_at_ns=BASE_NS,
        started_at_ns=BASE_NS + SECOND_NS,
    )
    data = info.to_dict()
    assert ContainerInfo.from_dict(data) == info
    assert canonical_json(data) == canonical_json(ContainerInfo.from_dict(data).to_dict())
    # 键顺序固定 + canonical_json 排序，因此两次序列化字节一致。
    assert json.dumps(data, sort_keys=True) == json.dumps(
        ContainerInfo.from_dict(data).to_dict(), sort_keys=True
    )


@pytest.mark.parametrize("key", ["container_id", "labels", "created_at_ns"])
def test_container_info_from_dict_requires_every_field(key: str) -> None:
    data = make_info().to_dict()
    data.pop(key)
    with pytest.raises(ContainerValidationError, match=key):
        ContainerInfo.from_dict(data)


def test_container_info_from_dict_rejects_unknown_field() -> None:
    data = make_info().to_dict()
    data["host_name"] = "vm"
    with pytest.raises(ContainerValidationError, match="host_name"):
        ContainerInfo.from_dict(data)


def test_container_info_from_dict_rejects_null_labels() -> None:
    data = make_info().to_dict()
    data["labels"] = None
    with pytest.raises(ContainerValidationError):
        ContainerInfo.from_dict(data)


# --------------------------------------------------------------------------- #
# ContainerMapping 不变式
# --------------------------------------------------------------------------- #


def make_mapping(**overrides: Any) -> ContainerMapping:
    info = overrides.pop("info", make_info())
    outcome = MappingOutcome(overrides.get("outcome", MappingOutcome.MAPPED))
    payload: dict[str, Any] = {
        "outcome": outcome,
        "task_label": LABEL,
        "mapping": info if outcome is MappingOutcome.MAPPED else None,
        "candidates": (info,) if outcome is MappingOutcome.MAPPED else (),
        "mounts": (),
        "evidence": ("ok",),
        "reason": None,
        "observed_monotonic_ns": 1_000,
    }
    payload.update(overrides)
    return ContainerMapping(**payload)


def test_mapping_mapped_requires_mapping() -> None:
    with pytest.raises(ContainerValidationError, match="必须给出 mapping"):
        make_mapping(mapping=None, candidates=())


def test_mapping_mapped_rejects_reason() -> None:
    with pytest.raises(ContainerValidationError, match="不允许携带 reason"):
        make_mapping(reason="拿不准")


def test_mapping_mapped_requires_candidates_to_be_the_mapping() -> None:
    other = make_info(container_id=container_id(0xB2))
    with pytest.raises(ContainerValidationError, match="恰好是"):
        make_mapping(candidates=(other,))


def test_mapping_non_mapped_rejects_mapping() -> None:
    info = make_info()
    with pytest.raises(ContainerValidationError, match="不允许携带 mapping"):
        make_mapping(
            outcome=MappingOutcome.AMBIGUOUS,
            mapping=info,
            candidates=(info,),
            reason="多候选",
        )


def test_mapping_non_mapped_rejects_mounts() -> None:
    with pytest.raises(ContainerValidationError, match="不给出挂载视图"):
        make_mapping(
            outcome=MappingOutcome.UNMAPPED, candidates=(), mounts=(make_mount(),), reason="无"
        )


@pytest.mark.parametrize(
    "outcome",
    [MappingOutcome.AMBIGUOUS, MappingOutcome.UNMAPPED, MappingOutcome.ERROR],
)
def test_mapping_requires_reason_for_non_mapped(outcome: MappingOutcome) -> None:
    info = make_info()
    candidates = (info,) if outcome is MappingOutcome.AMBIGUOUS else ()
    with pytest.raises(ContainerValidationError, match="reason"):
        make_mapping(outcome=outcome, candidates=candidates, reason=None)


def test_mapping_ambiguous_requires_candidates() -> None:
    with pytest.raises(ContainerValidationError, match="至少要列出一个候选"):
        make_mapping(outcome=MappingOutcome.AMBIGUOUS, candidates=(), reason="多候选")


def test_mapping_unmapped_requires_no_candidates() -> None:
    with pytest.raises(ContainerValidationError, match="不应有候选"):
        make_mapping(
            outcome=MappingOutcome.UNMAPPED, candidates=(make_info(),), reason="无候选"
        )


def test_mapping_error_requires_no_candidates() -> None:
    with pytest.raises(ContainerValidationError, match="不应有候选"):
        make_mapping(
            outcome=MappingOutcome.ERROR, candidates=(make_info(),), reason="查询失败"
        )


def test_mapping_rejects_non_tuple_collections() -> None:
    info = make_info()
    with pytest.raises(ContainerValidationError, match="必须是元组"):
        make_mapping(candidates=[info])  # type: ignore[arg-type]


def test_mapping_rejects_negative_observed_time() -> None:
    with pytest.raises(ContainerValidationError):
        make_mapping(observed_monotonic_ns=-1)


def test_mapping_roundtrip_includes_candidates_and_mounts() -> None:
    first = make_info(container_id=container_id(0x11))
    second = make_info(container_id=container_id(0x22), state=ContainerState.EXITED)
    mapping = make_mapping(
        outcome=MappingOutcome.AMBIGUOUS,
        candidates=(first, second),
        evidence=("命中 2 个容器", "按 container_id 排序"),
        reason="2 个候选",
    )
    data = mapping.to_dict()
    assert ContainerMapping.from_dict(data) == mapping
    assert [item["container_id"] for item in data["candidates"]] == [
        first.container_id,
        second.container_id,
    ]

    mapped = make_mapping(mounts=(make_mount(),))
    restored = ContainerMapping.from_dict(mapped.to_dict())
    assert restored == mapped
    assert restored.mounts[0].destination == "/data"
    assert mapped.to_json() == restored.to_json()
    assert mapped.to_json().encode("utf-8") == mapped.to_json().encode("utf-8")


def test_mapping_from_dict_is_strict() -> None:
    data = make_mapping().to_dict()
    data.pop("evidence")
    with pytest.raises(ContainerValidationError, match="evidence"):
        ContainerMapping.from_dict(data)

    data = make_mapping().to_dict()
    data["confidence"] = 0.9
    with pytest.raises(ContainerValidationError, match="confidence"):
        ContainerMapping.from_dict(data)


def test_mapping_from_dict_rejects_non_list_candidates() -> None:
    data = make_mapping().to_dict()
    data["candidates"] = make_info().to_dict()
    with pytest.raises(ContainerValidationError, match="candidates"):
        ContainerMapping.from_dict(data)


def test_canonical_json_is_sorted_and_compact() -> None:
    text = canonical_json({"b": 1, "a": [1, 2], "c": "中文"})
    assert text == '{"a":[1,2],"b":1,"c":"中文"}'


def test_rfc3339_rendering_roundtrip_through_parser() -> None:
    for value in (BASE_NS, BASE_NS + 1, BASE_NS + 999_999_999, 0):
        assert parse_rfc3339_ns(rfc3339_ns(value), field="t") == value
