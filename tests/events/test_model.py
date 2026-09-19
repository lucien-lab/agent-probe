"""事件模型：头字段、边界校验、未知字段策略与规范化序列化。"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from agent_probe.events import (
    HEADER_FIELDS,
    MAX_EVENT_BYTES,
    MAX_STRING_BYTES,
    REQUIRED_HEADER_FIELDS,
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    Event,
    EventResult,
    EventSource,
    EventTooLargeError,
    EventType,
    EventValidationError,
    UnknownFieldError,
    UnknownFieldPolicy,
    canonical_json,
    event_from_dict,
    event_from_json,
    event_to_bytes,
    event_to_json,
    new_event,
    new_event_id,
    new_run_id,
    payload_required_keys,
    payload_schema,
)

_NET_CONNECT_PAYLOAD: dict[str, Any] = {
    "family": "inet",
    "protocol": "tcp",
    "dest_addr": "127.0.0.1",
    "dest_port": 8443,
    "local_port": 51000,
}

_SEQUENCE_GAP_PAYLOAD: dict[str, Any] = {
    "stream": "ebpf/ring0",
    "expected_seq": 10,
    "received_seq": 13,
    "missing": 3,
}


def test_all_schema_fields_present_in_serialized_header(make_event: Any) -> None:
    data = make_event().to_dict()
    for field in HEADER_FIELDS:
        assert field in data, field
    assert set(REQUIRED_HEADER_FIELDS) <= set(data)
    assert data["schema_version"] == SCHEMA_VERSION


def test_required_header_field_set_matches_plan() -> None:
    assert set(REQUIRED_HEADER_FIELDS) == {
        "schema_version",
        "event_id",
        "run_id",
        "source",
        "event_type",
        "monotonic_ns",
        "wall_time",
        "pid",
        "tid",
        "process_start_id",
        "cgroup_id",
        "pid_namespace",
        "result",
        "payload",
    }
    assert set(HEADER_FIELDS) > set(REQUIRED_HEADER_FIELDS)


def test_json_roundtrip_preserves_event(make_event: Any) -> None:
    event = make_event(EventType.FILE_RENAME)
    restored = event_from_json(event_to_json(event))
    assert restored == event
    assert event_to_bytes(restored) == event_to_bytes(event)


def test_serialization_is_byte_stable(make_event: Any) -> None:
    event = make_event()
    assert event_to_json(event) == canonical_json(event.to_dict())
    assert event_to_bytes(event) == event_to_bytes(event_from_json(event_to_json(event)))


def test_unicode_payload_roundtrips_without_escaping(make_event: Any) -> None:
    payload = {
        "path": "/工作/目录/文件-🧪.txt",
        "flags": 0,
        "fd": 7,
    }
    event = make_event(EventType.FILE_OPEN, payload=payload)
    text = event_to_json(event)
    # ensure_ascii=False：UTF-8 原样保存，字节可复现。
    assert "🧪" in text
    assert "工作" in text
    restored = event_from_json(text)
    assert restored.payload["path"] == payload["path"]
    assert event_to_bytes(restored) == text.encode("utf-8")


def test_astral_and_combining_characters_roundtrip(make_event: Any) -> None:
    weird = "e\u0301\u200d𝔘𝔫𝔦"  # 组合重音 + ZWJ + 星形平面字符
    event = make_event(EventType.FILE_OPEN, payload={"path": weird, "flags": 0})
    assert event_from_json(event_to_json(event)).payload["path"] == weird


@pytest.mark.parametrize(
    "field, value",
    [
        ("monotonic_ns", -1),
        ("wall_time", -1),
        ("pid", -1),
        ("tid", -1),
        ("process_start_id", -1),
        ("cgroup_id", -1),
        ("pid_namespace", -1),
        ("seq", -1),
        ("error_code", -1),
    ],
)
def test_negative_numeric_fields_rejected(
    event_kwargs: dict[str, Any], field: str, value: int
) -> None:
    kwargs = dict(event_kwargs)
    kwargs[field] = value
    if field == "error_code":
        kwargs["result"] = EventResult.ERROR
    with pytest.raises(EventValidationError):
        Event(**kwargs)


def test_zero_wall_time_is_allowed_and_means_unknown_clock(
    event_kwargs: dict[str, Any],
) -> None:
    kwargs = dict(event_kwargs, wall_time=0)
    assert Event(**kwargs).wall_time == 0


def test_bool_is_not_accepted_as_integer(event_kwargs: dict[str, Any]) -> None:
    with pytest.raises(EventValidationError):
        Event(**dict(event_kwargs, pid=True))


def test_event_id_must_be_uuid(event_kwargs: dict[str, Any]) -> None:
    with pytest.raises(EventValidationError):
        Event(**dict(event_kwargs, event_id="not-a-uuid"))


def test_uppercase_uuid_is_rejected_to_avoid_duplicate_keys(
    event_kwargs: dict[str, Any],
) -> None:
    kwargs = dict(event_kwargs, event_id=new_event_id().upper())
    with pytest.raises(EventValidationError):
        Event(**kwargs)


def test_nil_uuid_is_rejected(event_kwargs: dict[str, Any]) -> None:
    with pytest.raises(EventValidationError):
        Event(**dict(event_kwargs, run_id="00000000-0000-0000-0000-000000000000"))


@pytest.mark.parametrize(
    "field, value",
    [
        ("source", "kernel-magic"),
        ("event_type", "file.chmod"),
        ("result", "maybe"),
    ],
)
def test_invalid_enums_rejected(
    event_kwargs: dict[str, Any], field: str, value: str
) -> None:
    with pytest.raises(EventValidationError):
        Event(**dict(event_kwargs, **{field: value}))


def test_string_enum_values_are_coerced(event_kwargs: dict[str, Any]) -> None:
    event = Event(**dict(event_kwargs, source="userspace"))
    assert event.source is EventSource.USERSPACE
    assert event.to_dict()["source"] == "userspace"


def test_missing_header_key_is_rejected_even_for_nullable_field(
    event_kwargs: dict[str, Any],
) -> None:
    data = Event(**event_kwargs).to_dict()
    del data["cgroup_id"]
    with pytest.raises(EventValidationError):
        event_from_dict(data)


def test_missing_result_is_not_defaulted_to_success(event_kwargs: dict[str, Any]) -> None:
    data = Event(**event_kwargs).to_dict()
    del data["result"]
    with pytest.raises(EventValidationError):
        event_from_dict(data)


def test_or_omitted_result_is_not_defaulted_to_success() -> None:
    with pytest.raises(TypeError):
        # result 是必填位置/关键字参数：语言层面就不存在"默认成功"。
        Event(  # type: ignore[call-arg]
            schema_version=1,
            event_id=new_event_id(),
            run_id=new_run_id(),
            source=EventSource.EBPF,
            event_type=EventType.FILE_OPEN,
            monotonic_ns=1,
            wall_time=1,
            pid=1,
            tid=1,
            payload={"path": "/a", "flags": 0},
        )


def test_result_error_requires_error_code(event_kwargs: dict[str, Any]) -> None:
    with pytest.raises(EventValidationError, match="error_code"):
        Event(**dict(event_kwargs, result=EventResult.ERROR))


def test_result_ok_rejects_error_code(event_kwargs: dict[str, Any]) -> None:
    with pytest.raises(EventValidationError, match="error_code"):
        Event(**dict(event_kwargs, result=EventResult.OK, error_code=13))


def test_result_unknown_rejects_error_code(event_kwargs: dict[str, Any]) -> None:
    with pytest.raises(EventValidationError, match="unknown"):
        Event(**dict(event_kwargs, result=EventResult.UNKNOWN, error_code=13))


def test_result_unknown_without_error_code_is_valid(make_event: Any) -> None:
    event = make_event(result=EventResult.UNKNOWN)
    assert event.result is EventResult.UNKNOWN
    assert event.error_code is None


def test_result_error_with_error_code_is_valid(make_event: Any) -> None:
    event = make_event(
        EventType.FILE_OPEN,
        payload={"path": "/denied", "flags": 0},
        result=EventResult.ERROR,
        error_code=13,
    )
    assert event.error_code == 13


def test_missing_required_payload_field_rejected(make_event: Any) -> None:
    with pytest.raises(EventValidationError, match="bytes_read"):
        make_event(EventType.FILE_READ, payload={"fd": 3, "count": 1})


def test_unknown_payload_field_rejected_by_default(make_event: Any) -> None:
    with pytest.raises(UnknownFieldError, match="extra_field"):
        make_event(EventType.FILE_OPEN, payload={"path": "/a", "flags": 0, "extra_field": 1})


def test_unknown_payload_field_preserved_under_preserve_policy(make_event: Any) -> None:
    event = make_event(EventType.FILE_OPEN)
    data = event.to_dict()
    data["payload"]["future_field"] = {"a": [1, 2]}
    restored = event_from_dict(data, policy=UnknownFieldPolicy.PRESERVE)
    # payload 是深度冻结结构（MappingProxyType/tuple）：比较 JSON 形态请用 to_dict()。
    assert restored.payload["future_field"]["a"][1] == 2
    assert restored.to_dict()["payload"]["future_field"] == {"a": [1, 2]}
    assert restored.to_dict() == data
    assert event_from_json(event_to_json(restored), policy=UnknownFieldPolicy.PRESERVE) == restored
    # REJECT 策略下同一份数据必须报错，而不是静默忽略。
    with pytest.raises(UnknownFieldError):
        event_from_dict(data)


def test_unknown_header_field_rejected_and_preserved(make_event: Any) -> None:
    data = make_event().to_dict()
    data["future_header"] = "x"
    with pytest.raises(UnknownFieldError, match="future_header"):
        event_from_dict(data)
    restored = event_from_dict(data, policy=UnknownFieldPolicy.PRESERVE)
    assert restored.extra == {"future_header": "x"}
    assert restored.to_dict()["future_header"] == "x"


def test_extra_cannot_override_known_header_field(event_kwargs: dict[str, Any]) -> None:
    with pytest.raises(EventValidationError, match="extra"):
        Event(**dict(event_kwargs, extra={"pid": 1}))


def test_non_json_serializable_payload_rejected(make_event: Any) -> None:
    with pytest.raises(EventValidationError):
        make_event(EventType.FILE_OPEN, payload={"path": object(), "flags": 0})


def test_nan_payload_rejected(make_event: Any) -> None:
    with pytest.raises(EventValidationError):
        make_event(EventType.FILE_OPEN, payload={"path": "/a", "flags": 0, "x": float("nan")})


def test_deeply_nested_payload_rejected(make_event: Any) -> None:
    nested: Any = 1
    for _ in range(12):
        nested = {"a": nested}
    with pytest.raises(EventValidationError, match="嵌套深度"):
        make_event(EventType.FILE_OPEN, payload={"path": "/a", "flags": 0, "x": nested})


def test_oversized_event_rejected(make_event: Any) -> None:
    payload = {
        "exe": "/usr/bin/python3",
        "argv": ["x" * MAX_STRING_BYTES] * 64,
    }
    with pytest.raises(EventTooLargeError):
        make_event(EventType.PROCESS_EXEC, payload=payload)


def test_event_just_below_limit_is_accepted(make_event: Any) -> None:
    payload = {"exe": "/usr/bin/python3", "argv": ["y" * 4000] * 15}
    event = make_event(EventType.PROCESS_EXEC, payload=payload)
    size = len(event_to_bytes(event))
    assert size <= MAX_EVENT_BYTES
    assert event_from_json(event_to_json(event)) == event


def test_path_with_nul_rejected(make_event: Any) -> None:
    with pytest.raises(EventValidationError, match="NUL"):
        make_event(EventType.FILE_OPEN, payload={"path": "/a\x00b", "flags": 0})


def test_empty_path_rejected(make_event: Any) -> None:
    with pytest.raises(EventValidationError, match="空"):
        make_event(EventType.FILE_OPEN, payload={"path": "", "flags": 0})


def test_overlong_path_rejected(make_event: Any) -> None:
    with pytest.raises(EventValidationError, match="4096"):
        make_event(EventType.FILE_OPEN, payload={"path": "/" + "a" * 5000, "flags": 0})


def test_overlong_known_text_field_rejected(make_event: Any) -> None:
    with pytest.raises(EventValidationError, match="128"):
        make_event(
            EventType.QUALITY_RING_DROP,
            payload={"count": 1, "reason": "z" * 129},
        )


def test_overlong_unknown_string_rejected(make_event: Any) -> None:
    with pytest.raises(EventValidationError):
        make_event(
            EventType.FILE_OPEN,
            payload={"path": "/a", "flags": 0, "note": "z" * (MAX_STRING_BYTES + 1)},
        )


@pytest.mark.parametrize("port", [-1, 65536])
def test_network_port_range_enforced(make_event: Any, port: int) -> None:
    payload = dict(_NET_CONNECT_PAYLOAD, dest_port=port)
    with pytest.raises(EventValidationError):
        make_event(EventType.NET_CONNECT, payload=payload)


def test_network_family_enum_enforced(make_event: Any) -> None:
    payload = dict(_NET_CONNECT_PAYLOAD, family="unix")
    with pytest.raises(EventValidationError):
        make_event(EventType.NET_CONNECT, payload=payload)


def test_sequence_gap_arithmetic_enforced(make_event: Any) -> None:
    payload = dict(_SEQUENCE_GAP_PAYLOAD, missing=99)
    with pytest.raises(EventValidationError, match="missing"):
        make_event(EventType.QUALITY_SEQUENCE_GAP, payload=payload)
    backwards = dict(
        _SEQUENCE_GAP_PAYLOAD,
        expected_seq=10,
        received_seq=10,
        missing=1,
    )
    with pytest.raises(EventValidationError, match="received_seq"):
        make_event(EventType.QUALITY_SEQUENCE_GAP, payload=backwards)


def test_truncate_requires_file_identity(make_event: Any) -> None:
    with pytest.raises(EventValidationError, match="file.truncate"):
        make_event(EventType.FILE_TRUNCATE, payload={"length": 0})


def test_payload_is_immutable_after_construction(make_event: Any) -> None:
    event = make_event()
    with pytest.raises(TypeError):
        event.payload["path"] = "/other"  # type: ignore[index]
    with pytest.raises(TypeError):
        event.payload["flags"] = 9  # type: ignore[index]


def test_uncaptured_process_metadata_is_explicit_null(make_event: Any) -> None:
    event = make_event(cgroup_id=None, pid_namespace=None, process_start_id=None)
    data = event.to_dict()
    assert data["cgroup_id"] is None
    assert data["pid_namespace"] is None
    assert data["process_start_id"] is None


def test_unsupported_schema_version_rejected(event_kwargs: dict[str, Any]) -> None:
    kwargs = dict(event_kwargs, schema_version=2)
    with pytest.raises(EventValidationError, match="schema_version"):
        Event(**kwargs)
    assert SUPPORTED_SCHEMA_VERSIONS == {SCHEMA_VERSION}


@pytest.mark.parametrize("event_type", sorted(EventType, key=str))
def test_every_event_type_has_a_schema_and_constructs(make_event: Any, event_type: EventType) -> None:
    schema = payload_schema(event_type)
    assert schema, event_type
    event = make_event(event_type)
    assert event.event_type is event_type
    assert set(schema) >= set(event.payload)
    assert event_from_json(event_to_json(event)) == event


def test_process_exit_requires_exit_status(make_event: Any) -> None:
    with pytest.raises(EventValidationError, match="exit_code"):
        make_event(EventType.PROCESS_EXIT, payload={})


def test_payload_schema_required_keys_are_declared_for_most_types() -> None:
    for event_type in EventType:
        if event_type is EventType.PROCESS_EXIT:
            # 退出状态允许二选一（exit_code 或 signal），因此没有必填项；
            # 两者都不给会被 _validate_type_constraints 拒绝（见上一个用例）。
            assert payload_required_keys(event_type) == ()
            continue
        assert payload_required_keys(event_type), event_type


def test_payload_schema_unknown_event_type_raises() -> None:
    with pytest.raises(EventValidationError):
        payload_schema("not.an.event")


def test_new_event_fills_identifiers_and_clock(clock: Any, run_id: str) -> None:
    event = new_event(
        run_id=run_id,
        event_type=EventType.PROCESS_EXIT,
        payload={"exit_code": 3},
        pid=10,
        tid=11,
        clock=clock,
    )
    assert event.run_id == run_id
    assert event.monotonic_ns == 1_000_000_000
    assert event.wall_time == 1_700_000_000_000_000_000
    assert event.source is EventSource.EBPF
    assert event.result is EventResult.OK
    assert len(event.event_id) == 36


def test_from_json_rejects_malformed_json() -> None:
    with pytest.raises(EventValidationError, match="JSON"):
        event_from_json("{not json")


def test_from_json_rejects_non_object() -> None:
    with pytest.raises(EventValidationError):
        event_from_json("[1, 2, 3]")


def test_from_json_accepts_utf8_bytes(make_event: Any) -> None:
    event = make_event()
    assert event_from_json(event_to_json(event).encode("utf-8")) == event


def test_canonical_json_is_sorted_and_rejects_nan() -> None:
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    with pytest.raises(ValueError):
        canonical_json({"a": float("inf")})


def test_payload_mapping_types_checked(event_kwargs: dict[str, Any]) -> None:
    with pytest.raises(EventValidationError):
        Event(**dict(event_kwargs, payload=["not", "a", "mapping"]))


def test_payload_keys_must_be_strings(event_kwargs: dict[str, Any]) -> None:
    with pytest.raises(EventValidationError, match="键必须是字符串"):
        Event(**dict(event_kwargs, payload={"path": "/a", "flags": 0, 1: "x"}))


def test_roundtrip_through_dict_is_identity_for_all_sample_types(make_event: Any) -> None:
    for event_type in EventType:
        event = make_event(event_type)
        assert Event.from_dict(event.to_dict()) == event


def test_json_dumped_event_is_a_mapping(make_event: Any) -> None:
    parsed = json.loads(event_to_json(make_event()))
    assert isinstance(parsed, Mapping)
    assert parsed["event_type"] in {str(t) for t in EventType}
