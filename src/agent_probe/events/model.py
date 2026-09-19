"""版本化系统事件模型（M2 核心）。

设计要点
--------

1. **显式未知，不伪装成功**
   ``result`` 是必填枚举（``ok``/``error``/``unknown``），没有默认值。
   拿不到返回值时必须写 ``unknown``，不能因为"没看到错误"就记成 ``ok``。
   可能真实缺采的字段（``cgroup_id``/``pid_namespace``/``process_start_id``）
   允许 ``null``，但 ``null`` 有明确语义：**未采集**，绝不等于 0 或成功。
2. **严格边界**
   每个事件类型的 payload 都有一张字段表（类型/范围/字节上限/枚举），
   逐字段校验；跨字段约束（如 ``sequence_gap`` 的算术关系、
   ``file.truncate`` 至少要有一个文件身份、``result=error`` 必须带 ``error_code``）
   也在此实现。
3. **未知字段策略显式**
   :class:`UnknownFieldPolicy` 只有两个取值：``REJECT``（默认，拒绝未知字段）
   与 ``PRESERVE``（保留并原样回写，但永不解释其语义）。没有"静默忽略"。
4. **规范化序列化**
   持久化字节一律来自 :func:`canonical_json`（``sort_keys``、紧凑分隔符、
   ``ensure_ascii=False``、``allow_nan=False``），因此摘要与校验值可复现、
   跨进程一致，且同一条事件的字节恒定。

本模块只做模型与校验，不做 IO、不做索引、不做采集。
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final, Protocol

from .errors import EventTooLargeError, EventValidationError, UnknownFieldError

__all__ = [
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_VERSIONS",
    "MAX_EVENT_BYTES",
    "MAX_STRING_BYTES",
    "MAX_PATH_BYTES",
    "MAX_LIST_ITEMS",
    "MAX_ARGV_ITEMS",
    "MAX_COUNTER_KEYS",
    "MAX_PAYLOAD_DEPTH",
    "MAX_PID",
    "MAX_UINT32",
    "MAX_UINT64",
    "MAX_INT64",
    "HEADER_FIELDS",
    "REQUIRED_HEADER_FIELDS",
    "OPTIONAL_HEADER_FIELDS",
    "UNKNOWN_WALL_TIME",
    "EventSource",
    "EventType",
    "EventResult",
    "UnknownFieldPolicy",
    "FieldSpec",
    "PAYLOAD_SCHEMAS",
    "payload_schema",
    "payload_required_keys",
    "Event",
    "EventClock",
    "SystemClock",
    "new_event_id",
    "new_run_id",
    "new_event",
    "canonical_json",
    "event_to_dict",
    "event_to_json",
    "event_to_bytes",
    "event_checksum",
    "event_from_dict",
    "event_from_json",
]


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #

#: 当前 schema 版本。不兼容变更必须递增该值，并在 docs/02-event-ledger.md
#: 的"schema 演进"一节登记迁移方式。
SCHEMA_VERSION: Final[int] = 1

#: 本实现能解析的 schema 版本集合。未知版本必须显式报告，不能"尽力解析"。
SUPPORTED_SCHEMA_VERSIONS: Final[frozenset[int]] = frozenset({SCHEMA_VERSION})

#: 单条事件（不含 JSONL 信封）规范化后允许的最大 UTF-8 字节数。
MAX_EVENT_BYTES: Final[int] = 64 * 1024

#: 一般标识/文本字段（路径、主机名、reason、connection id …）的字节上限。
MAX_STRING_BYTES: Final[int] = 4096

#: 文件路径字段的字节上限（Linux PATH_MAX 为 4096）。
MAX_PATH_BYTES: Final[int] = 4096

#: 单个数组类字段的元素上限。
MAX_LIST_ITEMS: Final[int] = 256

#: ``process.exec`` 的 argv 元素上限。
MAX_ARGV_ITEMS: Final[int] = 128

#: 计数器映射的键数量上限。
MAX_COUNTER_KEYS: Final[int] = 64

#: payload/未知字段允许的最大嵌套深度。
MAX_PAYLOAD_DEPTH: Final[int] = 8

MAX_PID: Final[int] = 2**31 - 1
MAX_UINT32: Final[int] = 2**32 - 1
MAX_UINT64: Final[int] = 2**64 - 1
MAX_INT64: Final[int] = 2**63 - 1

#: ``wall_time`` 取 0 时的约定值：时钟未能采集。它**不是** 1970-01-01 的真实时刻，
#: 排序与关联一律以 ``monotonic_ns`` 为准。
UNKNOWN_WALL_TIME: Final[int] = 0


class EventSource(StrEnum):
    """事件来源。用于区分采集通道，也用于序号/顺序的流划分。"""

    EBPF = "ebpf"
    USERSPACE = "userspace"
    SYNTHETIC = "synthetic"


class EventType(StrEnum):
    """M2 支持的事件类型（进程生命周期 / 文件 / 网络 / TLS / 数据质量）。"""

    PROCESS_FORK = "process.fork"
    PROCESS_EXEC = "process.exec"
    PROCESS_EXIT = "process.exit"

    FILE_OPEN = "file.open"
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    FILE_TRUNCATE = "file.truncate"
    FILE_RENAME = "file.rename"
    FILE_UNLINK = "file.unlink"

    NET_CONNECT = "net.connect"
    NET_SEND = "net.send"

    TLS_BYTES = "tls.bytes"

    QUALITY_SEQUENCE_GAP = "quality.sequence_gap"
    QUALITY_RING_DROP = "quality.ring_drop"
    QUALITY_QUEUE_DROP = "quality.queue_drop"
    QUALITY_STORAGE_DROP = "quality.storage_drop"
    QUALITY_COUNTER_SNAPSHOT = "quality.counter_snapshot"


class EventResult(StrEnum):
    """操作结果。**必填**，没有隐式默认值。

    * ``OK``：已确认成功（例如系统调用返回值表示成功）。
    * ``ERROR``：已确认失败（必须带 ``error_code``）。
    * ``UNKNOWN``：入口观测到了，但返回值未被捕获/无法判定（不得写成 ``ok``）。
    """

    OK = "ok"
    ERROR = "error"
    UNKNOWN = "unknown"


class UnknownFieldPolicy(StrEnum):
    """未知字段兼容策略。

    * ``REJECT``（默认）：出现未知头字段或未知 payload 字段即报错，
      避免把拼写错误或版本错配当成有效数据。
    * ``PRESERVE``：保留未知字段并原样回写（不解释、不参与校验判定），
      用于读比当前实现更新的 schema 版本时保持不丢数据。
    """

    REJECT = "reject"
    PRESERVE = "preserve"


#: 事件头的完整字段集合（**恒定存在**，未知值写 ``null`` 而不是省略键）。
HEADER_FIELDS: Final[tuple[str, ...]] = (
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
    "seq",
    "error_code",
    "correlation_id",
    "payload",
)

#: M2 计划要求"至少包括"的头字段（缺失即非法）。
REQUIRED_HEADER_FIELDS: Final[tuple[str, ...]] = (
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
)

#: 本实现新增的可空头字段（用于序号与关联，M3 会继续使用）。
OPTIONAL_HEADER_FIELDS: Final[tuple[str, ...]] = (
    "seq",
    "error_code",
    "correlation_id",
)


# --------------------------------------------------------------------------- #
# 校验原语
# --------------------------------------------------------------------------- #

_UUID_FIELDS: Final[frozenset[str]] = frozenset({"event_id", "run_id"})


def _check_int(
    context: str,
    name: str,
    value: Any,
    minimum: int,
    maximum: int,
) -> int:
    # bool 是 int 的子类：这里显式拒绝，避免 True 被当成 1。
    if isinstance(value, bool) or not isinstance(value, int):
        raise EventValidationError(
            f"{context}：字段 {name!r} 必须是整数，实际为 {type(value).__name__}"
        )
    if value < minimum or value > maximum:
        raise EventValidationError(
            f"{context}：字段 {name!r} 必须在 [{minimum}, {maximum}] 内，实际为 {value}"
        )
    return value


def _check_nullable_int(
    context: str,
    name: str,
    value: Any,
    minimum: int,
    maximum: int,
) -> int | None:
    if value is None:
        return None
    return _check_int(context, name, value, minimum, maximum)


def _check_uuid(context: str, name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise EventValidationError(
            f"{context}：字段 {name!r} 必须是 UUID 字符串，实际为 {type(value).__name__}"
        )
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise EventValidationError(
            f"{context}：字段 {name!r} 不是合法 UUID：{value!r}（{exc}）"
        ) from exc
    if int(parsed) == 0:
        raise EventValidationError(
            f"{context}：字段 {name!r} 不能是 nil UUID；请使用 new_event_id()/new_run_id()"
        )
    if str(parsed) != value:
        raise EventValidationError(
            f"{context}：字段 {name!r} 必须是规范小写连字符形式 {str(parsed)!r}，"
            f"实际为 {value!r}"
        )
    return value


def _check_text(
    context: str,
    name: str,
    value: Any,
    *,
    max_bytes: int,
    allow_empty: bool,
) -> str:
    if not isinstance(value, str):
        raise EventValidationError(
            f"{context}：字段 {name!r} 必须是字符串，实际为 {type(value).__name__}"
        )
    if "\x00" in value:
        raise EventValidationError(f"{context}：字段 {name!r} 不能包含 NUL 字节")
    size = len(value.encode("utf-8"))
    if size > max_bytes:
        raise EventValidationError(
            f"{context}：字段 {name!r} 的 UTF-8 长度为 {size} 字节，超过上限 {max_bytes}"
        )
    if not value and not allow_empty:
        raise EventValidationError(f"{context}：字段 {name!r} 不能为空字符串")
    return value


def _coerce_enum(context: str, name: str, value: Any, enum_cls: type[StrEnum]) -> Any:
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value)
        except ValueError as exc:
            allowed = ", ".join(repr(member.value) for member in enum_cls)
            raise EventValidationError(
                f"{context}：字段 {name!r} 的值 {value!r} 不在允许集合 {{{allowed}}} 内"
            ) from exc
    raise EventValidationError(
        f"{context}：字段 {name!r} 必须是 {enum_cls.__name__} 或字符串，"
        f"实际为 {type(value).__name__}"
    )


def _validate_generic_value(context: str, name: str, value: Any, depth: int) -> None:
    """校验没有字段表约束的值（未知字段、额外头字段、计数器映射的值）。

    只允许 JSON 原生类型；int/float 限定范围，字符串与集合限定规模与深度。
    """

    if depth > MAX_PAYLOAD_DEPTH:
        raise EventValidationError(
            f"{context}：字段 {name!r} 的嵌套深度超过上限 {MAX_PAYLOAD_DEPTH}"
        )
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -MAX_UINT64 <= value <= MAX_UINT64:
            raise EventValidationError(
                f"{context}：字段 {name!r} 的整数 {value} 超出 64 位无符号范围"
            )
        return
    if isinstance(value, float):
        # allow_nan=False 会拒绝 NaN/Infinity；这里提前给出更明确的错误。
        if value != value or value in (float("inf"), float("-inf")):
            raise EventValidationError(
                f"{context}：字段 {name!r} 不能是 NaN 或 Infinity（JSON 无法表示）"
            )
        return
    if isinstance(value, str):
        _check_text(context, name, value, max_bytes=MAX_STRING_BYTES, allow_empty=True)
        return
    if isinstance(value, Mapping):
        if len(value) > MAX_COUNTER_KEYS:
            raise EventValidationError(
                f"{context}：字段 {name!r} 的对象键数量 {len(value)} 超过上限 "
                f"{MAX_COUNTER_KEYS}"
            )
        for key, item in value.items():
            if not isinstance(key, str):
                raise EventValidationError(
                    f"{context}：字段 {name!r} 的对象键必须是字符串，实际为 "
                    f"{type(key).__name__}"
                )
            _check_text(
                context, f"{name}.{key}", key, max_bytes=MAX_STRING_BYTES, allow_empty=True
            )
            _validate_generic_value(context, f"{name}.{key}", item, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_LIST_ITEMS:
            raise EventValidationError(
                f"{context}：字段 {name!r} 的元素数量 {len(value)} 超过上限 {MAX_LIST_ITEMS}"
            )
        for index, item in enumerate(value):
            _validate_generic_value(context, f"{name}[{index}]", item, depth + 1)
        return
    raise EventValidationError(
        f"{context}：字段 {name!r} 的值类型 {type(value).__name__} 不是 JSON 原生类型"
    )


def _freeze(value: Any, depth: int = 0) -> Any:
    """把 payload 冻结为不可变结构，避免调用方在事件构造后篡改内容。"""

    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item, depth + 1) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item, depth + 1) for item in value)
    return value


def _thaw(value: Any) -> Any:
    """把冻结结构还原为 JSON 可序列化的原生结构。"""

    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


# --------------------------------------------------------------------------- #
# payload schema
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """payload 单字段的边界声明。

    ``kind`` 取值：

    * ``int`` / ``nullable_int``：整数（bool 被拒绝），范围由 ``minimum``/``maximum`` 限定。
    * ``text`` / ``nullable_text``：字符串，受 ``max_bytes`` 与 ``allow_empty`` 约束。
    * ``path`` / ``nullable_path``：非空文件路径字符串，受 ``MAX_PATH_BYTES`` 约束。
    * ``bool``：布尔值。
    * ``text_list``：字符串数组，受 ``max_items`` 与 ``MAX_STRING_BYTES`` 约束。
    * ``enum``：字符串取值必须在 ``choices`` 内。
    * ``counter_map``：``{名称: 非负整数}`` 映射。
    """

    kind: str
    required: bool = True
    minimum: int | None = None
    maximum: int | None = None
    max_bytes: int | None = None
    max_items: int | None = None
    allow_empty: bool = True
    choices: tuple[str, ...] | None = None


_NET_FAMILIES: Final[tuple[str, ...]] = ("inet", "inet6")
_NET_PROTOCOLS: Final[tuple[str, ...]] = ("tcp", "udp")
_TLS_DIRECTIONS: Final[tuple[str, ...]] = ("read", "write")


def _schema(**fields: FieldSpec) -> Mapping[str, FieldSpec]:
    return MappingProxyType(dict(fields))


PAYLOAD_SCHEMAS: Final[Mapping[EventType, Mapping[str, FieldSpec]]] = MappingProxyType(
    {
        # ---- 进程生命周期 -------------------------------------------------
        EventType.PROCESS_FORK: _schema(
            child_pid=FieldSpec("int", minimum=0, maximum=MAX_PID),
            parent_pid=FieldSpec("int", minimum=0, maximum=MAX_PID),
            child_start_id=FieldSpec(
                "nullable_int", required=False, minimum=0, maximum=MAX_UINT64
            ),
        ),
        EventType.PROCESS_EXEC: _schema(
            exe=FieldSpec("path"),
            argv=FieldSpec("text_list", max_items=MAX_ARGV_ITEMS),
            cwd=FieldSpec("nullable_path", required=False),
        ),
        EventType.PROCESS_EXIT: _schema(
            exit_code=FieldSpec("nullable_int", required=False, minimum=0, maximum=255),
            signal=FieldSpec("nullable_int", required=False, minimum=0, maximum=64),
        ),
        # ---- 文件 ---------------------------------------------------------
        EventType.FILE_OPEN: _schema(
            path=FieldSpec("path"),
            flags=FieldSpec("int", minimum=0, maximum=MAX_UINT32),
            fd=FieldSpec("nullable_int", required=False, minimum=0, maximum=MAX_PID),
            mode=FieldSpec("nullable_int", required=False, minimum=0, maximum=0o7777),
        ),
        EventType.FILE_READ: _schema(
            fd=FieldSpec("int", minimum=0, maximum=MAX_PID),
            path=FieldSpec("nullable_path", required=False),
            count=FieldSpec("int", minimum=0, maximum=MAX_UINT64),
            bytes_read=FieldSpec("int", minimum=0, maximum=MAX_UINT64),
        ),
        EventType.FILE_WRITE: _schema(
            fd=FieldSpec("int", minimum=0, maximum=MAX_PID),
            path=FieldSpec("nullable_path", required=False),
            count=FieldSpec("int", minimum=0, maximum=MAX_UINT64),
            bytes_written=FieldSpec("int", minimum=0, maximum=MAX_UINT64),
        ),
        EventType.FILE_TRUNCATE: _schema(
            path=FieldSpec("nullable_path", required=False),
            fd=FieldSpec("nullable_int", required=False, minimum=0, maximum=MAX_PID),
            length=FieldSpec("int", minimum=0, maximum=MAX_UINT64),
        ),
        EventType.FILE_RENAME: _schema(
            old_path=FieldSpec("path"),
            new_path=FieldSpec("path"),
            flags=FieldSpec("nullable_int", required=False, minimum=0, maximum=MAX_UINT32),
        ),
        EventType.FILE_UNLINK: _schema(
            path=FieldSpec("path"),
            dir_fd=FieldSpec("nullable_int", required=False, minimum=0, maximum=MAX_PID),
        ),
        # ---- 网络 ---------------------------------------------------------
        EventType.NET_CONNECT: _schema(
            family=FieldSpec("enum", choices=_NET_FAMILIES),
            protocol=FieldSpec("enum", choices=_NET_PROTOCOLS),
            dest_addr=FieldSpec("text", max_bytes=64, allow_empty=False),
            dest_port=FieldSpec("int", minimum=0, maximum=65535),
            local_port=FieldSpec(
                "nullable_int", required=False, minimum=0, maximum=65535
            ),
        ),
        EventType.NET_SEND: _schema(
            family=FieldSpec("enum", choices=_NET_FAMILIES),
            protocol=FieldSpec("enum", choices=_NET_PROTOCOLS),
            dest_addr=FieldSpec("text", max_bytes=64, allow_empty=False),
            dest_port=FieldSpec("int", minimum=0, maximum=65535),
            bytes_sent=FieldSpec("int", minimum=0, maximum=MAX_UINT64),
        ),
        # ---- TLS ----------------------------------------------------------
        EventType.TLS_BYTES: _schema(
            direction=FieldSpec("enum", choices=_TLS_DIRECTIONS),
            bytes=FieldSpec("int", minimum=0, maximum=MAX_UINT64),
            connection_id=FieldSpec("text", max_bytes=128, allow_empty=False),
            plaintext_included=FieldSpec("bool"),
            truncated=FieldSpec("bool"),
        ),
        # ---- 数据质量 ------------------------------------------------------
        EventType.QUALITY_SEQUENCE_GAP: _schema(
            stream=FieldSpec("text", max_bytes=128, allow_empty=False),
            expected_seq=FieldSpec("int", minimum=0, maximum=MAX_UINT64),
            received_seq=FieldSpec("int", minimum=0, maximum=MAX_UINT64),
            missing=FieldSpec("int", minimum=1, maximum=MAX_UINT64),
        ),
        EventType.QUALITY_RING_DROP: _schema(
            count=FieldSpec("int", minimum=1, maximum=MAX_UINT64),
            reason=FieldSpec("text", max_bytes=128, allow_empty=False),
        ),
        EventType.QUALITY_QUEUE_DROP: _schema(
            count=FieldSpec("int", minimum=1, maximum=MAX_UINT64),
            reason=FieldSpec("text", max_bytes=128, allow_empty=False),
        ),
        EventType.QUALITY_STORAGE_DROP: _schema(
            count=FieldSpec("int", minimum=1, maximum=MAX_UINT64),
            reason=FieldSpec("text", max_bytes=128, allow_empty=False),
        ),
        EventType.QUALITY_COUNTER_SNAPSHOT: _schema(
            counters=FieldSpec("counter_map"),
        ),
    }
)


def payload_schema(event_type: EventType | str) -> Mapping[str, FieldSpec]:
    """返回事件类型的 payload 字段表（未知类型抛 :class:`EventValidationError`）。"""

    resolved = _coerce_enum("payload_schema", "event_type", event_type, EventType)
    return PAYLOAD_SCHEMAS[resolved]


def payload_required_keys(event_type: EventType | str) -> tuple[str, ...]:
    """返回事件类型 payload 的必填字段名（按字段表声明顺序）。"""

    return tuple(
        name for name, spec in payload_schema(event_type).items() if spec.required
    )


def _validate_payload_field(
    context: str,
    event_type: EventType,
    name: str,
    spec: FieldSpec,
    value: Any,
) -> None:
    kind = spec.kind
    if kind == "int":
        _check_int(context, name, value, spec.minimum or 0, spec.maximum or MAX_UINT64)
    elif kind == "nullable_int":
        _check_nullable_int(
            context, name, value, spec.minimum or 0, spec.maximum or MAX_UINT64
        )
    elif kind == "text":
        _check_text(
            context,
            name,
            value,
            max_bytes=spec.max_bytes or MAX_STRING_BYTES,
            allow_empty=spec.allow_empty,
        )
    elif kind == "nullable_text":
        if value is not None:
            _check_text(
                context,
                name,
                value,
                max_bytes=spec.max_bytes or MAX_STRING_BYTES,
                allow_empty=spec.allow_empty,
            )
    elif kind == "path":
        _check_text(context, name, value, max_bytes=MAX_PATH_BYTES, allow_empty=False)
    elif kind == "nullable_path":
        if value is not None:
            _check_text(context, name, value, max_bytes=MAX_PATH_BYTES, allow_empty=False)
    elif kind == "bool":
        if not isinstance(value, bool):
            raise EventValidationError(
                f"{context}：字段 {name!r} 必须是布尔值，实际为 {type(value).__name__}"
            )
    elif kind == "text_list":
        if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
            raise EventValidationError(
                f"{context}：字段 {name!r} 必须是字符串数组，实际为 {type(value).__name__}"
            )
        limit = spec.max_items or MAX_LIST_ITEMS
        if len(value) > limit:
            raise EventValidationError(
                f"{context}：字段 {name!r} 的元素数量 {len(value)} 超过上限 {limit}"
            )
        for index, item in enumerate(value):
            _check_text(
                context,
                f"{name}[{index}]",
                item,
                max_bytes=MAX_STRING_BYTES,
                allow_empty=True,
            )
    elif kind == "enum":
        choices = spec.choices or ()
        if not isinstance(value, str) or value not in choices:
            raise EventValidationError(
                f"{context}：字段 {name!r} 必须是 {{{', '.join(choices)}}} 之一，"
                f"实际为 {value!r}"
            )
    elif kind == "counter_map":
        if not isinstance(value, Mapping):
            raise EventValidationError(
                f"{context}：字段 {name!r} 必须是对象，实际为 {type(value).__name__}"
            )
        if len(value) > MAX_COUNTER_KEYS:
            raise EventValidationError(
                f"{context}：字段 {name!r} 的键数量 {len(value)} 超过上限 {MAX_COUNTER_KEYS}"
            )
        for key, item in value.items():
            if not isinstance(key, str):
                raise EventValidationError(
                    f"{context}：字段 {name!r} 的键必须是字符串，实际为 {type(key).__name__}"
                )
            _check_text(
                context,
                f"{name}.{key}",
                key,
                max_bytes=MAX_STRING_BYTES,
                allow_empty=False,
            )
            _check_int(context, f"{name}.{key}", item, 0, MAX_UINT64)
    else:  # pragma: no cover - 字段表是内建数据，出现未知 kind 属实现错误
        raise EventValidationError(f"{context}：字段 {name!r} 声明了未知类型 {kind!r}")


def _validate_type_constraints(context: str, event_type: EventType, payload: Mapping[str, Any]) -> None:
    """跨字段约束：字段表表达不了的规则。"""

    if event_type is EventType.QUALITY_SEQUENCE_GAP:
        expected = payload["expected_seq"]
        received = payload["received_seq"]
        missing = payload["missing"]
        if received <= expected:
            raise EventValidationError(
                f"{context}：sequence_gap 要求 received_seq({received}) > "
                f"expected_seq({expected})；序号回退请用 out_of_order 统计"
            )
        if missing != received - expected:
            raise EventValidationError(
                f"{context}：sequence_gap 要求 missing == received_seq - expected_seq "
                f"（{missing} != {received} - {expected}）"
            )
    elif event_type is EventType.FILE_TRUNCATE:
        if payload.get("path") is None and payload.get("fd") is None:
            raise EventValidationError(
                f"{context}：file.truncate 至少要提供 path 或 fd 之一作为文件身份"
            )
    elif event_type is EventType.PROCESS_EXIT:
        if payload.get("exit_code") is None and payload.get("signal") is None:
            raise EventValidationError(
                f"{context}：process.exit 至少要提供 exit_code 或 signal 之一；"
                "未观测到退出状态时不得谎报为正常退出"
            )


# --------------------------------------------------------------------------- #
# Event
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Event:
    """一条规范化系统事件。

    字段语义：

    * ``monotonic_ns``：``CLOCK_MONOTONIC`` 纳秒值，**同一 boot 内**的排序依据。
    * ``wall_time``：Unix epoch 纳秒值；``0`` 表示未采集（见 ``UNKNOWN_WALL_TIME``）。
    * ``process_start_id``：``/proc/<pid>/stat`` 的 starttime，用于识别 PID 复用。
    * ``cgroup_id`` / ``pid_namespace``：``None`` 表示未采集，不代表"无 cgroup"或宿主命名空间。
    * ``seq``：同一 ``(run_id, source)`` 流内的连续序号；不连续即丢失信号。
      生产者必须保证同一 ``(run_id, source)`` 只有一条连续序列，否则置 ``None``。
    * ``error_code``：``result == ERROR`` 时必填的 errno（非负）；成功/未知时必须为 ``None``。
    * ``correlation_id``：可选的关联令牌（M3 使用），本层不做语义解释。
    * ``extra``：``PRESERVE`` 策略下保留的未知头字段，原样回写、永不参与判定。

    ``payload``/``extra`` 在构造时被**深度冻结**：对象变成 ``MappingProxyType``，
    数组变成 ``tuple``，因此事件构造后内容不可被就地修改。需要 JSON 原生结构
    时请用 :meth:`to_dict`（``_thaw`` 会还原为 ``dict``/``list``）。
    """

    schema_version: int
    event_id: str
    run_id: str
    source: EventSource
    event_type: EventType
    monotonic_ns: int
    wall_time: int
    pid: int
    tid: int
    result: EventResult
    payload: Mapping[str, Any]
    process_start_id: int | None = None
    cgroup_id: int | None = None
    pid_namespace: int | None = None
    seq: int | None = None
    error_code: int | None = None
    correlation_id: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)
    _allow_unknown: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        context = f"event[{self.event_type!r}]"

        schema_version = _check_int(
            "event", "schema_version", self.schema_version, 0, MAX_UINT32
        )
        if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            supported = ", ".join(str(v) for v in sorted(SUPPORTED_SCHEMA_VERSIONS))
            raise EventValidationError(
                f"event：不支持的 schema_version {schema_version}（支持：{supported}）"
            )
        object.__setattr__(self, "schema_version", schema_version)

        source = _coerce_enum("event", "source", self.source, EventSource)
        object.__setattr__(self, "source", source)
        event_type = _coerce_enum("event", "event_type", self.event_type, EventType)
        object.__setattr__(self, "event_type", event_type)
        result = _coerce_enum("event", "result", self.result, EventResult)
        object.__setattr__(self, "result", result)

        _check_uuid("event", "event_id", self.event_id)
        _check_uuid("event", "run_id", self.run_id)

        _check_int("event", "monotonic_ns", self.monotonic_ns, 0, MAX_INT64)
        _check_int("event", "wall_time", self.wall_time, 0, MAX_INT64)
        _check_int("event", "pid", self.pid, 0, MAX_PID)
        _check_int("event", "tid", self.tid, 0, MAX_PID)
        _check_nullable_int(
            "event", "process_start_id", self.process_start_id, 0, MAX_UINT64
        )
        _check_nullable_int("event", "cgroup_id", self.cgroup_id, 0, MAX_UINT64)
        _check_nullable_int("event", "pid_namespace", self.pid_namespace, 0, MAX_UINT32)
        _check_nullable_int("event", "seq", self.seq, 0, MAX_UINT64)
        _check_nullable_int("event", "error_code", self.error_code, 0, MAX_INT64)
        if self.correlation_id is not None:
            _check_text(
                "event",
                "correlation_id",
                self.correlation_id,
                max_bytes=128,
                allow_empty=False,
            )

        # result 与 error_code 的一致性：这是"不把未知当成功"的核心机制。
        if result is EventResult.OK and self.error_code is not None:
            raise EventValidationError(
                "event：result=ok 时不允许携带 error_code "
                f"({self.error_code})；失败事件必须写 result=error"
            )
        if result is EventResult.ERROR and self.error_code is None:
            raise EventValidationError(
                "event：result=error 时必须提供非负 error_code(errno)；"
                "不确定返回值请写 result=unknown"
            )
        if result is EventResult.UNKNOWN and self.error_code is not None:
            raise EventValidationError(
                "event：result=unknown 时不允许携带 error_code；已知 errno 应写 result=error"
            )

        if not isinstance(self.payload, Mapping):
            raise EventValidationError(
                f"event：payload 必须是对象，实际为 {type(self.payload).__name__}"
            )
        for key in self.payload:
            if not isinstance(key, str):
                raise EventValidationError(
                    f"event：payload 的键必须是字符串，实际为 {type(key).__name__}"
                )
        for key, value in self.payload.items():
            _validate_generic_value(context, f"payload.{key}", value, 1)

        schema = PAYLOAD_SCHEMAS[event_type]
        unknown_payload = [key for key in self.payload if key not in schema]
        if unknown_payload and not self._allow_unknown:
            raise UnknownFieldError(
                f"{context}：payload 出现未知字段 "
                f"{', '.join(sorted(unknown_payload))}；"
                "如需保留请使用 UnknownFieldPolicy.PRESERVE"
            )
        for name, spec in schema.items():
            if name not in self.payload:
                if spec.required:
                    raise EventValidationError(f"{context}：缺少必需 payload 字段 {name!r}")
                continue
            _validate_payload_field(context, event_type, name, spec, self.payload[name])
        _validate_type_constraints(context, event_type, self.payload)
        object.__setattr__(self, "payload", _freeze(dict(self.payload)))

        if not isinstance(self.extra, Mapping):
            raise EventValidationError(
                f"event：extra 必须是对象，实际为 {type(self.extra).__name__}"
            )
        for key in self.extra:
            if not isinstance(key, str):
                raise EventValidationError(
                    f"event：extra 的键必须是字符串，实际为 {type(key).__name__}"
                )
            if key in HEADER_FIELDS:
                raise EventValidationError(
                    f"event：extra 不能覆盖已知头字段 {key!r}"
                )
            _validate_generic_value("event", f"extra.{key}", self.extra[key], 1)
        object.__setattr__(self, "extra", _freeze(dict(self.extra)))

        # 大小上限：以最终序列化字节为准（信封之外的净事件体）。
        size = len(event_to_bytes(self))
        if size > MAX_EVENT_BYTES:
            raise EventTooLargeError(
                f"{context}：事件规范化后为 {size} 字节，超过上限 {MAX_EVENT_BYTES}"
            )

    # -- 转换 --------------------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        """展开为 JSON 可序列化字典（头字段恒定存在，未知值写 ``null``）。"""

        data: dict[str, Any] = {
            "schema_version": int(self.schema_version),
            "event_id": self.event_id,
            "run_id": self.run_id,
            "source": str(self.source),
            "event_type": str(self.event_type),
            "monotonic_ns": self.monotonic_ns,
            "wall_time": self.wall_time,
            "pid": self.pid,
            "tid": self.tid,
            "process_start_id": self.process_start_id,
            "cgroup_id": self.cgroup_id,
            "pid_namespace": self.pid_namespace,
            "result": str(self.result),
            "seq": self.seq,
            "error_code": self.error_code,
            "correlation_id": self.correlation_id,
            "payload": _thaw(self.payload),
        }
        for key, value in self.extra.items():
            if key not in data:
                data[key] = _thaw(value)
        return data

    def to_json(self) -> str:
        """规范化 JSON 文本（与持久化字节一致）。"""

        return event_to_json(self)

    def identity(self) -> tuple[str, str, str]:
        """``(run_id, source, event_type)``，常用查询键。"""

        return (self.run_id, str(self.source), str(self.event_type))

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    ) -> Event:
        """从字典构造事件。

        ``policy`` 决定未知头字段与未知 payload 字段的处理方式；缺失任何头字段
        一律报错（包括可空字段：必须显式写 ``null``）。
        """

        if not isinstance(data, Mapping):
            raise EventValidationError(
                f"event：期望对象，实际为 {type(data).__name__}"
            )
        resolved_policy = _coerce_enum(
            "event", "unknown_field_policy", policy, UnknownFieldPolicy
        )
        missing = [name for name in HEADER_FIELDS if name not in data]
        if missing:
            raise EventValidationError(
                f"event：缺少必需头字段 {', '.join(missing)}；"
                "未知值必须显式写 null，而不是省略键"
            )
        unknown_header = {
            key: value for key, value in data.items() if key not in HEADER_FIELDS
        }
        if unknown_header and resolved_policy is UnknownFieldPolicy.REJECT:
            raise UnknownFieldError(
                f"event：出现未知头字段 {', '.join(sorted(unknown_header))}；"
                "如需保留请使用 UnknownFieldPolicy.PRESERVE"
            )

        event_type = _coerce_enum("event", "event_type", data["event_type"], EventType)
        payload = data["payload"]
        if not isinstance(payload, Mapping):
            raise EventValidationError(
                f"event：payload 必须是对象，实际为 {type(payload).__name__}"
            )
        schema = PAYLOAD_SCHEMAS[event_type]
        unknown_payload = [str(key) for key in payload if key not in schema]
        if unknown_payload and resolved_policy is UnknownFieldPolicy.REJECT:
            raise UnknownFieldError(
                f"event[{str(event_type)!r}]：payload 出现未知字段 "
                f"{', '.join(sorted(unknown_payload))}；"
                "如需保留请使用 UnknownFieldPolicy.PRESERVE"
            )

        kwargs: dict[str, Any] = {
            name: data[name] for name in HEADER_FIELDS if name != "payload"
        }
        kwargs["event_type"] = event_type
        kwargs["payload"] = payload
        kwargs["extra"] = unknown_header
        kwargs["_allow_unknown"] = resolved_policy is UnknownFieldPolicy.PRESERVE
        return cls(**kwargs)

    @classmethod
    def from_json(
        cls,
        text: str | bytes,
        *,
        policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
    ) -> Event:
        """从 JSON 文本/字节构造事件。"""

        if isinstance(text, bytes):
            try:
                text = text.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise EventValidationError(f"event：不是合法 UTF-8：{exc}") from exc
        if not isinstance(text, str):
            raise EventValidationError(
                f"event：期望 str 或 bytes，实际为 {type(text).__name__}"
            )
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            raise EventValidationError(f"event：JSON 解析失败：{exc}") from exc
        return cls.from_dict(data, policy=policy)


# --------------------------------------------------------------------------- #
# 规范化序列化
# --------------------------------------------------------------------------- #


def canonical_json(value: Any) -> str:
    """规范化 JSON 文本。

    ``sort_keys=True`` + 紧凑分隔符 + ``ensure_ascii=False`` + ``allow_nan=False``：
    保证同一逻辑内容在同一实现下字节恒定，跨进程可复现校验值。
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def event_to_dict(event: Event) -> dict[str, Any]:
    """``Event.to_dict()`` 的函数式别名（便于按模块导入使用）。"""

    return event.to_dict()


def event_to_json(event: Event) -> str:
    """事件的规范化 JSON 文本。"""

    return canonical_json(event.to_dict())


def event_to_bytes(event: Event) -> bytes:
    """事件的规范化 UTF-8 字节；校验值与索引摘要都基于它。"""

    return event_to_json(event).encode("utf-8")


def event_checksum(event: Event) -> str:
    """事件的 JSON 摘要输入（由 ``ledger`` 模块加算 SHA-256）。"""

    return event_to_json(event)


def event_from_dict(
    data: Mapping[str, Any],
    *,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
) -> Event:
    return Event.from_dict(data, policy=policy)


def event_from_json(
    text: str | bytes,
    *,
    policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT,
) -> Event:
    return Event.from_json(text, policy=policy)


# --------------------------------------------------------------------------- #
# 时钟与工厂
# --------------------------------------------------------------------------- #


class EventClock(Protocol):
    """可注入时钟：测试与离线重放需要确定性时间。"""

    def monotonic_ns(self) -> int:
        ...

    def wall_time_ns(self) -> int:
        ...


class SystemClock:
    """默认时钟：``CLOCK_MONOTONIC`` 与 Unix epoch 纳秒。"""

    __slots__ = ()

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()

    def wall_time_ns(self) -> int:
        return time.time_ns()


SYSTEM_CLOCK: Final[SystemClock] = SystemClock()


def new_event_id() -> str:
    """新事件 ID（UUIDv4 规范小写形式）。"""

    return str(uuid.uuid4())


def new_run_id() -> str:
    """新 run ID（UUIDv4 规范小写形式）。"""

    return str(uuid.uuid4())


def new_event(
    *,
    run_id: str,
    event_type: EventType | str,
    payload: Mapping[str, Any],
    pid: int,
    tid: int,
    result: EventResult | str = EventResult.OK,
    source: EventSource | str = EventSource.EBPF,
    error_code: int | None = None,
    process_start_id: int | None = None,
    cgroup_id: int | None = None,
    pid_namespace: int | None = None,
    seq: int | None = None,
    correlation_id: str | None = None,
    monotonic_ns: int | None = None,
    wall_time: int | None = None,
    event_id: str | None = None,
    clock: EventClock | None = None,
    schema_version: int = SCHEMA_VERSION,
) -> Event:
    """构造一条事件，补齐时钟、ID 与 schema 版本。

    时间字段未显式给出时由 ``clock``（默认 :data:`SYSTEM_CLOCK`）提供；
    其余字段一律要求显式传入，不做默认成功假设。
    """

    active_clock = clock if clock is not None else SYSTEM_CLOCK
    if monotonic_ns is None:
        monotonic_ns = active_clock.monotonic_ns()
    if wall_time is None:
        wall_time = active_clock.wall_time_ns()
    return Event(
        schema_version=schema_version,
        event_id=event_id if event_id is not None else new_event_id(),
        run_id=run_id,
        source=source,
        event_type=event_type,
        monotonic_ns=monotonic_ns,
        wall_time=wall_time,
        pid=pid,
        tid=tid,
        result=result,
        payload=payload,
        process_start_id=process_start_id,
        cgroup_id=cgroup_id,
        pid_namespace=pid_namespace,
        seq=seq,
        error_code=error_code,
        correlation_id=correlation_id,
    )
