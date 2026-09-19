"""容器与挂载的规范化模型（M3 容器任务映射核心）。

设计要点
--------

1. **容器不是 agent 的子进程**
   容器由 Docker daemon 创建，其宿主进程**不在** agent 的进程树里。
   因此本模块只依据三类真值做映射：容器 **label**、容器 **state**、
   ``docker inspect`` 的**显式字段**。禁止用进程树推断，也禁止把
   "最近创建/最近退出"当成唯一映射（见 :mod:`agent_probe.container.mapper`）。
2. **显式未知，不伪装成功**
   ``host_pid`` / ``cgroup_id`` / ``cgroup_path`` 拿不到时一律写 ``None``；
   绝不填 0、绝不猜测。``ContainerInfo`` 甚至**拒绝** ``host_pid=0``，
   避免把 docker 的"没有宿主进程"哨兵值伪装成真实 PID。
   未知的 ``State.Status`` 字符串折叠为 :attr:`ContainerState.UNKNOWN`，
   并附带一条说明写入 evidence。
3. **严格边界**
   容器 ID 必须是 12 或 64 位十六进制（大小写归一为小写）；
   label 键值、挂载项字段、时间戳（RFC3339，必须带时区）逐项校验；
   映射结果 ``ContainerMapping`` 的四种 outcome 各有跨字段不变式
   （MAPPED 必须给出 mapping 且 candidates 恰为其本身；ERROR 必须给出 reason…）。
4. **时间戳保留纳秒**
   docker 用 RFC3339 字符串给时间（``Created``、``StartedAt``、``FinishedAt``）。
   本模块用正则 + 整数运算解析为 Unix epoch **纳秒**，不经过 float，
   也不把 ``0001-01-01T00:00:00Z``（docker 的"尚未发生"）当成真实时间。
5. **规范化序列化**
   :func:`canonical_json` 与事件账本同规则（``sort_keys``、紧凑分隔符、
   ``ensure_ascii=False``、``allow_nan=False``），因此同一映射的字节恒定，
   可复现、可比较。

本模块只做模型与解析，不做 IO、不执行 docker。
"""

from __future__ import annotations

import calendar
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Final

from .errors import ContainerValidationError
from .paths import MAX_PATH_BYTES, is_clean_absolute_path

__all__ = [
    "DEFAULT_LABEL_KEY",
    "MAX_TEXT_BYTES",
    "MAX_LABELS",
    "MAX_MOUNTS",
    "MAX_RAW_TYPE_BYTES",
    "MAX_INT64",
    "CONTAINER_ID_HEX_LENGTHS",
    "CGROUP_ID_KEY",
    "CGROUP_PATH_KEY",
    "CGROUP_NOTE_KEY",
    "ZERO_DOCKER_TIMESTAMP_PREFIX",
    "INSPECT_REQUIRED_KEYS",
    "ContainerState",
    "MountType",
    "MappingOutcome",
    "DOCKER_STATE_MAP",
    "MOUNT_TYPE_MAP",
    "validate_container_id",
    "parse_container_state",
    "parse_rfc3339_ns",
    "format_rfc3339_ns",
    "canonical_json",
    "ContainerMount",
    "ContainerInfo",
    "InspectView",
    "parse_mounts",
    "parse_inspect",
    "ContainerMapping",
]


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #

#: 默认的任务标签键。容器侧由 ``docker run --label agent-probe.task=<run_id>`` 打上，
#: 本模块只按该键比较 label 值，不做任何模糊匹配。
DEFAULT_LABEL_KEY: Final[str] = "agent-probe.task"

#: 一般文本字段（容器名、label 键值、evidence、reason）的 UTF-8 字节上限。
MAX_TEXT_BYTES: Final[int] = 4096

#: 单个容器的 label 数量上限（超过即拒绝，避免无界内存）。
MAX_LABELS: Final[int] = 256

#: 单个容器的挂载数量上限。超过即报错而不是静默截断：
#: 截断挂载会让路径解析给出错误答案，这比显式失败更危险。
MAX_MOUNTS: Final[int] = 1024

#: ``Mounts[].Type`` 原始字符串的字节上限。
MAX_RAW_TYPE_BYTES: Final[int] = 256

MAX_INT64: Final[int] = 2**63 - 1

#: 合法的容器 ID 长度：完整的 64 位十六进制，或 docker 短 ID 的 12 位。
CONTAINER_ID_HEX_LENGTHS: Final[tuple[int, ...]] = (12, 64)

#: 可选扩展键：cgroup 标识。标准 ``docker inspect`` **不提供**这些字段，
#: 只有注入的增强查询（例如 :class:`agent_probe.container.ProcCgroupReader`
#: 读 ``/proc/<pid>/cgroup``）才会填。缺失时字段为 ``None``，不猜测。
CGROUP_ID_KEY: Final[str] = "CgroupID"
CGROUP_PATH_KEY: Final[str] = "CgroupPath"
CGROUP_NOTE_KEY: Final[str] = "CgroupProbeNote"

#: docker 用该前缀表示"该时间点尚未发生"（未启动/未退出），
#: 它不是真实时刻，解析为 ``None``。
ZERO_DOCKER_TIMESTAMP_PREFIX: Final[str] = "0001-01-01T00:00:00"

#: 必须存在的 inspect 顶层键。缺失即报错（未知值要显式写 null，不能省略键）。
INSPECT_REQUIRED_KEYS: Final[tuple[str, ...]] = ("Id", "Name", "State", "Mounts")


class ContainerState(StrEnum):
    """容器状态（``State.Status`` 的规范化取值）。

    ``UNKNOWN`` 表示状态字符串不在已知集合内或缺失——它是"未判定"，
    **不是**任何具体状态，也不允许被当成 running。
    """

    CREATED = "created"
    RUNNING = "running"
    EXITED = "exited"
    PAUSED = "paused"
    UNKNOWN = "unknown"


class MountType(StrEnum):
    """挂载类型（``Mounts[].Type`` 的规范化取值）。"""

    BIND = "bind"
    VOLUME = "volume"
    TMPFS = "tmpfs"
    OTHER = "other"


class MappingOutcome(StrEnum):
    """标签→容器映射的结果。

    * ``MAPPED``：**唯一**候选，且调用方给出的时间约束全部验证通过。
    * ``AMBIGUOUS``：无法唯一确定。两种情况：①候选多于一个；②只有一个候选但
      时间约束无法验证（``created_at_ns`` 缺失）或与调用方窗口不一致
      （容器创建早于窗口起点但仍跨越窗口）。``reason`` 区分两者。
    * ``UNMAPPED``：该 label 没有任何候选（被时间窗排除的容器只记入 evidence）。
    * ``ERROR``：查询/解析失败，无法给出结论；``reason`` 必须说明失败原因。
    """

    MAPPED = "mapped"
    AMBIGUOUS = "ambiguous"
    UNMAPPED = "unmapped"
    ERROR = "error"


#: ``docker inspect`` 的 ``State.Status`` 到规范状态的映射。
#: ``restarting``/``removing``/``dead`` 等未列出的取值一律折叠为 ``UNKNOWN``。
DOCKER_STATE_MAP: Final[Mapping[str, ContainerState]] = MappingProxyType(
    {
        "created": ContainerState.CREATED,
        "running": ContainerState.RUNNING,
        "exited": ContainerState.EXITED,
        "paused": ContainerState.PAUSED,
    }
)

#: ``Mounts[].Type`` 到规范类型的映射（比较前会 strip + lower）；
#: 未列出的取值折叠为 :attr:`MountType.OTHER`，原始字符串保留在 ``raw_type``。
MOUNT_TYPE_MAP: Final[Mapping[str, MountType]] = MappingProxyType(
    {
        "bind": MountType.BIND,
        "volume": MountType.VOLUME,
        "tmpfs": MountType.TMPFS,
    }
)

_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]+$")

_TS_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})[Tt ]"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<frac>\d{1,9}))?"
    r"(?:(?P<zulu>[Zz])|(?P<sign>[+-])(?P<offset_hour>\d{2}):?(?P<offset_minute>\d{2}))$"
)


# --------------------------------------------------------------------------- #
# 校验原语
# --------------------------------------------------------------------------- #


def _check_int(context: str, name: str, value: Any, minimum: int, maximum: int) -> int:
    # bool 是 int 的子类：显式拒绝，避免 True 被当成 1。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContainerValidationError(
            f"{context}：字段 {name!r} 必须是整数，实际为 {type(value).__name__}"
        )
    if value < minimum or value > maximum:
        raise ContainerValidationError(
            f"{context}：字段 {name!r} 必须在 [{minimum}, {maximum}] 内，实际为 {value}"
        )
    return value


def _check_nullable_int(
    context: str, name: str, value: Any, minimum: int, maximum: int
) -> int | None:
    if value is None:
        return None
    return _check_int(context, name, value, minimum, maximum)


def _check_text(
    context: str,
    name: str,
    value: Any,
    *,
    max_bytes: int = MAX_TEXT_BYTES,
    allow_empty: bool = True,
) -> str:
    if not isinstance(value, str):
        raise ContainerValidationError(
            f"{context}：字段 {name!r} 必须是字符串，实际为 {type(value).__name__}"
        )
    if "\x00" in value:
        raise ContainerValidationError(f"{context}：字段 {name!r} 不能包含 NUL 字节")
    size = len(value.encode("utf-8"))
    if size > max_bytes:
        raise ContainerValidationError(
            f"{context}：字段 {name!r} 的 UTF-8 长度为 {size} 字节，超过上限 {max_bytes}"
        )
    if not value and not allow_empty:
        raise ContainerValidationError(f"{context}：字段 {name!r} 不能为空字符串")
    return value


def _coerce_enum(context: str, name: str, value: Any, enum_cls: type[StrEnum]) -> Any:
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value)
        except ValueError as exc:
            allowed = ", ".join(repr(member.value) for member in enum_cls)
            raise ContainerValidationError(
                f"{context}：字段 {name!r} 的值 {value!r} 不在允许集合 {{{allowed}}} 内"
            ) from exc
    raise ContainerValidationError(
        f"{context}：字段 {name!r} 必须是 {enum_cls.__name__} 或字符串，"
        f"实际为 {type(value).__name__}"
    )


def _check_tuple_of(
    context: str, name: str, value: Any, expected: type
) -> tuple[Any, ...]:
    if not isinstance(value, tuple):
        raise ContainerValidationError(
            f"{context}：字段 {name!r} 必须是元组，实际为 {type(value).__name__}"
        )
    for index, item in enumerate(value):
        if not isinstance(item, expected):
            raise ContainerValidationError(
                f"{context}：字段 {name}[{index}] 必须是 {expected.__name__}，"
                f"实际为 {type(item).__name__}"
            )
    return value


def _check_required_keys(context: str, data: Mapping[str, Any], keys: Sequence[str]) -> None:
    missing = [key for key in keys if key not in data]
    if missing:
        raise ContainerValidationError(
            f"{context}：缺少必需字段 {', '.join(missing)}；"
            "未知值必须显式写 null，而不是省略键"
        )


def _check_no_unknown_keys(
    context: str, data: Mapping[str, Any], allowed: Sequence[str]
) -> None:
    unknown = sorted(str(key) for key in data if key not in allowed)
    if unknown:
        raise ContainerValidationError(
            f"{context}：出现未知字段 {', '.join(unknown)}（允许：{', '.join(allowed)}）"
        )


def _check_labels(labels: Any) -> Mapping[str, str]:
    if not isinstance(labels, Mapping):
        raise ContainerValidationError(
            f"container_info：字段 'labels' 必须是对象，实际为 {type(labels).__name__}"
        )
    if len(labels) > MAX_LABELS:
        raise ContainerValidationError(
            f"container_info：label 数量 {len(labels)} 超过上限 {MAX_LABELS}"
        )
    normalized: dict[str, str] = {}
    for key, value in labels.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ContainerValidationError(
                "container_info：label 的键与值都必须是字符串，实际为 "
                f"{type(key).__name__}/{type(value).__name__}"
            )
        _check_text("container_info", f"labels[{key!r}]", key, allow_empty=False)
        _check_text("container_info", f"labels[{key!r}]", value, allow_empty=True)
        normalized[key] = value
    # 按 key 排序：保证 to_dict()/canonical_json() 的可复现字节。
    return MappingProxyType({key: normalized[key] for key in sorted(normalized)})


# --------------------------------------------------------------------------- #
# 标识与状态解析
# --------------------------------------------------------------------------- #


def validate_container_id(value: Any, *, field: str = "container_id") -> str:
    """校验并规范化容器 ID（返回小写形式）。

    docker 的容器 ID 是十六进制字符串：完整 64 位，或短 ID 12 位。
    其它长度、非十六进制字符、非字符串一律报错——接口不允许"大致像 ID"的输入。
    """

    if not isinstance(value, str):
        raise ContainerValidationError(
            f"{field} 必须是字符串，实际为 {type(value).__name__}"
        )
    if not value:
        raise ContainerValidationError(f"{field} 不能为空字符串")
    allowed = " 或 ".join(str(length) for length in CONTAINER_ID_HEX_LENGTHS)
    if len(value) not in CONTAINER_ID_HEX_LENGTHS:
        raise ContainerValidationError(
            f"{field} 必须是 {allowed} 位十六进制，实际为 {len(value)} 位：{value!r}"
        )
    if _HEX_RE.match(value) is None:
        raise ContainerValidationError(f"{field} 含非十六进制字符：{value!r}")
    return value.lower()


def parse_container_state(raw: Any) -> tuple[ContainerState, str | None]:
    """把 ``State.Status`` 解析为 :class:`ContainerState` 并给出说明。

    返回 ``(状态, 说明或 None)``。未知字符串与缺失值都折叠为 ``UNKNOWN``
    并附带说明（"未判定"必须可见）；非字符串且非 ``None`` 的值报错。
    """

    if raw is None:
        return ContainerState.UNKNOWN, "State.Status 缺失，state=unknown（未判定）"
    if not isinstance(raw, str):
        raise ContainerValidationError(
            f"State.Status 必须是字符串，实际为 {type(raw).__name__}"
        )
    known = DOCKER_STATE_MAP.get(raw)
    if known is not None:
        return known, None
    allowed = ", ".join(sorted(DOCKER_STATE_MAP))
    return (
        ContainerState.UNKNOWN,
        f"State.Status={raw!r} 不在已知集合 {{{allowed}}} 内，"
        "state=unknown（未判定，不当作 running）",
    )


def parse_rfc3339_ns(value: Any, *, field: str) -> int | None:
    """把 docker 的 RFC3339 时间戳解析为 Unix epoch 纳秒。

    * ``None`` → ``None``（未采集）
    * ``0001-01-01T00:00:00Z`` 等零时间 → ``None``（"尚未发生"，不是真实时刻）
    * 小数字段最多 9 位，按纳秒保留精度（不经过 float）
    * 必须带时区（``Z`` 或 ``±HH:MM``）；本地时间无时区信息，一律报错

    无法解析、日期非法或早于 epoch 都抛 :class:`ContainerValidationError`。
    """

    if value is None:
        return None
    if not isinstance(value, str):
        raise ContainerValidationError(
            f"{field} 必须是 RFC3339 字符串，实际为 {type(value).__name__}"
        )
    if value.startswith(ZERO_DOCKER_TIMESTAMP_PREFIX):
        return None
    matched = _TS_RE.match(value)
    if matched is None:
        raise ContainerValidationError(
            f"{field} 不是可解析的 RFC3339 时间戳（要求带时区）：{value!r}"
        )
    parts = {
        name: int(matched.group(name))
        for name in ("year", "month", "day", "hour", "minute", "second")
    }
    try:
        moment = datetime(
            parts["year"],
            parts["month"],
            parts["day"],
            parts["hour"],
            parts["minute"],
            parts["second"],
            tzinfo=timezone.utc,
        )
    except ValueError as exc:
        raise ContainerValidationError(
            f"{field} 不是合法日期时间：{value!r}（{exc}）"
        ) from exc
    epoch_seconds = calendar.timegm(moment.utctimetuple())
    if matched.group("sign") is not None:
        offset = int(matched.group("offset_hour")) * 3600 + int(
            matched.group("offset_minute")
        ) * 60
        epoch_seconds += -offset if matched.group("sign") == "+" else offset
    fraction = matched.group("frac") or ""
    nanoseconds = int(fraction.ljust(9, "0")) if fraction else 0
    total = epoch_seconds * 1_000_000_000 + nanoseconds
    if total < 0:
        raise ContainerValidationError(f"{field} 早于 Unix epoch：{value!r}")
    return total


def format_rfc3339_ns(value: int) -> str:
    """把 Unix epoch 纳秒渲染成 docker 风格的 RFC3339 字符串（测试与诊断用）。

    只支持非负值；纳秒部分最多 9 位，超出部分截断为微秒以内精度。
    """

    seconds, nanoseconds = divmod(_check_int("format_rfc3339_ns", "value", value, 0, MAX_INT64), 1_000_000_000)
    moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
    text = moment.strftime("%Y-%m-%dT%H:%M:%S")
    if nanoseconds:
        return f"{text}.{nanoseconds:09d}Z"
    return f"{text}Z"


def canonical_json(value: Any) -> str:
    """规范化 JSON 文本（与事件账本同规则，保证字节可复现）。

    ``sort_keys=True`` + 紧凑分隔符 + ``ensure_ascii=False`` + ``allow_nan=False``。
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


# --------------------------------------------------------------------------- #
# 挂载
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ContainerMount:
    """容器的一个挂载项（``docker inspect`` 的 ``Mounts[]`` 元素）。

    * ``mount_type``：规范化类型；未知 Type 折叠为 :attr:`MountType.OTHER`。
    * ``source``：**宿主**路径。可空：tmpfs 没有宿主路径，docker 也可能给空串
      （空串一律记为 ``None``，不伪造路径）。
    * ``destination``：**容器内**绝对路径，要求已是规范化形式。
    * ``read_write``：``RW`` 字段，必填；缺失即报错（不默认成只读或读写）。
    * ``raw_type``：docker 原始 ``Type`` 字符串，原样保留（含未知类型），
      用于解释"为什么折叠成 other"。
    """

    mount_type: MountType
    source: str | None
    destination: str
    read_write: bool
    raw_type: str

    #: ``to_dict``/``from_dict`` 的字段清单（ClassVar：不参与 dataclass 字段）。
    FIELDS: ClassVar[tuple[str, ...]] = (
        "mount_type",
        "source",
        "destination",
        "read_write",
        "raw_type",
    )

    def __post_init__(self) -> None:
        context = "container_mount"
        object.__setattr__(
            self, "mount_type", _coerce_enum(context, "mount_type", self.mount_type, MountType)
        )
        destination = _check_text(
            context, "destination", self.destination, max_bytes=MAX_PATH_BYTES, allow_empty=False
        )
        if not is_clean_absolute_path(destination):
            raise ContainerValidationError(
                f"{context}：destination 必须是规范化的绝对路径（无重复/结尾斜杠、"
                f"无 . / .. 分量），实际为 {destination!r}"
            )
        if self.source is not None:
            source = _check_text(
                context, "source", self.source, max_bytes=MAX_PATH_BYTES, allow_empty=False
            )
            if not is_clean_absolute_path(source):
                raise ContainerValidationError(
                    f"{context}：source 必须是规范化的绝对宿主路径或 None，"
                    f"实际为 {source!r}"
                )
        if not isinstance(self.read_write, bool):
            raise ContainerValidationError(
                f"{context}：read_write 必须是布尔值，实际为 {type(self.read_write).__name__}"
            )
        _check_text(
            context,
            "raw_type",
            self.raw_type,
            max_bytes=MAX_RAW_TYPE_BYTES,
            allow_empty=True,
        )

    # -- 转换 --------------------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        """展开为 JSON 可序列化字典（字段顺序固定）。"""

        return {
            "mount_type": str(self.mount_type),
            "source": self.source,
            "destination": self.destination,
            "read_write": self.read_write,
            "raw_type": self.raw_type,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ContainerMount:
        """从 :meth:`to_dict` 的输出恢复；缺字段或未知字段都报错。"""

        if not isinstance(data, Mapping):
            raise ContainerValidationError(
                f"container_mount：期望对象，实际为 {type(data).__name__}"
            )
        _check_required_keys("container_mount", data, cls.FIELDS)
        _check_no_unknown_keys("container_mount", data, cls.FIELDS)
        return cls(
            mount_type=data["mount_type"],
            source=data["source"],
            destination=data["destination"],
            read_write=data["read_write"],
            raw_type=data["raw_type"],
        )

    @classmethod
    def from_inspect(cls, entry: Any, *, index: int | None = None) -> ContainerMount:
        """解析 ``docker inspect`` 的一个 ``Mounts[]`` 元素。

        ``Type`` / ``Destination`` / ``RW`` 必须存在；``Source`` 可缺失或为空串
        （记为 ``None``）。``Destination`` 会先做纯词法清理（重复/结尾斜杠），
        但含 ``..`` 或相对路径一律报错——那类输入无法可靠映射。
        """

        context = "mounts[]" if index is None else f"mounts[{index}]"
        if not isinstance(entry, Mapping):
            raise ContainerValidationError(
                f"{context}：期望对象，实际为 {type(entry).__name__}"
            )
        _check_required_keys(context, entry, ("Type", "Destination", "RW"))

        raw_type = _check_text(
            context, "Type", entry["Type"], max_bytes=MAX_RAW_TYPE_BYTES, allow_empty=True
        )
        destination_raw = _check_text(
            context,
            "Destination",
            entry["Destination"],
            max_bytes=MAX_PATH_BYTES,
            allow_empty=False,
        )
        destination, reason = _clean_mount_path(destination_raw, what=f"{context}.Destination")
        if destination is None:
            raise ContainerValidationError(f"{context}：Destination 无法规范化：{reason}")

        source: str | None = None
        raw_source = entry.get("Source")
        if raw_source not in (None, ""):
            source_text = _check_text(
                context, "Source", raw_source, max_bytes=MAX_PATH_BYTES, allow_empty=False
            )
            source, reason = _clean_mount_path(source_text, what=f"{context}.Source")
            if source is None:
                raise ContainerValidationError(f"{context}：Source 无法规范化：{reason}")

        read_write = entry["RW"]
        if not isinstance(read_write, bool):
            raise ContainerValidationError(
                f"{context}：RW 必须是布尔值，实际为 {type(read_write).__name__}"
            )

        mount_type = MOUNT_TYPE_MAP.get(raw_type.strip().lower(), MountType.OTHER)
        return cls(
            mount_type=mount_type,
            source=source,
            destination=destination,
            read_write=read_write,
            raw_type=raw_type,
        )


def _clean_mount_path(path: str, *, what: str) -> tuple[str | None, str | None]:
    """挂载项路径的词法清理：只接受绝对路径，允许重复/结尾斜杠，拒绝 ``..``。"""

    if not path.startswith("/"):
        return None, f"{what} 是相对路径（{path!r}）"
    segments = [segment for segment in path.split("/") if segment not in ("", ".")]
    if ".." in segments:
        return None, f"{what} 含 '..' 分量（{path!r}）"
    return ("/" + "/".join(segments) if segments else "/"), None


def parse_mounts(data: Mapping[str, Any], *, context: str = "docker inspect") -> tuple[ContainerMount, ...]:
    """解析 inspect 顶层 ``Mounts`` 字段为挂载元组。

    ``Mounts`` 必须存在且是数组；单个容器超过 :data:`MAX_MOUNTS` 个挂载直接报错
    （静默截断会让挂载视图给出错误路径）。
    """

    if "Mounts" not in data:
        raise ContainerValidationError(f"{context}：缺少必需字段 Mounts")
    raw_mounts = data["Mounts"]
    if isinstance(raw_mounts, (str, bytes)) or not isinstance(raw_mounts, Sequence):
        raise ContainerValidationError(
            f"{context}：Mounts 必须是数组，实际为 {type(raw_mounts).__name__}"
        )
    if len(raw_mounts) > MAX_MOUNTS:
        raise ContainerValidationError(
            f"{context}：挂载数量 {len(raw_mounts)} 超过上限 {MAX_MOUNTS}"
        )
    return tuple(
        ContainerMount.from_inspect(entry, index=index)
        for index, entry in enumerate(raw_mounts)
    )


# --------------------------------------------------------------------------- #
# 容器
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ContainerInfo:
    """某个容器的规范化真值快照（来自一次 ``docker inspect``）。

    字段语义与"缺失"约定：

    * ``state``：见 :class:`ContainerState`；未知/缺失 → ``unknown``（未判定）。
    * ``host_pid``：容器主进程在**宿主**命名空间的 PID。``None`` 表示拿不到
      （容器未运行、docker 报 ``Pid=0``、字段缺失）。**绝不**用 0 或负值填充，
      构造器会直接拒绝 ``host_pid=0``。
    * ``cgroup_id`` / ``cgroup_path``：``None`` 表示未提供/未采集，
      不代表"没有 cgroup"。标准 ``docker inspect`` 不提供这两个值，
      只有增强查询（见 :mod:`agent_probe.container.cgroup`）才会填。
    * ``created_at_ns`` / ``started_at_ns`` / ``finished_at_ns``：Unix epoch
      纳秒；``None`` 表示未知或 docker 的零时间（"尚未发生"）。
      时间先后**不做校验**：三个时间都来自 daemon 时钟，可能受时钟调整影响。
    * ``labels``：按 key 排序并冻结；空字符串值是合法数据，
      但**不会**匹配非空的查询标签（见 mapper 的唯一匹配规则）。
    """

    container_id: str
    name: str
    labels: Mapping[str, str]
    state: ContainerState
    host_pid: int | None = None
    cgroup_id: int | None = None
    cgroup_path: str | None = None
    created_at_ns: int | None = None
    started_at_ns: int | None = None
    finished_at_ns: int | None = None

    #: ``to_dict``/``from_dict`` 的字段清单（ClassVar：不参与 dataclass 字段）。
    FIELDS: ClassVar[tuple[str, ...]] = (
        "container_id",
        "name",
        "labels",
        "state",
        "host_pid",
        "cgroup_id",
        "cgroup_path",
        "created_at_ns",
        "started_at_ns",
        "finished_at_ns",
    )

    def __post_init__(self) -> None:
        context = "container_info"
        object.__setattr__(
            self, "container_id", validate_container_id(self.container_id)
        )

        name = _check_text(context, "name", self.name, allow_empty=False)
        if name.startswith("/"):
            # docker inspect 的 Name 带前导 '/'，本层统一去掉单个前导 '/'。
            name = name[1:]
        if not name:
            raise ContainerValidationError(f"{context}：name 去掉前导 '/' 后为空")
        object.__setattr__(self, "name", name)

        object.__setattr__(self, "labels", _check_labels(self.labels))
        object.__setattr__(
            self, "state", _coerce_enum(context, "state", self.state, ContainerState)
        )

        for field in ("host_pid", "cgroup_id"):
            value = getattr(self, field)
            if value == 0:
                raise ContainerValidationError(
                    f"{context}：{field}=0 不是有效值（docker 用 0 表示"
                    "\"没有宿主进程\"/未知），未知请写 None，不要填 0"
                )
            _check_nullable_int(context, field, value, 1, MAX_INT64)

        if self.cgroup_path is not None:
            cgroup_path = _check_text(
                context,
                "cgroup_path",
                self.cgroup_path,
                max_bytes=MAX_PATH_BYTES,
                allow_empty=False,
            )
            if not is_clean_absolute_path(cgroup_path):
                raise ContainerValidationError(
                    f"{context}：cgroup_path 必须是规范化的绝对路径或 None，"
                    f"实际为 {cgroup_path!r}"
                )

        for field in ("created_at_ns", "started_at_ns", "finished_at_ns"):
            _check_nullable_int(context, field, getattr(self, field), 0, MAX_INT64)

    # -- 转换 --------------------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        """展开为 JSON 可序列化字典（字段顺序固定，未知值写 ``null``）。"""

        return {
            "container_id": self.container_id,
            "name": self.name,
            "labels": dict(self.labels),
            "state": str(self.state),
            "host_pid": self.host_pid,
            "cgroup_id": self.cgroup_id,
            "cgroup_path": self.cgroup_path,
            "created_at_ns": self.created_at_ns,
            "started_at_ns": self.started_at_ns,
            "finished_at_ns": self.finished_at_ns,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ContainerInfo:
        """从 :meth:`to_dict` 的输出恢复；缺字段或未知字段都报错。"""

        if not isinstance(data, Mapping):
            raise ContainerValidationError(
                f"container_info：期望对象，实际为 {type(data).__name__}"
            )
        _check_required_keys("container_info", data, cls.FIELDS)
        _check_no_unknown_keys("container_info", data, cls.FIELDS)
        return cls(
            container_id=data["container_id"],
            name=data["name"],
            labels=data["labels"],
            state=data["state"],
            host_pid=data["host_pid"],
            cgroup_id=data["cgroup_id"],
            cgroup_path=data["cgroup_path"],
            created_at_ns=data["created_at_ns"],
            started_at_ns=data["started_at_ns"],
            finished_at_ns=data["finished_at_ns"],
        )

    @classmethod
    def from_inspect(cls, data: Mapping[str, Any]) -> ContainerInfo:
        """解析 ``docker inspect`` 输出的单个容器对象（丢掉附带说明）。"""

        return parse_inspect(data).info

    def active_interval(self) -> tuple[int | None, int | None]:
        """返回 ``(created_at_ns, finished_at_ns)``；``finished_at_ns=None`` 表示未知/仍在运行。"""

        return (self.created_at_ns, self.finished_at_ns)


@dataclass(frozen=True, slots=True)
class InspectView:
    """一次 inspect 解析的结果：容器信息 + 挂载视图 + 解析说明。"""

    info: ContainerInfo
    mounts: tuple[ContainerMount, ...]
    notes: tuple[str, ...] = ()


def parse_inspect(data: Mapping[str, Any], *, context: str = "docker inspect") -> InspectView:
    """解析 ``docker inspect <id>`` 的单个容器 JSON 对象。

    必需顶层键：``Id`` / ``Name`` / ``State`` / ``Mounts``（缺失即报错）。
    ``Config`` / ``Created`` / ``State.Pid`` / ``State.StartedAt`` / ``State.FinishedAt``
    以及可选的 ``CgroupID`` / ``CgroupPath`` 缺失时给 ``None`` 并附一条说明——
    **未知就是未知**，不会被填成 0、空串或"最近一次"的值。

    返回 :class:`InspectView`，其中 ``notes`` 是需要进入 evidence 的说明。
    """

    if not isinstance(data, Mapping):
        raise ContainerValidationError(
            f"{context}：期望对象，实际为 {type(data).__name__}"
        )
    _check_required_keys(context, data, INSPECT_REQUIRED_KEYS)

    notes: list[str] = []
    container_id = validate_container_id(data["Id"], field=f"{context}.Id")
    name = _check_text(context, "Name", data["Name"], allow_empty=False)

    raw_state = data["State"]
    if not isinstance(raw_state, Mapping):
        raise ContainerValidationError(
            f"{context}：State 必须是对象，实际为 {type(raw_state).__name__}"
        )
    state, state_note = parse_container_state(raw_state.get("Status"))
    if state_note is not None:
        notes.append(f"容器 {container_id}：{state_note}")

    host_pid = _parse_host_pid(raw_state, container_id=container_id, state=state, notes=notes)

    created_at_ns = parse_rfc3339_ns(data.get("Created"), field=f"{context}.Created")
    if created_at_ns is None and data.get("Created") is not None:
        notes.append(
            f"容器 {container_id}：Created 是 docker 零时间（尚未发生），created_at_ns=null"
        )
    elif "Created" not in data:
        notes.append(f"容器 {container_id}：Created 缺失，created_at_ns=null")
    started_at_ns = parse_rfc3339_ns(
        raw_state.get("StartedAt"), field=f"{context}.State.StartedAt"
    )
    finished_at_ns = parse_rfc3339_ns(
        raw_state.get("FinishedAt"), field=f"{context}.State.FinishedAt"
    )
    if started_at_ns is None and state in (ContainerState.RUNNING, ContainerState.EXITED):
        notes.append(
            f"容器 {container_id}：state={state} 但 StartedAt 缺失/零时间，"
            "started_at_ns=null（不猜测）"
        )

    labels = _parse_labels(data, container_id=container_id, notes=notes)
    cgroup_id, cgroup_path = _parse_cgroup(data, container_id=container_id, notes=notes)
    mounts = parse_mounts(data, context=context)

    info = ContainerInfo(
        container_id=container_id,
        name=name,
        labels=labels,
        state=state,
        host_pid=host_pid,
        cgroup_id=cgroup_id,
        cgroup_path=cgroup_path,
        created_at_ns=created_at_ns,
        started_at_ns=started_at_ns,
        finished_at_ns=finished_at_ns,
    )
    return InspectView(info=info, mounts=mounts, notes=tuple(notes))


def _parse_host_pid(
    raw_state: Mapping[str, Any],
    *,
    container_id: str,
    state: ContainerState,
    notes: list[str],
) -> int | None:
    """解析 ``State.Pid``；拿不到就是 ``None``（绝不填 0）。"""

    raw_pid = raw_state.get("Pid")
    if raw_pid is None:
        if state is ContainerState.RUNNING:
            notes.append(
                f"容器 {container_id}：state=running 但 State.Pid 缺失，host_pid=null"
            )
        return None
    if isinstance(raw_pid, bool) or not isinstance(raw_pid, int):
        raise ContainerValidationError(
            f"State.Pid 必须是整数，实际为 {type(raw_pid).__name__}"
        )
    if raw_pid == 0:
        notes.append(
            f"容器 {container_id}：State.Pid=0 表示没有宿主进程，host_pid=null"
        )
        return None
    if raw_pid < 0:
        raise ContainerValidationError(f"State.Pid 不能为负数，实际为 {raw_pid}")
    return raw_pid


def _parse_labels(
    data: Mapping[str, Any], *, container_id: str, notes: list[str]
) -> Mapping[str, str]:
    """解析 ``Config.Labels``；缺失或 null 视为"无标签"，非法类型报错。"""

    if "Config" not in data or data["Config"] is None:
        notes.append(f"容器 {container_id}：Config/Labels 缺失，按无标签处理")
        return MappingProxyType({})
    config = data["Config"]
    if not isinstance(config, Mapping):
        raise ContainerValidationError(
            f"Config 必须是对象，实际为 {type(config).__name__}"
        )
    raw_labels = config.get("Labels")
    if raw_labels is None:
        return MappingProxyType({})
    return _check_labels(raw_labels)


def _parse_cgroup(
    data: Mapping[str, Any], *, container_id: str, notes: list[str]
) -> tuple[int | None, str | None]:
    """解析可选扩展键 ``CgroupID`` / ``CgroupPath``（标准 docker inspect 不提供）。"""

    raw_id = data.get(CGROUP_ID_KEY)
    cgroup_id: int | None = None
    if raw_id is not None:
        if isinstance(raw_id, bool) or not isinstance(raw_id, int):
            raise ContainerValidationError(
                f"{CGROUP_ID_KEY} 必须是整数，实际为 {type(raw_id).__name__}"
            )
        if raw_id < 0:
            raise ContainerValidationError(f"{CGROUP_ID_KEY} 不能为负数，实际为 {raw_id}")
        if raw_id == 0:
            notes.append(
                f"容器 {container_id}：{CGROUP_ID_KEY}=0 不是合法的 cgroup 标识，"
                "cgroup_id=null"
            )
        else:
            cgroup_id = raw_id

    raw_path = data.get(CGROUP_PATH_KEY)
    cgroup_path: str | None = None
    if raw_path not in (None, ""):
        path_text = _check_text(
            CGROUP_PATH_KEY, CGROUP_PATH_KEY, raw_path, max_bytes=MAX_PATH_BYTES, allow_empty=False
        )
        if not is_clean_absolute_path(path_text):
            raise ContainerValidationError(
                f"{CGROUP_PATH_KEY} 必须是规范化的绝对路径，实际为 {path_text!r}"
            )
        cgroup_path = path_text
    elif raw_path == "":
        notes.append(
            f"容器 {container_id}：{CGROUP_PATH_KEY} 为空串，cgroup_path=null"
        )

    note = data.get(CGROUP_NOTE_KEY)
    if note is not None:
        notes.append(
            f"容器 {container_id}："
            + _check_text(CGROUP_NOTE_KEY, CGROUP_NOTE_KEY, note)
        )
    return cgroup_id, cgroup_path


# --------------------------------------------------------------------------- #
# 映射结果
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ContainerMapping:
    """一次 "任务标签 → 容器" 映射的完整结果（含证据与不确定性）。

    跨字段不变式（构造即校验，避免出现自相矛盾的报告）：

    * ``MAPPED``：必须有 ``mapping``、不得有 ``reason``，
      且 ``candidates`` 恰为 ``(mapping,)``；
    * ``AMBIGUOUS``：``mapping`` 必须为 ``None``，``candidates`` 至少一个，
      不得给出 ``mounts``（没有唯一容器就没有挂载视图），``reason`` 必填；
    * ``UNMAPPED`` / ``ERROR``：``mapping``/``candidates``/``mounts`` 都必须为空，
      ``reason`` 必填。

    ``mounts`` 只在 ``MAPPED`` 时非空（对象容器没有挂载时也允许为空元组）。
    ``observed_monotonic_ns`` 是本模块的观测时刻（``CLOCK_MONOTONIC`` 纳秒），
    与容器自身的 wall-clock 时间无关；报告里必须区分这两类时间。
    """

    outcome: MappingOutcome
    task_label: str
    mapping: ContainerInfo | None
    candidates: tuple[ContainerInfo, ...]
    mounts: tuple[ContainerMount, ...]
    evidence: tuple[str, ...]
    reason: str | None
    observed_monotonic_ns: int

    #: ``to_dict``/``from_dict`` 的字段清单（ClassVar：不参与 dataclass 字段）。
    FIELDS: ClassVar[tuple[str, ...]] = (
        "outcome",
        "task_label",
        "mapping",
        "candidates",
        "mounts",
        "evidence",
        "reason",
        "observed_monotonic_ns",
    )

    def __post_init__(self) -> None:
        context = "container_mapping"
        outcome = _coerce_enum(context, "outcome", self.outcome, MappingOutcome)
        object.__setattr__(self, "outcome", outcome)
        _check_text(context, "task_label", self.task_label)

        if self.mapping is not None and not isinstance(self.mapping, ContainerInfo):
            raise ContainerValidationError(
                f"{context}：mapping 必须是 ContainerInfo 或 None，"
                f"实际为 {type(self.mapping).__name__}"
            )
        _check_tuple_of(context, "candidates", self.candidates, ContainerInfo)
        _check_tuple_of(context, "mounts", self.mounts, ContainerMount)
        _check_tuple_of(context, "evidence", self.evidence, str)
        for index, text in enumerate(self.evidence):
            _check_text(context, f"evidence[{index}]", text)
        if self.reason is not None:
            _check_text(context, "reason", self.reason, allow_empty=False)
        _check_int(context, "observed_monotonic_ns", self.observed_monotonic_ns, 0, MAX_INT64)

        if outcome is MappingOutcome.MAPPED:
            if self.mapping is None:
                raise ContainerValidationError(
                    f"{context}：outcome=mapped 必须给出 mapping（不确定请用 ambiguous/error）"
                )
            if self.reason is not None:
                raise ContainerValidationError(
                    f"{context}：outcome=mapped 不允许携带 reason（{self.reason!r}）"
                )
            if self.candidates != (self.mapping,):
                raise ContainerValidationError(
                    f"{context}：outcome=mapped 的 candidates 必须恰好是 (mapping,)，"
                    f"实际为 {len(self.candidates)} 个候选"
                )
            return

        if self.mapping is not None:
            raise ContainerValidationError(
                f"{context}：outcome={outcome} 不允许携带 mapping"
            )
        if self.mounts:
            raise ContainerValidationError(
                f"{context}：outcome={outcome} 不给出挂载视图（没有唯一容器）"
            )
        if self.reason is None:
            raise ContainerValidationError(
                f"{context}：outcome={outcome} 必须给出 reason 说明原因"
            )
        if outcome is MappingOutcome.AMBIGUOUS:
            if not self.candidates:
                raise ContainerValidationError(
                    f"{context}：outcome=ambiguous 至少要列出一个候选"
                )
        elif self.candidates:
            raise ContainerValidationError(
                f"{context}：outcome={outcome} 不应有候选（被时间窗排除的容器记入 evidence）"
            )

    # -- 转换 --------------------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        """展开为 JSON 可序列化字典（字段顺序固定）。"""

        return {
            "outcome": str(self.outcome),
            "task_label": self.task_label,
            "mapping": self.mapping.to_dict() if self.mapping is not None else None,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "mounts": [mount.to_dict() for mount in self.mounts],
            "evidence": list(self.evidence),
            "reason": self.reason,
            "observed_monotonic_ns": self.observed_monotonic_ns,
        }

    def to_json(self) -> str:
        """规范化 JSON 文本（字节可复现，用于报告与快照对比）。"""

        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ContainerMapping:
        """从 :meth:`to_dict` 的输出恢复（含候选列表与挂载视图）。"""

        if not isinstance(data, Mapping):
            raise ContainerValidationError(
                f"container_mapping：期望对象，实际为 {type(data).__name__}"
            )
        _check_required_keys("container_mapping", data, cls.FIELDS)
        _check_no_unknown_keys("container_mapping", data, cls.FIELDS)

        raw_mapping = data["mapping"]
        mapping = (
            None if raw_mapping is None else ContainerInfo.from_dict(raw_mapping)
        )
        raw_candidates = data["candidates"]
        if isinstance(raw_candidates, (str, bytes)) or not isinstance(raw_candidates, Sequence):
            raise ContainerValidationError(
                f"container_mapping：candidates 必须是数组，"
                f"实际为 {type(raw_candidates).__name__}"
            )
        raw_mounts = data["mounts"]
        if isinstance(raw_mounts, (str, bytes)) or not isinstance(raw_mounts, Sequence):
            raise ContainerValidationError(
                f"container_mapping：mounts 必须是数组，实际为 {type(raw_mounts).__name__}"
            )
        raw_evidence = data["evidence"]
        if isinstance(raw_evidence, (str, bytes)) or not isinstance(raw_evidence, Sequence):
            raise ContainerValidationError(
                f"container_mapping：evidence 必须是数组，"
                f"实际为 {type(raw_evidence).__name__}"
            )
        return cls(
            outcome=data["outcome"],
            task_label=data["task_label"],
            mapping=mapping,
            candidates=tuple(
                ContainerInfo.from_dict(item) for item in raw_candidates
            ),
            mounts=tuple(ContainerMount.from_dict(item) for item in raw_mounts),
            evidence=tuple(raw_evidence),
            reason=data["reason"],
            observed_monotonic_ns=data["observed_monotonic_ns"],
        )
