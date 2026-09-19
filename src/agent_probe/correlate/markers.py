"""辅助模式的输入：应用侧**声明**（assistant markers）。

定位（务必与代码一致）：这里的每一条记录都是**声明**，不是事实。

* 声明本身**永远不足以**产生 ``CERTAIN`` 关联：必须与系统事件（进程身份、
  ``tls.bytes`` 连接、``run_id``）交叉核验。
* 交叉核验通过 → ``CERTAIN``；有未核验缺口但没有反证 → ``PROBABLE``；
  与系统证据**冲突** → 降级为 ``AMBIGUOUS``（有替代候选时）或 ``PROBABLE``，
  并且边的 ``evidence`` 里**同时**保留"声明"与"系统证据"两条字符串。
* 关闭 ``CorrelationConfig.use_assisted_markers`` 时，这里的一切都被忽略
  （结果里会留下显式 note，不会静默）。

``run_id``/``call_id``/``tool_id``/``task_label`` 的语义：

* ``run_id``：声明该调用/工具属于哪个 probe run。与任务声明核对。
* ``task_label``：声明该调用/工具属于哪个**任务标签**（``Task.label``）。用于
  应用只知道自己的任务名、不知道 probe 分配的 ``run_id`` 的场合；与
  ``run_id`` 二选一或同时给出（同时给出时两者都必须命中同一任务）。
* ``call_id``：声明该工具/副作用属于哪次调用；匹配范围是
  ``physical_request_id`` 或 ``logical_call_id``。
* ``tool_id``：声明一次工具执行的标识；一个 tool_id 会产生一个
  :attr:`~agent_probe.correlate.model.EvidenceNodeKind.TOOL_CALL` 节点。
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import MISSING as _MISSING
from dataclasses import dataclass
from typing import Any

from agent_probe.events import canonical_json

from .errors import CorrelationInputError
from .model import _check_int, _check_json_serializable, _check_text, _require_keys

__all__ = ["MarkerDeclaration", "AssistantMarkers"]

_KNOWN_KEYS = (
    "run_id",
    "call_id",
    "tool_id",
    "connection_id",
    "task_label",
    "pid",
    "process_start_id",
    "monotonic_ns",
    "wall_time_ns",
    "label",
    "source",
)


@dataclass(frozen=True, slots=True)
class MarkerDeclaration:
    """一条应用侧声明（``None`` = 未声明；**不是** 0，也不是"无"）。"""

    run_id: str | None = None
    call_id: str | None = None
    tool_id: str | None = None
    connection_id: str | None = None
    task_label: str | None = None
    pid: int | None = None
    process_start_id: int | None = None
    monotonic_ns: int | None = None
    wall_time_ns: int | None = None
    label: str = ""
    source: str = "assistant"
    extra: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        for name in ("run_id", "call_id", "tool_id", "connection_id", "task_label"):
            value = getattr(self, name)
            if value is not None:
                _check_text(f"MarkerDeclaration.{name}", value)
        for name in ("pid", "process_start_id", "monotonic_ns", "wall_time_ns"):
            value = getattr(self, name)
            if value is not None:
                _check_int(f"MarkerDeclaration.{name}", value, minimum=0)
        _check_text("MarkerDeclaration.label", self.label, allow_empty=True)
        _check_text("MarkerDeclaration.source", self.source)
        if (
            self.run_id is None
            and self.call_id is None
            and self.tool_id is None
            and self.connection_id is None
        ):
            raise CorrelationInputError(
                "MarkerDeclaration 至少要声明 run_id / call_id / tool_id / connection_id 之一"
            )
        extra = {} if self.extra is None else dict(self.extra)
        for key in extra:
            if not isinstance(key, str):
                raise CorrelationInputError("MarkerDeclaration.extra 的键必须是字符串")
            if key in _KNOWN_KEYS:
                raise CorrelationInputError(
                    f"MarkerDeclaration.extra 不能覆盖已知字段 {key!r}"
                )
            _check_json_serializable(f"MarkerDeclaration.extra.{key}", extra[key])
        object.__setattr__(self, "extra", {key: extra[key] for key in sorted(extra)})

    # -- 身份 --------------------------------------------------------------- #

    def identity_key(self) -> str:
        """内容派生身份：完全相同的两条声明视为同一条。"""

        return canonical_json(
            {
                "run_id": self.run_id,
                "call_id": self.call_id,
                "tool_id": self.tool_id,
                "connection_id": self.connection_id,
                "task_label": self.task_label,
                "pid": self.pid,
                "process_start_id": self.process_start_id,
                "monotonic_ns": self.monotonic_ns,
                "wall_time_ns": self.wall_time_ns,
                "label": self.label,
                "source": self.source,
                "extra": dict(self.extra),
            }
        )

    def sort_key(self) -> tuple[Any, ...]:
        """确定性排序键：与字典迭代顺序、输入顺序无关。"""

        return (
            self.run_id or "",
            -1 if self.monotonic_ns is None else self.monotonic_ns,
            self.call_id or "",
            self.tool_id or "",
            self.connection_id or "",
            self.task_label or "",
            -1 if self.pid is None else self.pid,
            -1 if self.process_start_id is None else self.process_start_id,
            self.identity_key(),
        )

    def declared_fields(self) -> tuple[str, ...]:
        """已声明的字段名（升序），用于 evidence 与核验统计。"""

        names = [
            name
            for name in _KNOWN_KEYS
            if name not in ("label", "source") and getattr(self, name) is not None
        ]
        return tuple(sorted(names))

    def task_label_key(self) -> str | None:
        """声明里用于定位任务的标签（``task_label`` 优先，其次 ``run_id``）。"""

        return self.task_label

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "call_id": self.call_id,
            "tool_id": self.tool_id,
            "connection_id": self.connection_id,
            "task_label": self.task_label,
            "pid": self.pid,
            "process_start_id": self.process_start_id,
            "monotonic_ns": self.monotonic_ns,
            "wall_time_ns": self.wall_time_ns,
            "label": self.label,
            "source": self.source,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MarkerDeclaration:
        if not isinstance(data, Mapping):
            raise CorrelationInputError(
                f"MarkerDeclaration：期望对象，实际为 {type(data).__name__}"
            )
        explicit_extra = data.get("extra")
        extra: dict[str, Any] = {}
        if explicit_extra is not None:
            if not isinstance(explicit_extra, Mapping):
                raise CorrelationInputError(
                    "MarkerDeclaration.extra 必须是映射"
                )
            extra.update(explicit_extra)
        for key in data:
            if key not in _KNOWN_KEYS and key != "extra":
                extra[key] = data[key]
        payload: dict[str, Any] = {}
        for name, spec in cls.__dataclass_fields__.items():
            if name == "extra":
                continue
            if name in data:
                payload[name] = data[name]
            elif spec.default is not _MISSING:
                payload[name] = spec.default
            else:  # pragma: no cover - 所有字段都有默认值
                raise CorrelationInputError(
                    f"MarkerDeclaration：缺少没有默认值的字段 {name!r}"
                )
        payload["extra"] = extra
        return cls(**payload)


@dataclass(frozen=True, slots=True)
class AssistantMarkers:
    """辅助模式的输入集合：``run_id`` / ``call_id`` / ``tool_id`` 声明的载体。

    :meth:`from_records` 面向"记录序列"（例如应用适配器吐出的 hook 事件）；
    :meth:`to_dict` / :meth:`from_dict` 保证 JSON 往返。
    """

    declarations: tuple[MarkerDeclaration, ...] = ()

    def __post_init__(self) -> None:
        raw = tuple(self.declarations)
        normalized: list[MarkerDeclaration] = []
        seen: set[str] = set()
        for item in raw:
            declaration = item if isinstance(item, MarkerDeclaration) else MarkerDeclaration.from_dict(item)
            key = declaration.identity_key()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(declaration)
        normalized.sort(key=MarkerDeclaration.sort_key)
        object.__setattr__(self, "declarations", tuple(normalized))

    # -- 构造 --------------------------------------------------------------- #

    @classmethod
    def from_records(
        cls, records: Iterable[Mapping[str, Any] | MarkerDeclaration]
    ) -> AssistantMarkers:
        """从记录序列构造（**显式校验**，不做宽容解析）。

        每条记录可以是 :class:`MarkerDeclaration`，也可以是普通映射
        （``{"call_id": …, "tool_id": …, "task_label": …}``）：

        * 不是映射也不是 :class:`MarkerDeclaration` → 抛
          :class:`~agent_probe.correlate.errors.CorrelationInputError`；
        * 已知字段逐项做类型/范围校验（``bool`` 不算 ``int``）；
        * 未知键进入 ``extra``：**保留但不解释语义**，绝不参与关联判定。
        """

        normalized: list[MarkerDeclaration | Mapping[str, Any]] = []
        for index, item in enumerate(records):
            if isinstance(item, (MarkerDeclaration, Mapping)):
                normalized.append(item)
                continue
            raise CorrelationInputError(
                f"AssistantMarkers.from_records 的第 {index} 条记录既不是映射也不是 "
                f"MarkerDeclaration，而是 {type(item).__name__}"
            )
        return cls(declarations=tuple(normalized))

    @classmethod
    def single(cls, **fields: Any) -> AssistantMarkers:
        """便捷构造：一条声明。"""

        return cls(declarations=(MarkerDeclaration(**fields),))

    def __len__(self) -> int:
        return len(self.declarations)

    @property
    def is_empty(self) -> bool:
        return not self.declarations

    # -- 序列化 ------------------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        return {"declarations": [item.to_dict() for item in self.declarations]}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AssistantMarkers:
        _require_keys("AssistantMarkers", data, {"declarations"})
        return cls(declarations=tuple(MarkerDeclaration.from_dict(item) for item in data["declarations"]))
