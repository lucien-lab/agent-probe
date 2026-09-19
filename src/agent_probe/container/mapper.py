"""任务标签 → 容器 → 宿主 PID/cgroup → 挂载视图 的映射（M3 容器归因核心）。

**信任模型（必须先读）**

* 容器由 **Docker daemon** 创建，容器内进程**不在** agent 的进程树里。
  因此本模块**只**用三样东西做映射：容器 **label 值**、
  ``docker inspect`` 的**显式真值字段**、以及调用方给出的**时间窗**。
  不允许用进程树推断，也不允许把"最近创建""最近退出"当成唯一映射。
* 时间窗只做**过滤与不确定标注**，永远不做"取最近的候选"：
  窗口内所有同标签容器都进入候选并保持歧义。
* 查询/解析失败一律返回 ``outcome=ERROR`` 且 ``reason`` 必填；
  拿不到的字段写 ``None``（绝不填 0 或猜测值）。

**四种 outcome 的判定规则**

1. ``MAPPED``：恰好一个候选，且调用方给出的时间约束**全部验证通过**。
2. ``AMBIGUOUS``：
   * 候选多于一个（含被 ``max_candidates`` 截断的情况），或
   * 只有一个候选，但该候选的时间约束**无法验证**（``created_at_ns`` 为 ``None``）
     或与调用方窗口**不一致**（容器创建早于窗口起点但仍跨越窗口）。
   ``candidates`` 列出全部（受截断），``reason`` 区分两种情况。
3. ``UNMAPPED``：该 label 没有任何候选。因"创建时间在窗口之外"被排除的容器
   只写进 ``evidence``，不进入候选（但也**不是静默丢弃**）。
4. ``ERROR``：``list_container_ids``/``inspect``/解析任一步失败。
   ``reason`` 说明是哪一步、哪个容器、为什么。

**竞态与短命任务**

* "同一标签的容器已退出但仍在时间窗内" → 如实进入候选（``state=exited``），
  不因为"已经退出"就被丢掉。
* "容器创建早于窗口起点、但在窗口内仍然存活" → 进入候选但标注为不一致，
  整体降级为 ``AMBIGUOUS``：拿不到唯一确定结论时**必须**显式表达。
* "容器在窗口开始前就已结束" → 排除，并在 evidence 里记录 ID 与时间。

**有界性**

* 候选数量不超过 ``max_candidates``（按 ``container_id`` 升序截断，
  截断事实写进 evidence，保证报告可复现）；
* evidence 条数有上限，超出只留截断提示；
* 挂载数量上限由 :data:`~agent_probe.container.model.MAX_MOUNTS` 控制
  （超限报错而不是静默截断）。
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any, Final

from .errors import ContainerError, ContainerValidationError
from .model import (
    DEFAULT_LABEL_KEY,
    MAX_INT64,
    MAX_TEXT_BYTES,
    ContainerInfo,
    ContainerMapping,
    ContainerMount,
    ContainerState,
    MappingOutcome,
    parse_inspect,
)
from .mounts import MountResolver
from .query import ContainerQuery

__all__ = [
    "DEFAULT_MAX_CANDIDATES",
    "MAX_CANDIDATES",
    "MAX_EVIDENCE_ITEMS",
    "ContainerTaskMapper",
]

#: 默认候选上限。
DEFAULT_MAX_CANDIDATES: Final[int] = 64

#: 候选上限的硬上界（防止调用方用极大值绕过"有界"约束）。
MAX_CANDIDATES: Final[int] = 4096

#: 映射结果里 evidence 的条数上限。
MAX_EVIDENCE_ITEMS: Final[int] = 128


class _EvidenceLog:
    """有界 evidence 收集器（超出上限只记录被丢弃的条数）。"""

    __slots__ = ("_items", "_dropped")

    def __init__(self) -> None:
        self._items: list[str] = []
        self._dropped = 0

    def add(self, text: str) -> None:
        if len(self._items) < MAX_EVIDENCE_ITEMS:
            self._items.append(text)
        else:
            self._dropped += 1

    def extend(self, texts: Iterable[str]) -> None:
        for text in texts:
            self.add(text)

    def finish(self) -> tuple[str, ...]:
        if self._dropped:
            return tuple(self._items) + (
                f"evidence 已截断：另有 {self._dropped} 条说明未列出"
                f"（上限 {MAX_EVIDENCE_ITEMS}）",
            )
        return tuple(self._items)


class ContainerTaskMapper:
    """按容器 label 把任务标签映射到容器，并给出挂载视图。

    * ``query``：:class:`~agent_probe.container.query.ContainerQuery` 实现
      （真实实现 :class:`~agent_probe.container.query.DockerCli`，
      测试用内存 fake）。本类**不**直接执行任何命令。
    * ``label_key``：容器上承载任务标签的 key（默认 ``agent-probe.task``）。
    * ``max_candidates``：候选上限（1..``MAX_CANDIDATES``）。

    每个 ``inspect`` 结果都会走到 :func:`~agent_probe.container.model.parse_inspect`，
    因此非法/缺字段的 inspect 会变成 ``outcome=ERROR``，不会静默降级。
    """

    __slots__ = ("_query", "_label_key", "_max_candidates")

    def __init__(
        self,
        query: ContainerQuery,
        *,
        label_key: str = DEFAULT_LABEL_KEY,
        max_candidates: int = DEFAULT_MAX_CANDIDATES,
    ) -> None:
        for method in ("list_container_ids", "inspect"):
            if not callable(getattr(query, method, None)):
                raise ContainerValidationError(
                    f"ContainerTaskMapper：查询对象 {type(query).__name__} "
                    f"未实现 {method}()"
                )
        if not isinstance(label_key, str):
            raise ContainerValidationError(
                f"label_key 必须是字符串，实际为 {type(label_key).__name__}"
            )
        if not label_key:
            raise ContainerValidationError("label_key 不能为空字符串")
        if "\x00" in label_key:
            raise ContainerValidationError("label_key 不能包含 NUL 字节")
        if len(label_key.encode("utf-8")) > MAX_TEXT_BYTES:
            raise ContainerValidationError(
                f"label_key 超过 {MAX_TEXT_BYTES} 字节上限"
            )
        if isinstance(max_candidates, bool) or not isinstance(max_candidates, int):
            raise ContainerValidationError(
                f"max_candidates 必须是整数，实际为 {type(max_candidates).__name__}"
            )
        if not 1 <= max_candidates <= MAX_CANDIDATES:
            raise ContainerValidationError(
                f"max_candidates 必须在 [1, {MAX_CANDIDATES}] 内，实际为 {max_candidates}"
            )

        self._query = query
        self._label_key = label_key
        self._max_candidates = max_candidates

    # -- 属性 --------------------------------------------------------------- #

    @property
    def query(self) -> ContainerQuery:
        return self._query

    @property
    def label_key(self) -> str:
        return self._label_key

    @property
    def max_candidates(self) -> int:
        return self._max_candidates

    # -- 映射 --------------------------------------------------------------- #

    def map_label(
        self,
        label: str,
        *,
        container_created_after_ns: int | None = None,
        container_created_before_ns: int | None = None,
        observed_monotonic_ns: int | None = None,
    ) -> ContainerMapping:
        """把任务标签 ``label`` 映射到容器。

        ``container_created_after_ns`` / ``container_created_before_ns`` 是**闭区间**
        创建时间窗（Unix epoch 纳秒），语义见本模块文档：窗口内的候选保持歧义，
        时间约束无法验证的候选降级为 ``AMBIGUOUS`` 而不是被静默丢弃。
        ``observed_monotonic_ns`` 不给出时取 ``CLOCK_MONOTONIC``；
        想要可复现的报告请显式传入。
        """

        label = _check_label(label)
        after = _check_timestamp(
            container_created_after_ns, field="container_created_after_ns"
        )
        before = _check_timestamp(
            container_created_before_ns, field="container_created_before_ns"
        )
        if after is not None and before is not None and after > before:
            raise ContainerValidationError(
                f"时间窗不合法：after={after} > before={before}"
            )
        observed = (
            _check_timestamp(observed_monotonic_ns, field="observed_monotonic_ns")
            if observed_monotonic_ns is not None
            else time.monotonic_ns()
        )
        assert observed is not None

        evidence = _EvidenceLog()
        evidence.add(
            f"查询标签 {label!r}（label_key={self._label_key!r}，"
            f"max_candidates={self._max_candidates}）"
        )
        window_text = _describe_window(after, before)
        if window_text is not None:
            evidence.add(window_text)

        try:
            container_ids = tuple(self._query.list_container_ids())
        except ContainerError as exc:
            return self._error(
                label,
                observed,
                f"list_container_ids() 失败：{exc}",
                evidence,
            )

        infos: list[ContainerInfo] = []
        mounts_by_id: dict[str, tuple[ContainerMount, ...]] = {}
        listed: list[str] = []
        seen_listed: set[str] = set()
        for container_id in container_ids:
            if container_id in seen_listed:
                evidence.add(
                    f"list_container_ids 重复列出 {container_id}，只查询一次"
                )
                continue
            seen_listed.add(container_id)
            listed.append(container_id)

        seen_resolved: set[str] = set()
        # 按容器 ID 升序扫描：evidence 的顺序与 docker ps 的返回顺序无关，
        # 因此同一真值集合得到字节一致的报告（可复现）。
        for container_id in sorted(listed):
            try:
                raw = self._query.inspect(container_id)
                view = parse_inspect(raw, context=f"docker inspect {container_id}")
            except ContainerError as exc:
                return self._error(
                    label,
                    observed,
                    f"inspect({container_id!r}) 失败：{exc}",
                    evidence,
                )
            info = view.info
            resolved_id = info.container_id
            if resolved_id in seen_resolved:
                evidence.add(
                    f"容器 {resolved_id} 被多次列出（不同写法），只计一次"
                )
                continue
            if not _same_container(container_id, resolved_id):
                return self._error(
                    label,
                    observed,
                    f"list_container_ids 给出 {container_id}，但 inspect 返回 "
                    f"{resolved_id}（可能查错了容器）",
                    evidence,
                )
            seen_resolved.add(resolved_id)
            infos.append(info)
            mounts_by_id[resolved_id] = view.mounts
            evidence.extend(view.notes)

        evidence.add(
            f"共查询 {len(infos)} 个容器（list_container_ids 返回 {len(container_ids)} 条，"
            f"去重后 {len(listed)} 条）"
        )

        matched = sorted(
            (info for info in infos if info.labels.get(self._label_key) == label),
            key=lambda item: item.container_id,
        )
        evidence.add(
            f"label {self._label_key}={label!r} 命中 {len(matched)} 个容器"
        )

        candidates: list[ContainerInfo] = []
        uncertain: dict[str, str] = {}
        excluded: list[str] = []
        for info in matched:
            decision = _evaluate_window(
                info, after=after, before=before
            )
            if decision.excluded_reason is not None:
                excluded.append(info.container_id)
                evidence.add(
                    f"排除容器 {info.container_id}（state={info.state}，"
                    f"created_at_ns={info.created_at_ns}）：{decision.excluded_reason}"
                )
                continue
            candidates.append(info)
            if decision.uncertain_reason is not None:
                uncertain[info.container_id] = decision.uncertain_reason
                evidence.add(
                    f"候选 {info.container_id} 的时间约束无法唯一确定："
                    f"{decision.uncertain_reason}"
                )
            evidence.extend(_candidate_notes(info))

        total_matched = len(candidates)
        ordered = sorted(candidates, key=lambda item: item.container_id)
        truncated = len(ordered) > self._max_candidates
        if truncated:
            ordered = ordered[: self._max_candidates]
            evidence.add(
                f"候选按 container_id 升序截断到 max_candidates="
                f"{self._max_candidates}（窗口内命中 {total_matched} 个，"
                "未列出的候选仍然存在）"
            )

        if not ordered:
            reason = (
                f"标签 {self._label_key}={label!r} 没有任何候选容器"
                f"（共查询 {len(infos)} 个容器）"
            )
            if excluded:
                reason += f"；{len(excluded)} 个同标签容器因创建/结束时间不在窗口内被排除"
            return ContainerMapping(
                outcome=MappingOutcome.UNMAPPED,
                task_label=label,
                mapping=None,
                candidates=(),
                mounts=(),
                evidence=evidence.finish(),
                reason=reason,
                observed_monotonic_ns=observed,
            )

        if len(ordered) == 1 and not truncated:
            only = ordered[0]
            reason = uncertain.get(only.container_id)
            if reason is None:
                return ContainerMapping(
                    outcome=MappingOutcome.MAPPED,
                    task_label=label,
                    mapping=only,
                    candidates=(only,),
                    mounts=mounts_by_id[only.container_id],
                    evidence=evidence.finish(),
                    reason=None,
                    observed_monotonic_ns=observed,
                )
            return ContainerMapping(
                outcome=MappingOutcome.AMBIGUOUS,
                task_label=label,
                mapping=None,
                candidates=(only,),
                mounts=(),
                evidence=evidence.finish(),
                reason=(
                    f"唯一候选 {only.container_id} 的时间约束无法验证或与调用方窗口"
                    f"不一致：{reason}"
                ),
                observed_monotonic_ns=observed,
            )

        reason = (
            f"标签 {self._label_key}={label!r} 有 {total_matched} 个候选容器，"
            "无法唯一确定（不做\"取最近\"猜测）"
        )
        if truncated:
            reason += f"；候选已按 container_id 截断到 {self._max_candidates} 个"
        return ContainerMapping(
            outcome=MappingOutcome.AMBIGUOUS,
            task_label=label,
            mapping=None,
            candidates=tuple(ordered),
            mounts=(),
            evidence=evidence.finish(),
            reason=reason,
            observed_monotonic_ns=observed,
        )

    def map_labels(
        self,
        labels: Iterable[str],
        *,
        container_created_after_ns: int | None = None,
        container_created_before_ns: int | None = None,
        observed_monotonic_ns: int | None = None,
    ) -> tuple[ContainerMapping, ...]:
        """对多个标签依次调用 :meth:`map_label`，保持输入顺序。

        全部结果共用同一个 ``observed_monotonic_ns``（未给出时取一次当前时间），
        因此同一批映射的观测时刻一致，报告里可比较。
        """

        if isinstance(labels, (str, bytes)) or not isinstance(labels, Iterable):
            raise ContainerValidationError(
                f"labels 必须是可迭代的标签集合，实际为 {type(labels).__name__}"
            )
        ordered = list(labels)
        if observed_monotonic_ns is None:
            observed_monotonic_ns = time.monotonic_ns()
        return tuple(
            self.map_label(
                label,
                container_created_after_ns=container_created_after_ns,
                container_created_before_ns=container_created_before_ns,
                observed_monotonic_ns=observed_monotonic_ns,
            )
            for label in ordered
        )

    def resolver_for(self, mapping: ContainerMapping) -> MountResolver:
        """返回映射结果对应的挂载视图解析器。

        只有 ``outcome=MAPPED`` 的映射才有唯一容器，才能解析挂载视图；
        其余情况显式报错（而不是返回一个"什么也解析不出来"的空解析器）。
        """

        if not isinstance(mapping, ContainerMapping):
            raise ContainerValidationError(
                f"resolver_for 期望 ContainerMapping，实际为 {type(mapping).__name__}"
            )
        if mapping.outcome is not MappingOutcome.MAPPED or mapping.mapping is None:
            raise ContainerValidationError(
                f"只有 outcome=mapped 的映射才能解析挂载视图，"
                f"当前为 {mapping.outcome}（{mapping.reason}）"
            )
        return MountResolver(
            mapping.mounts,
            container_id=mapping.mapping.container_id,
        )

    # -- 内部 --------------------------------------------------------------- #

    def _error(
        self,
        label: str,
        observed: int,
        reason: str,
        evidence: _EvidenceLog,
    ) -> ContainerMapping:
        evidence.add(f"映射失败：{reason}")
        return ContainerMapping(
            outcome=MappingOutcome.ERROR,
            task_label=label,
            mapping=None,
            candidates=(),
            mounts=(),
            evidence=evidence.finish(),
            reason=reason,
            observed_monotonic_ns=observed,
        )


class _WindowDecision:
    """单个容器相对调用方创建时间窗的判定结果。"""

    __slots__ = ("excluded_reason", "uncertain_reason")

    def __init__(
        self, excluded_reason: str | None = None, uncertain_reason: str | None = None
    ) -> None:
        self.excluded_reason = excluded_reason
        self.uncertain_reason = uncertain_reason


def _evaluate_window(
    info: ContainerInfo, *, after: int | None, before: int | None
) -> _WindowDecision:
    """判定容器是否进入候选，以及其时间约束是否可唯一确定。

    规则（写死在此处，避免各处口径不一致）：

    * 没有给出窗口 → 直接进入候选，不标注不确定。
    * ``created_at_ns`` 未知 → 进入候选并标注"无法验证"（不丢弃真值）。
    * ``created_at_ns`` 晚于窗口上界 → 排除（创建晚于窗口，不可能属于该窗口）。
    * ``created_at_ns`` 早于窗口下界：
        - 若 ``finished_at_ns`` 已知且早于下界 → 排除（窗口开始前已结束）；
        - 否则 → 进入候选并标注"创建早于窗口起点但覆盖窗口"，整体降级为
          ``AMBIGUOUS``（调用方的创建约束不满足，不做"取最近"猜测）。
    * 否则 → 进入候选，时间约束验证通过。
    """

    if after is None and before is None:
        return _WindowDecision()
    created = info.created_at_ns
    if created is None:
        return _WindowDecision(
            uncertain_reason=(
                "created_at_ns 缺失，无法验证调用方给出的创建时间窗"
                "（不猜测创建时间）"
            )
        )
    if before is not None and created > before:
        return _WindowDecision(
            excluded_reason=f"created_at_ns 晚于窗口上界 {before}"
        )
    if after is not None and created < after:
        finished = info.finished_at_ns
        if finished is not None and finished < after:
            return _WindowDecision(
                excluded_reason=(
                    f"容器在窗口开始前就已结束（finished_at_ns={finished} < {after}）"
                )
            )
        return _WindowDecision(
            uncertain_reason=(
                f"created_at_ns={created} 早于窗口起点 {after}，"
                f"但容器跨越窗口（finished_at_ns={finished}，state={info.state}）："
                "创建时间约束不满足"
            )
        )
    return _WindowDecision()


def _candidate_notes(info: ContainerInfo) -> tuple[str, ...]:
    """候选容器上值得进入 evidence 的"缺失/未判定"说明（不猜值，只陈述）。"""

    notes: list[str] = []
    if info.state is ContainerState.UNKNOWN:
        notes.append(
            f"候选 {info.container_id}：state=unknown（inspect 的状态字符串未知或缺失）"
        )
    if info.host_pid is None:
        notes.append(
            f"候选 {info.container_id}：host_pid=null（拿不到宿主 PID；state={info.state}）"
        )
    if info.host_pid is not None and info.cgroup_id is None:
        notes.append(
            f"候选 {info.container_id}：有宿主 PID 但 cgroup 标识缺失"
            "（inspect 未提供 CgroupPath/CgroupID），cgroup_id=null"
        )
    if info.cgroup_path is not None and info.cgroup_id is None:
        notes.append(
            f"候选 {info.container_id}：cgroup_path={info.cgroup_path} 已知，"
            "但 cgroup_id=null（未读到 cgroupfs inode）"
        )
    return tuple(notes)


def _check_label(label: Any) -> str:
    if not isinstance(label, str):
        raise ContainerValidationError(
            f"label 必须是字符串，实际为 {type(label).__name__}"
        )
    if not label:
        raise ContainerValidationError("label 不能为空字符串")
    if "\x00" in label:
        raise ContainerValidationError("label 不能包含 NUL 字节")
    if len(label.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ContainerValidationError(f"label 超过 {MAX_TEXT_BYTES} 字节上限")
    return label


def _check_timestamp(value: Any, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContainerValidationError(
            f"{field} 必须是整数纳秒或 None，实际为 {type(value).__name__}"
        )
    if value < 0 or value > MAX_INT64:
        raise ContainerValidationError(
            f"{field} 必须在 [0, {MAX_INT64}] 内，实际为 {value}"
        )
    return value


def _describe_window(after: int | None, before: int | None) -> str | None:
    if after is None and before is None:
        return None
    if after is not None and before is not None:
        return f"创建时间窗（闭区间）：[{after}, {before}]"
    if after is not None:
        return f"创建时间窗下界（闭区间）：>= {after}"
    return f"创建时间窗上界（闭区间）：<= {before}"


def _same_container(requested: str, returned: str) -> bool:
    """请求的（可能是 12 位短 ID）与 inspect 返回的完整 ID 是否指向同一容器。"""

    if returned == requested:
        return True
    return len(requested) < 64 and returned.startswith(requested)
