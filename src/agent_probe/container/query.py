"""容器查询端口与 ``docker`` CLI 实现（可注入 runner，测试不执行真实 docker）。

**设计要点**

* :class:`ContainerQuery` 是本子包唯一的查询端口：``list_container_ids()`` 与
  ``inspect(container_id)``。它只描述"能拿到什么"，不描述怎么拿，
  因此可以用内存 fake、也可以用别的后端（cri/containerd 适配）替换。
* :class:`DockerCli` 是**真实实现**：只有被显式调用时才执行 ``docker``，
  且命令固定为 ``docker ps``/``docker inspect``（不做 ``docker exec`` 等写操作）。
* **可注入 runner**：``runner(argv) -> (returncode, stdout, stderr)``，
  也可以是 :class:`RunnerResult`。测试注入 fake runner 即覆盖全部失败路径，
  不需要 docker、不需要网络。
* **失败即失败**：非零退出、无法启动、超时、stdout 不是 JSON、inspect 不是
  单个容器对象、字段缺失、返回的容器 ID 与请求不符——一律抛
  :class:`~agent_probe.container.errors.ContainerQueryError`。
  没有"尽力解析"分支。
* **cgroup 增强是显式的**：标准 ``docker inspect`` 不提供 cgroup 标识，
  只有显式注入 :class:`~agent_probe.container.cgroup.CgroupReader` 时，
  ``inspect()`` 才会追加 ``CgroupPath``/``CgroupID``（真值读不到就不加）。
  默认不注入，``inspect()`` 的输出与 ``docker inspect`` 保持一致。
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

from .cgroup import CgroupReader, CgroupRecord
from .errors import (
    ContainerNotFoundError,
    ContainerQueryError,
    ContainerTimeoutError,
    ContainerValidationError,
)
from .model import (
    CGROUP_ID_KEY,
    CGROUP_NOTE_KEY,
    CGROUP_PATH_KEY,
    ContainerInfo,
    validate_container_id,
)

__all__ = [
    "DEFAULT_DOCKER_BINARY",
    "DEFAULT_TIMEOUT_S",
    "MAX_EXCERPT_BYTES",
    "PS_ARGS",
    "INSPECT_ARGS",
    "RunnerResult",
    "DockerRunner",
    "SubprocessRunner",
    "ContainerQuery",
    "DockerCli",
]

#: 默认 docker 可执行文件名（允许注入绝对路径）。
DEFAULT_DOCKER_BINARY: Final[str] = "docker"

#: 单次 docker 查询的超时（秒）。超时**不是**"没有结果"，而是查询失败。
DEFAULT_TIMEOUT_S: Final[float] = 10.0

#: 错误信息里保留的 stderr 片段上限（避免把整段输出搬进日志）。
MAX_EXCERPT_BYTES: Final[int] = 512

#: 固定命令：``docker ps -a --no-trunc --format {{.ID}}``
#: ``-a`` 必须保留：已退出的容器同样可能是标签的候选（短命任务）。
PS_ARGS: Final[tuple[str, ...]] = ("ps", "-a", "--no-trunc", "--format", "{{.ID}}")

#: 固定命令：``docker inspect <id>``
INSPECT_ARGS: Final[tuple[str, ...]] = ("inspect",)


@dataclass(frozen=True, slots=True)
class RunnerResult:
    """一次命令执行的结果。

    ``returncode is None`` 表示命令**没有产生退出码**（超时被终止、无法启动），
    这是失败而不是"空结果"。
    """

    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str = ""


class DockerRunner(Protocol):
    """命令执行端口。返回值可以是 :class:`RunnerResult`，也可以是三元组。"""

    def __call__(self, argv: Sequence[str]) -> RunnerResult | tuple[Any, Any, Any]:
        ...


class SubprocessRunner:
    """默认 runner：用 :mod:`subprocess` 执行命令，超时抛 :class:`ContainerTimeoutError`。

    只做只读命令的执行；不写文件、不派发 shell（``argv`` 直接传给 ``Popen``，
    不经过 shell，因此不存在引号/注入问题）。
    """

    __slots__ = ("_timeout_s",)

    def __init__(self, *, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
            raise ContainerValidationError(
                f"timeout_s 必须是数字，实际为 {type(timeout_s).__name__}"
            )
        if timeout_s <= 0:
            raise ContainerValidationError(f"timeout_s 必须为正数，实际为 {timeout_s}")
        self._timeout_s = float(timeout_s)

    @property
    def timeout_s(self) -> float:
        return self._timeout_s

    def __call__(self, argv: Sequence[str]) -> RunnerResult:
        command = tuple(str(part) for part in argv)
        if not command:
            raise ContainerQueryError("runner 收到空 argv")
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                timeout=self._timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ContainerTimeoutError(
                f"命令超时（{self._timeout_s}s）：{command[0]}（已终止，不视为空结果）"
            ) from exc
        except OSError as exc:
            raise ContainerQueryError(
                f"命令无法启动：{command!r}（{exc}）"
            ) from exc
        return RunnerResult(
            argv=command,
            returncode=completed.returncode,
            stdout=completed.stdout.decode("utf-8", errors="replace"),
            stderr=completed.stderr.decode("utf-8", errors="replace"),
        )


@runtime_checkable
class ContainerQuery(Protocol):
    """容器查询端口（``list_container_ids`` / ``inspect``）。

    ``inspect`` 的返回值语义是"等价于 ``docker inspect <id>`` 的 JSON 对象"：
    既可以被 :func:`agent_probe.container.parse_inspect` 解析，
    也可以携带可选扩展键（``CgroupID``/``CgroupPath``）。
    """

    def list_container_ids(self) -> tuple[str, ...]:
        """返回全部容器 ID（含已退出）。顺序不限，但必须完整。"""

        ...

    def inspect(self, container_id: str) -> Mapping[str, Any]:
        """返回单个容器的 inspect JSON 对象；失败必须抛异常而不是返回空对象。"""

        ...


def _normalize_runner_result(raw: Any, argv: Sequence[str]) -> RunnerResult:
    """把 runner 的返回值统一成 :class:`RunnerResult`。"""

    if isinstance(raw, RunnerResult):
        return raw
    if isinstance(raw, tuple) and len(raw) == 3:
        returncode, stdout, stderr = raw
        if returncode is not None and not isinstance(returncode, int):
            raise ContainerQueryError(
                "runner 返回值的第一项必须是退出码（int）或 None，实际为 "
                f"{type(returncode).__name__}"
            )
        return RunnerResult(
            argv=tuple(str(part) for part in argv),
            returncode=returncode,
            stdout=stdout if isinstance(stdout, str) else str(stdout),
            stderr=stderr if isinstance(stderr, str) else str(stderr),
        )
    raise ContainerQueryError(
        "runner 必须返回 RunnerResult 或 (returncode, stdout, stderr) 三元组，"
        f"实际为 {type(raw).__name__}"
    )


def _excerpt(text: str) -> str:
    """截断诊断文本（按 UTF-8 字节），避免把长输出搬进错误信息。"""

    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_EXCERPT_BYTES:
        return text
    return encoded[:MAX_EXCERPT_BYTES].decode("utf-8", errors="ignore") + "…"


class DockerCli:
    """:class:`ContainerQuery` 的真实实现：委托 ``docker ps`` / ``docker inspect``。

    参数：

    * ``query``：可选的上游查询实现。给出时本对象只做**委托**（不再执行 docker），
      用于把别的后端（cri/containerd/mock）包装成同一个接口；与 ``runner``
      互斥。
    * ``runner``：命令执行器，默认 :class:`SubprocessRunner`。测试注入 fake
      即完全不执行 docker。
    * ``docker_binary``：可执行文件名或绝对路径（默认 ``docker``）。
    * ``timeout_s``：单次命令超时（默认 10s）。
    * ``cgroup_reader``：显式的 cgroup 增强端口；``None``（默认）表示**不增强**，
      此时 ``inspect()`` 的输出等价于 ``docker inspect``。

    返回的 inspect 映射在校验通过后原样返回（可能追加 cgroup 扩展键）；
    校验包括：JSON 可解析 → 数组长度为 1（或直接是对象）→ 必需字段齐备 →
    返回的容器 ID 与请求一致（短 ID 前缀匹配）。
    """

    __slots__ = ("_query", "_runner", "_docker_binary", "_timeout_s", "_cgroup_reader")

    def __init__(
        self,
        query: ContainerQuery | None = None,
        *,
        runner: DockerRunner | None = None,
        docker_binary: str = DEFAULT_DOCKER_BINARY,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        cgroup_reader: CgroupReader | None = None,
    ) -> None:
        if query is not None and runner is not None:
            raise ContainerValidationError(
                "DockerCli：query（委托）与 runner（执行 docker）互斥，不能同时给出"
            )
        if query is not None:
            for method in ("list_container_ids", "inspect"):
                if not callable(getattr(query, method, None)):
                    raise ContainerValidationError(
                        f"DockerCli：上游查询对象 {type(query).__name__} 未实现 {method}()"
                    )
        if not isinstance(docker_binary, str) or not docker_binary:
            raise ContainerValidationError("docker_binary 必须是非空字符串")
        if "\x00" in docker_binary:
            raise ContainerValidationError("docker_binary 不能包含 NUL 字节")
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
            raise ContainerValidationError("timeout_s 必须是数字")
        if timeout_s <= 0:
            raise ContainerValidationError(f"timeout_s 必须为正数，实际为 {timeout_s}")

        self._query = query
        self._docker_binary = docker_binary
        self._timeout_s = float(timeout_s)
        self._cgroup_reader = cgroup_reader
        self._runner: DockerRunner = (
            runner if runner is not None else SubprocessRunner(timeout_s=self._timeout_s)
        )

    # -- 属性 --------------------------------------------------------------- #

    @property
    def docker_binary(self) -> str:
        return self._docker_binary

    @property
    def timeout_s(self) -> float:
        return self._timeout_s

    @property
    def cgroup_reader(self) -> CgroupReader | None:
        return self._cgroup_reader

    @property
    def runner(self) -> DockerRunner:
        return self._runner

    # -- ContainerQuery ------------------------------------------------------ #

    def list_container_ids(self) -> tuple[str, ...]:
        """``docker ps -a --no-trunc --format {{.ID}}`` → 容器 ID 元组（保序去重）。

        包含**已退出**的容器：短命任务在映射时可能只以"已退出"的形态可见，
        丢掉它们就等于丢真值。
        """

        if self._query is not None:
            return self._query.list_container_ids()

        argv = (self._docker_binary, *PS_ARGS)
        result = self._run_ok(argv)
        ids: list[str] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            text = line.strip()
            if not text:
                continue
            try:
                container_id = validate_container_id(text, field="docker ps 输出的容器 ID")
            except ContainerValidationError as exc:
                raise ContainerQueryError(
                    f"docker ps 输出中出现非法容器 ID {text!r}：{exc}"
                ) from exc
            if container_id in seen:
                continue
            seen.add(container_id)
            ids.append(container_id)
        return tuple(ids)

    def inspect(self, container_id: str) -> Mapping[str, Any]:
        """``docker inspect <id>`` → 单个容器对象（校验通过后原样返回）。"""

        requested = validate_container_id(container_id)
        if self._query is not None:
            data = self._query.inspect(requested)
            if not isinstance(data, Mapping):
                raise ContainerQueryError(
                    f"上游查询返回的 inspect 不是对象：{type(data).__name__}"
                )
            return data

        argv = (self._docker_binary, *INSPECT_ARGS, requested)
        result = self._run_ok(argv)
        payload = self._parse_json(result.stdout, requested)
        data = self._single_container(payload, requested)
        enriched = self._enrich_cgroup(data)
        try:
            info = ContainerInfo.from_inspect(enriched)
        except ContainerValidationError as exc:
            raise ContainerQueryError(
                f"docker inspect {requested} 的 JSON 不满足容器契约：{exc}"
            ) from exc
        self._check_identity(requested, info.container_id)
        return enriched

    # -- 内部 --------------------------------------------------------------- #

    def _run(self, argv: Sequence[str]) -> RunnerResult:
        raw = self._runner(argv)
        return _normalize_runner_result(raw, argv)

    def _check(self, result: RunnerResult, argv: Sequence[str]) -> None:
        if result.returncode is None:
            detail = _excerpt(result.stderr.strip()) or "命令未返回退出码"
            raise ContainerQueryError(
                f"命令未产生退出码（超时或无法启动）：{' '.join(argv)}：{detail}"
            )
        if result.returncode != 0:
            detail = _excerpt(result.stderr.strip()) or _excerpt(result.stdout.strip())
            raise ContainerQueryError(
                f"命令失败（退出码 {result.returncode}）：{' '.join(argv)}"
                + (f"：{detail}" if detail else "")
            )

    def _run_ok(self, argv: Sequence[str]) -> RunnerResult:
        result = self._run(argv)
        self._check(result, argv)
        return result

    def _parse_json(self, stdout: str, container_id: str) -> Any:
        text = stdout.strip()
        if not text:
            raise ContainerQueryError(
                f"docker inspect {container_id} 的 stdout 为空，不是 JSON"
            )
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ContainerQueryError(
                f"docker inspect {container_id} 的 stdout 不是合法 JSON：{exc}"
            ) from exc

    def _single_container(self, payload: Any, container_id: str) -> Mapping[str, Any]:
        if isinstance(payload, Mapping):
            return payload
        if isinstance(payload, list):
            if not payload:
                raise ContainerNotFoundError(
                    f"docker inspect {container_id} 没有返回任何容器（空数组）"
                )
            if len(payload) != 1:
                raise ContainerQueryError(
                    f"docker inspect {container_id} 返回了 {len(payload)} 个对象，期望 1 个"
                )
            item = payload[0]
            if not isinstance(item, Mapping):
                raise ContainerQueryError(
                    f"docker inspect {container_id} 的元素不是对象：{type(item).__name__}"
                )
            return item
        raise ContainerQueryError(
            f"docker inspect {container_id} 的 JSON 既不是对象也不是数组，"
            f"实际为 {type(payload).__name__}"
        )

    def _enrich_cgroup(self, data: Mapping[str, Any]) -> Mapping[str, Any]:
        """显式注入 cgroup reader 时，把真值追加为扩展键（读不到就不加）。"""

        if self._cgroup_reader is None:
            return data
        raw_state = data.get("State")
        if not isinstance(raw_state, Mapping):
            return data
        raw_pid = raw_state.get("Pid")
        if isinstance(raw_pid, bool) or not isinstance(raw_pid, int) or raw_pid <= 0:
            return data

        record = self._cgroup_reader.read(raw_pid)
        if not isinstance(record, CgroupRecord):
            raise ContainerValidationError(
                f"cgroup reader 必须返回 CgroupRecord，实际为 {type(record).__name__}"
            )
        cgroup_path = record.cgroup_path
        cgroup_id = record.cgroup_id
        note = record.note
        if cgroup_path is None and cgroup_id is None and note is None:
            return data

        enriched = dict(data)
        if cgroup_path is not None:
            enriched[CGROUP_PATH_KEY] = cgroup_path
        if cgroup_id is not None:
            enriched[CGROUP_ID_KEY] = cgroup_id
        if note is not None:
            enriched[CGROUP_NOTE_KEY] = note
        return enriched

    def _check_identity(self, requested: str, returned: str) -> None:
        if returned == requested:
            return
        if len(requested) < 64 and returned.startswith(requested):
            return
        raise ContainerQueryError(
            f"docker inspect 返回的容器 ID {returned} 与请求的 {requested} 不一致"
            "（可能查错了容器，拒绝使用）"
        )
