"""挂载视图：容器内路径 ↔ 宿主路径的双向解析（纯词法，不访问文件系统）。

**规则**

* 只按 :class:`~agent_probe.container.model.ContainerMount` 的
  ``destination``（容器内）与 ``source``（宿主）做**目录边界**前缀匹配：
  ``/data`` 匹配 ``/data`` 与 ``/data/x``，不匹配 ``/database``；多个匹配时
  **最长 destination/source 优先**（更深的挂载覆盖更浅的）。
* tmpfs 位于内存，没有宿主路径；``other`` 类型（npipe/cluster…）语义未知，
  两者都**不做宿主路径映射**，返回 ``None`` 并在 evidence 里说明原因。
* 同一路径被两个挂载以相同长度匹配（例如两个挂载项 destination 相同）时，
  无法唯一确定，返回 ``None`` 并说明；**不**按顺序取第一个。
* 查询路径会做纯词法规范化（重复斜杠、结尾斜杠、``.``），但相对路径与含
  ``..`` 的路径一律拒绝——不访问文件系统就无法判定 ``..`` 的真实指向。
* 解析结果和原因都**不猜测、不默认**：映射不到就是 ``None``。

**真值边界**

* 纯词法映射：不解析符号链接，也不检查宿主路径是否真的存在/可读。
  容器内是另一套挂载命名空间，本模块只在"挂载前缀"这一层做映射。
* 卷（volume）的 ``source`` 是 daemon 侧的 ``_data`` 目录，
  映射到它是**宿主文件系统视图**，不等于容器内路径的 inode。
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from .errors import ContainerValidationError
from .model import ContainerMount, MountType, validate_container_id
from .paths import join_path, normalize_path, relative_to

__all__ = [
    "MAX_RESOLVER_EVIDENCE",
    "MountResolver",
]

#: 单个 resolver 累积的 evidence 上限（超出后只记录截断提示）。
MAX_RESOLVER_EVIDENCE: Final[int] = 64

#: 可映射到宿主路径的挂载类型：bind 直接是宿主目录，volume 是 daemon 侧目录。
_HOST_PATH_MOUNT_TYPES: Final[frozenset[MountType]] = frozenset(
    {MountType.BIND, MountType.VOLUME}
)


class MountResolver:
    """一组挂载项构成的双向路径解析器。

    典型获取方式：``ContainerTaskMapper.resolver_for(mapping)``（只在
    ``outcome=MAPPED`` 时可用）。也可以直接用一组 :class:`ContainerMount` 构造。

    ``evidence`` 累积解析过程中的说明（命中哪个挂载、为什么映射不到），
    供报告引用；超过 :data:`MAX_RESOLVER_EVIDENCE` 条后只保留一条截断提示。
    """

    __slots__ = ("_mounts", "_container_id", "_evidence", "_dropped")

    def __init__(
        self,
        mounts: Sequence[ContainerMount],
        *,
        container_id: str | None = None,
    ) -> None:
        if isinstance(mounts, (str, bytes)) or not isinstance(mounts, Sequence):
            raise ContainerValidationError(
                f"MountResolver：mounts 必须是序列，实际为 {type(mounts).__name__}"
            )
        checked: list[ContainerMount] = []
        for index, mount in enumerate(mounts):
            if not isinstance(mount, ContainerMount):
                raise ContainerValidationError(
                    f"MountResolver：mounts[{index}] 必须是 ContainerMount，"
                    f"实际为 {type(mount).__name__}"
                )
            checked.append(mount)
        if container_id is not None:
            container_id = validate_container_id(container_id)
        self._mounts = tuple(checked)
        self._container_id = container_id
        self._evidence: list[str] = []
        self._dropped = 0

    # -- 属性 --------------------------------------------------------------- #

    @property
    def mounts(self) -> tuple[ContainerMount, ...]:
        return self._mounts

    @property
    def container_id(self) -> str | None:
        return self._container_id

    @property
    def evidence(self) -> tuple[str, ...]:
        if self._dropped:
            return tuple(self._evidence) + (
                f"evidence 已截断：另有 {self._dropped} 条解析说明未列出"
                f"（上限 {MAX_RESOLVER_EVIDENCE}）",
            )
        return tuple(self._evidence)

    def _note(self, text: str) -> None:
        if len(self._evidence) < MAX_RESOLVER_EVIDENCE:
            self._evidence.append(text)
        else:
            self._dropped += 1

    # -- 解析 --------------------------------------------------------------- #

    def container_to_host(self, container_path: str) -> str | None:
        """容器内路径 → 宿主路径；无法映射返回 ``None``（原因写入 evidence）。"""

        normalized, reason = normalize_path(container_path, what=f"容器内路径 {container_path!r}")
        if normalized is None:
            self._note(f"无法解析：{reason}")
            return None

        best_len = -1
        winners: list[ContainerMount] = []
        for mount in self._mounts:
            relative = relative_to(normalized, mount.destination)
            if relative is None:
                continue
            length = len(mount.destination)
            if length > best_len:
                best_len = length
                winners = [mount]
            elif length == best_len:
                winners.append(mount)

        if not winners:
            self._note(
                f"容器内路径 {normalized} 不在任何挂载的 destination 之下"
                f"（共 {len(self._mounts)} 个挂载）"
            )
            return None
        if len(winners) > 1:
            destinations = ", ".join(sorted({mount.destination for mount in winners}))
            self._note(
                f"容器内路径 {normalized} 同时命中 {len(winners)} 个同级挂载"
                f"（destination: {destinations}），无法唯一确定"
            )
            return None

        mount = winners[0]
        relative = relative_to(normalized, mount.destination)
        assert relative is not None  # 由上面的匹配保证
        if mount.mount_type not in _HOST_PATH_MOUNT_TYPES:
            self._note(
                f"容器内路径 {normalized} 命中挂载 {mount.destination}"
                f"（type={mount.mount_type}，raw_type={mount.raw_type!r}）："
                "tmpfs 位于内存、other 语义未知，均无宿主路径可映射"
            )
            return None
        if mount.source is None:
            self._note(
                f"容器内路径 {normalized} 命中挂载 {mount.destination}"
                f"（type={mount.mount_type}），但该挂载没有宿主 source：无法映射"
            )
            return None
        resolved = join_path(mount.source, relative)
        self._note(
            f"容器内路径 {normalized} 命中挂载 {mount.destination} → 宿主 {resolved}"
            f"（type={mount.mount_type}，rw={mount.read_write}）"
        )
        return resolved

    def host_to_container(self, host_path: str) -> str | None:
        """宿主路径 → 容器内路径；无法映射返回 ``None``（原因写入 evidence）。"""

        normalized, reason = normalize_path(host_path, what=f"宿主路径 {host_path!r}")
        if normalized is None:
            self._note(f"无法解析：{reason}")
            return None

        best_len = -1
        winners: list[ContainerMount] = []
        for mount in self._mounts:
            if mount.mount_type not in _HOST_PATH_MOUNT_TYPES or mount.source is None:
                continue
            relative = relative_to(normalized, mount.source)
            if relative is None:
                continue
            length = len(mount.source)
            if length > best_len:
                best_len = length
                winners = [mount]
            elif length == best_len:
                winners.append(mount)

        if not winners:
            self._note(
                f"宿主路径 {normalized} 不在任何 bind/volume 挂载的 source 之下"
                f"（共 {len(self._mounts)} 个挂载）"
            )
            return None
        if len(winners) > 1:
            sources = ", ".join(sorted({str(mount.source) for mount in winners}))
            self._note(
                f"宿主路径 {normalized} 同时命中 {len(winners)} 个同级挂载"
                f"（source: {sources}），无法唯一确定"
            )
            return None

        mount = winners[0]
        relative = relative_to(normalized, str(mount.source))
        assert relative is not None
        resolved = join_path(mount.destination, relative)
        self._note(
            f"宿主路径 {normalized} 命中挂载 source {mount.source} → 容器内 {resolved}"
            f"（type={mount.mount_type}，rw={mount.read_write}）"
        )
        return resolved

    #: 语义更明确的别名（与 :meth:`container_to_host` / :meth:`host_to_container` 等价）。
    to_host = container_to_host
    to_container = host_to_container

    def to_dict(self) -> dict[str, Any]:
        """挂载视图的可序列化快照（用于报告；不含解析过程中的 evidence）。"""

        return {
            "container_id": self._container_id,
            "mounts": [mount.to_dict() for mount in self._mounts],
            "evidence": list(self.evidence),
        }
