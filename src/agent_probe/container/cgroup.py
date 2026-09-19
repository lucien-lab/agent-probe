"""可注入的 cgroup 标识读取端口（宿主 PID → cgroup 路径 / cgroup id）。

**为什么单独一层**

标准 ``docker inspect`` **不提供** cgroup 标识，只给 ``State.Pid``。
把"容器"与"事件里的 cgroup_id"对上，唯一可靠的真值是宿主上的
``/proc/<pid>/cgroup``（cgroup 路径）与 ``cgroupfs`` 目录的 ``st_ino``
（即内核用于 ``bpf_get_current_cgroup_id()`` 的 cgroup id）。

因此本模块把它做成一个**可注入端口**：

* 真实实现 :class:`ProcCgroupReader` 只读 ``/proc/<pid>/cgroup`` 并 ``stat``
  cgroup 目录，绝不写、绝不猜；
* 测试用内存 fake（或 :class:`NullCgroupReader`）即可覆盖全部分支，
  不需要 root、不需要 Linux、不需要 docker；
* 读取失败**不抛异常**，而是返回带 ``note`` 的记录：缺失就是缺失
  （``None``），说明会流入映射证据，而不是被静默吞掉。

**真值边界**：``/proc/<pid>/cgroup`` 里的路径是**该进程所在 cgroup**，
容器内进程可能被移动到更深层的子 cgroup；本模块只报告容器主进程的位置。
cgroup id 是 kernfs inode，**只在同一挂载的 cgroupfs 内**可比较，
跨宿主/跨 boot 不保证稳定。
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

__all__ = [
    "DEFAULT_PROC_ROOT",
    "DEFAULT_CGROUP_ROOT",
    "MAX_CGROUP_LINES",
    "CgroupRecord",
    "CgroupReader",
    "NullCgroupReader",
    "ProcCgroupReader",
]

#: ``/proc`` 挂载点（可注入，便于测试用 tmp_path 构造内存视图）。
DEFAULT_PROC_ROOT: Final[str] = "/proc"

#: cgroupfs 挂载点（cgroup v2 统一层级）。
DEFAULT_CGROUP_ROOT: Final[str] = "/sys/fs/cgroup"

#: ``/proc/<pid>/cgroup`` 的行数上限（每行一个层级；防御异常大文件）。
MAX_CGROUP_LINES: Final[int] = 64


@dataclass(frozen=True, slots=True)
class CgroupRecord:
    """一次 cgroup 读取的结果。

    * ``pid``：被查询的宿主 PID。
    * ``cgroup_path``：cgroupfs 上的**绝对路径**（已拼上挂载点）。未知为 ``None``。
    * ``cgroup_id``：cgroup 目录的 kernfs inode。未知为 ``None``；
      **不会**用 0 或 PID 之类的近似值填充。
    * ``note``：读取过程中的说明（失败原因、v1/v2 层级选择等），
      会进入映射 evidence。``None`` 表示没有需要说明的事。
    """

    pid: int
    cgroup_path: str | None = None
    cgroup_id: int | None = None
    note: str | None = None


class CgroupReader(Protocol):
    """宿主 PID → cgroup 标识的读取端口。

    实现**不得抛异常**：读不到就返回字段为 ``None`` 的 :class:`CgroupRecord`，
    并在 ``note`` 里说明原因。
    """

    def read(self, pid: int) -> CgroupRecord:
        ...


class NullCgroupReader:
    """:class:`CgroupReader` 的空实现：明确表示"不读 cgroup"。

    用于：非 Linux 宿主、只读环境、测试里要断言"没有 cgroup 增强"的场景。
    它返回的 ``note`` 会让下游证据显示"cgroup 未采集"，而不是"cgroup 不存在"。
    """

    __slots__ = ()

    def read(self, pid: int) -> CgroupRecord:
        return CgroupRecord(
            pid=pid,
            note="cgroup 读取未启用（NullCgroupReader）：cgroup_id/cgroup_path 为 null",
        )


class ProcCgroupReader:
    """读取 ``/proc/<pid>/cgroup`` 与 cgroupfs inode 的真实实现（只读）。

    * ``proc_root`` / ``cgroup_root`` 可注入，测试用 ``tmp_path`` 构造内存视图；
    * cgroup v2：取 ``0::<path>`` 行（统一层级）；
    * cgroup v1：按 ``name=systemd`` → ``pids`` → 首个非空路径的顺序选择，
      并在 ``note`` 里说明选中的层级，避免把 v1 的某个子系统路径当成唯一真值；
    * 路径为 ``/`` 表示进程位于根 cgroup（合法结果，照实报告）；
    * 读文件或 ``stat`` 失败时给 ``None`` 并附 ``note``，不抛异常、不填 0。

    **不读容器内 PID 命名空间**：``pid`` 必须是宿主命名空间的 PID，
    否则会读到别处（甚至读不到）。
    """

    __slots__ = ("_proc_root", "_cgroup_root")

    def __init__(
        self,
        *,
        proc_root: str | os.PathLike[str] = DEFAULT_PROC_ROOT,
        cgroup_root: str | os.PathLike[str] = DEFAULT_CGROUP_ROOT,
    ) -> None:
        self._proc_root = Path(proc_root)
        self._cgroup_root = Path(cgroup_root)

    @property
    def proc_root(self) -> Path:
        return self._proc_root

    @property
    def cgroup_root(self) -> Path:
        return self._cgroup_root

    def read(self, pid: int) -> CgroupRecord:
        path, note = self._read_path(pid)
        if path is None:
            return CgroupRecord(pid=pid, note=note)
        absolute = self._join(path)
        try:
            inode = os.stat(absolute).st_ino
        except OSError as exc:
            return CgroupRecord(
                pid=pid,
                cgroup_path=absolute,
                note=f"cgroup 目录 {absolute} 无法 stat（{exc.strerror or exc}）："
                "cgroup_id=null",
            )
        if inode <= 0:
            return CgroupRecord(
                pid=pid,
                cgroup_path=absolute,
                note=f"cgroup 目录 {absolute} 的 inode 为 {inode}（非正数）：cgroup_id=null",
            )
        return CgroupRecord(pid=pid, cgroup_path=absolute, cgroup_id=inode, note=note)

    # -- 内部 --------------------------------------------------------------- #

    def _read_path(self, pid: int) -> tuple[str | None, str | None]:
        target = self._proc_root / str(pid) / "cgroup"
        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return None, f"无法读取 {target}（{exc.strerror or exc}）：cgroup 标识为 null"
        lines: Sequence[str] = text.splitlines()[:MAX_CGROUP_LINES]
        parsed: list[tuple[str, str]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parts = line.split(":", 2)
            if len(parts) != 3:
                continue
            controllers, path = parts[1], parts[2]
            parsed.append((controllers, path))
        if not parsed:
            return None, f"{target} 没有可解析的层级行：cgroup 标识为 null"

        for controllers, path in parsed:
            if controllers == "":  # cgroup v2：0::<path>
                return path, "cgroup v2 统一层级"
        for wanted, label in (("name=systemd", "name=systemd"), ("pids", "pids")):
            for controllers, path in parsed:
                if wanted in controllers.split(","):
                    return path, f"cgroup v1 层级 {label}（v1 无统一层级，按控制器选择）"
        controllers, path = parsed[0]
        return path, f"cgroup v1 层级 {controllers!r}（按行序取首行，v1 无统一层级）"

    def _join(self, path: str) -> str:
        if not path.startswith("/"):
            # 规范上不会出现；照实反映，交给下面拼接逻辑（不猜测）。
            path = "/" + path
        if path == "/":
            return str(self._cgroup_root)
        return str(self._cgroup_root) + path
