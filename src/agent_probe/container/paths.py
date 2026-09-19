"""容器/宿主路径的词法规范化与目录边界匹配（纯计算）。

容器挂载视图是**两个命名空间之间的路径前缀映射**，因此这里只做纯词法处理：

* 只接受 POSIX 绝对路径。相对路径在不知道工作目录的情况下无法映射，
  一律返回原因，**不猜测**。
* 折叠重复 ``/``、丢弃 ``.`` 分量、去掉结尾 ``/``（根 ``/`` 除外）。
* 出现 ``..`` 分量直接拒绝：词法上的 ``..`` 在符号链接下可能指向完全不同的
  位置，不访问文件系统就无法判定，宁可返回 ``None`` 也不给错答案。
* 前缀匹配按**目录边界**：``/data`` 匹配 ``/data`` 与 ``/data/x``，
  但**不**匹配 ``/database``。

本模块不访问文件系统、不做 realpath、不解符号链接、不做大小写折叠。
"""

from __future__ import annotations

from typing import Final

from .errors import ContainerValidationError

__all__ = [
    "MAX_PATH_BYTES",
    "is_clean_absolute_path",
    "normalize_path",
    "relative_to",
    "join_path",
]

#: 路径字段的 UTF-8 字节上限（与 Linux ``PATH_MAX`` 及事件模型保持一致）。
MAX_PATH_BYTES: Final[int] = 4096


def is_clean_absolute_path(path: object) -> bool:
    """判断 ``path`` 是否已经是**规范化绝对路径**。

    规范化含义：以 ``/`` 开头、不含 NUL、无重复 ``/``、无 ``.``/``..`` 分量、
    除根以外不以 ``/`` 结尾。挂载项（``source``/``destination``）要求已是
    这种形式，避免同一挂载出现多种字符串写法。
    """

    if not isinstance(path, str) or not path or "\x00" in path:
        return False
    if not path.startswith("/"):
        return False
    if path == "/":
        return True
    if path.endswith("/") or "//" in path:
        return False
    for segment in path.split("/")[1:]:
        if segment in ("", ".", ".."):
            return False
    return True


def normalize_path(path: object, *, what: str) -> tuple[str | None, str | None]:
    """规范化**查询**路径；返回 ``(规范化路径, 失败原因)``。

    失败时路径为 ``None`` 且给出人可读原因（调用方负责把原因写进 evidence）。
    允许的"脏"输入：重复斜杠、结尾斜杠、``.`` 分量。
    不允许：非字符串、空串、NUL、相对路径、``..`` 分量、超过字节上限。
    """

    if not isinstance(path, str):
        return None, f"{what} 必须是字符串，实际为 {type(path).__name__}"
    if not path:
        return None, f"{what} 是空字符串，无法解析"
    if "\x00" in path:
        return None, f"{what} 含 NUL 字节，无法解析"
    if len(path.encode("utf-8")) > MAX_PATH_BYTES:
        return None, f"{what} 超过 {MAX_PATH_BYTES} 字节上限"
    if not path.startswith("/"):
        return None, f"{what} 是相对路径（{path!r}）：不知道容器/宿主工作目录，无法映射"
    segments = [segment for segment in path.split("/") if segment not in ("", ".")]
    if ".." in segments:
        return None, f"{what} 含 '..' 分量（{path!r}）：词法解析在符号链接下不可靠，拒绝猜测"
    normalized = "/" + "/".join(segments) if segments else "/"
    if len(normalized.encode("utf-8")) > MAX_PATH_BYTES:
        return None, f"{what} 规范化后超过 {MAX_PATH_BYTES} 字节上限"
    return normalized, None


def relative_to(child: str, parent: str) -> str | None:
    """若 ``child`` 位于 ``parent`` 之下（按**目录边界**），返回相对部分。

    ``child == parent`` 时返回空串；否则返回不含前导 ``/`` 的相对路径。
    不在其下（或仅共享字符串前缀，如 ``/data`` vs ``/database``）返回 ``None``。

    两个参数都必须是 :func:`is_clean_absolute_path` 认可的规范化路径。
    """

    if not is_clean_absolute_path(child) or not is_clean_absolute_path(parent):
        raise ContainerValidationError(
            f"relative_to 只接受规范化绝对路径：child={child!r} parent={parent!r}"
        )
    if parent == "/":
        return "" if child == "/" else child[1:]
    if child == parent:
        return ""
    prefix = parent + "/"
    if child.startswith(prefix):
        return child[len(prefix) :]
    return None


def join_path(parent: str, relative: str) -> str:
    """把规范化绝对路径 ``parent`` 与相对部分 ``relative`` 拼成绝对路径。"""

    if not relative:
        return parent
    if parent == "/":
        return "/" + relative
    return parent + "/" + relative
