"""容器任务映射的异常层次。

分层原则：

* :class:`ContainerValidationError` —— **数据/契约**问题：容器 ID 形状非法、
  inspect 缺字段、挂载项不可解析、映射结果自相矛盾。调用方必须修数据，
  本层不替它猜。
* :class:`ContainerQueryError` —— **查询**问题：命令非零退出、进程无法启动、
  超时、stdout 不是 JSON、inspect 返回的不是单个容器对象。
  查询失败一律显式上报（或产出 ``outcome=error`` 的映射），**绝不静默成功**。
* :class:`ContainerNotFoundError` / :class:`ContainerTimeoutError` —— 上述两类
  常见原因的具名子类，便于调用方区分"确实不存在"与"查询本身失败"。

所有异常都继承 :class:`ContainerError`，便于调用方一次性捕获。
"""

from __future__ import annotations

__all__ = [
    "ContainerError",
    "ContainerValidationError",
    "ContainerQueryError",
    "ContainerTimeoutError",
    "ContainerNotFoundError",
]


class ContainerError(Exception):
    """容器任务映射相关错误的公共基类。"""


class ContainerValidationError(ContainerError, ValueError):
    """容器/挂载/映射数据不满足契约：ID 形状、字段类型、跨字段一致性。"""


class ContainerQueryError(ContainerError, RuntimeError):
    """容器查询失败：非零退出、无法启动、stdout 不是 JSON、inspect 结构不符。"""


class ContainerTimeoutError(ContainerQueryError):
    """docker 查询超时：命令被终止或未在期限内返回（不得当作"无结果"）。"""


class ContainerNotFoundError(ContainerQueryError):
    """``docker inspect`` 明确没有返回该容器（空数组）。

    这是"容器确实不存在"，与"查询失败"是两件事，因此单独成类；
    它仍然是 :class:`ContainerQueryError`，映射层会记录到 ``reason``。
    """
