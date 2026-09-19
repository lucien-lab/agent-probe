"""``agent_probe.correlate`` 的异常层次。

设计原则与其他子包一致：**错误必须可区分**。

* 输入自相矛盾（重复的 ``run_id`` 任务声明、节点身份冲突）→
  :class:`CorrelationInputError`：调用方的数据有问题，静默取一个不是选项。
* 规模超限 → :class:`CorrelationLimitError`：**抛异常，不静默截断**。
* 查询不存在的 node/edge → :class:`CorrelationNotFoundError`：解释接口必须
  明确报告"查不到"，不能返回空结构冒充"没有关联"。
"""

from __future__ import annotations

__all__ = [
    "CorrelationError",
    "CorrelationInputError",
    "CorrelationLimitError",
    "CorrelationNotFoundError",
]


class CorrelationError(Exception):
    """关联引擎的所有异常基类。"""


class CorrelationInputError(CorrelationError, ValueError):
    """输入数据自相矛盾或违反契约。"""


class CorrelationLimitError(CorrelationError):
    """节点/边数量超过配置上限。

    有界性是硬约束：超限必须让调用方看到明确异常，而不是拿到被悄悄截断的
    证据图（截断会直接改变 precision/recall 分母）。
    """


class CorrelationNotFoundError(CorrelationError, KeyError):
    """``explain`` 查询的 node_id/edge_id 不在结果里。"""
