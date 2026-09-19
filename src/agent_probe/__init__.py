"""agent-probe：为 Coding Agent 提供系统审计、行为关联与受限执行控制。

当前处于**工程骨架阶段**：本包只提供可安装的包结构与 CLI 入口，
不包含 eBPF 采集、协议重建、事件账本、关联引擎或执行控制实现。
完整规划见仓库根目录的 ``plan.md``。
"""

from __future__ import annotations

# 版本单一来源：pyproject.toml 通过 [tool.setuptools.dynamic] 读取该属性。
__version__ = "0.0.1.dev0"

__all__ = ["__version__"]
