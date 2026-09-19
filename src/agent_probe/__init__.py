"""agent-probe：为 Coding Agent 提供系统审计、行为关联与受限执行控制。

当前处于 M0 早期：本包提供可安装的包结构、CLI 入口（``--version`` / ``doctor``）
与 :mod:`agent_probe.doctor` 的只读环境能力检测。
尚未包含 eBPF 采集、协议重建、事件账本、关联引擎或执行控制实现。
完整规划见仓库根目录的 ``plan.md``，环境与验收边界见 ``docs/00-env.md``。
"""

from __future__ import annotations

# 版本单一来源：pyproject.toml 通过 [tool.setuptools.dynamic] 读取该属性。
__version__ = "0.0.1.dev0"

__all__ = ["__version__"]
