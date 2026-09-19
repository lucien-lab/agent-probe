"""M4 审计层的异常边界。"""

from __future__ import annotations

__all__ = ["AuditError", "AuditInputError", "RuleSchemaError", "RuleLoadError"]


class AuditError(Exception):
    """审计层基类。"""


class AuditInputError(AuditError, ValueError):
    """输入事件、调用或关联结果不满足审计前提。"""


class RuleSchemaError(AuditError, ValueError):
    """规则内容不满足版本化 schema。"""


class RuleLoadError(AuditError, ValueError):
    """规则文件无法读取或不属于支持的 YAML 子集。"""
