"""M5 受保护目录策略的纯 Python 决策模型。

这里是策略编译前的、可离线测试的语义层，不加载 BPF 程序、不修改
文件系统，也不把策略验证成功误报为内核策略已经安装。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Iterable

__all__ = [
    "EnforcementMode", "FileOperation", "LsmHook", "RefusalReason",
    "ProtectedDirectoryPolicy", "OperationRequest", "EnforcementDecision",
    "InstallationCapabilities", "InstallationIssue", "InstallationValidation",
    "path_is_within", "required_hooks", "validate_installation", "evaluate_operation",
]


class EnforcementMode(StrEnum):
    """策略运行语义；audit 从不阻断，enforce 才应由内核拒绝。"""

    AUDIT = "audit"
    ENFORCE = "enforce"


class FileOperation(StrEnum):
    WRITE = "write"
    CREATE = "create"
    TRUNCATE = "truncate"
    UNLINK = "unlink"
    RENAME = "rename"
    LINK = "link"


class LsmHook(StrEnum):
    FILE_PERMISSION = "file_permission"
    INODE_CREATE = "inode_create"
    INODE_SETATTR = "inode_setattr"
    INODE_UNLINK = "inode_unlink"
    INODE_RENAME = "inode_rename"
    INODE_LINK = "inode_link"


class RefusalReason(StrEnum):
    PROTECTED_DIRECTORY = "protected_directory"
    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    INSTALLATION_NOT_READY = "installation_not_ready"


def _normal_path(path: str) -> str:
    """返回不含 ``.`` / ``..`` 的绝对 POSIX 路径，拒绝含糊输入。"""
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("路径必须是非空且不含 NUL 的字符串")
    candidate = PurePosixPath(path)
    if not candidate.is_absolute():
        raise ValueError("路径必须是绝对 POSIX 路径")
    if ".." in candidate.parts:
        raise ValueError("路径不能包含 '..'；调用方须先完成内核路径解析")
    return str(candidate)


def path_is_within(path: str, directory: str) -> bool:
    """按路径段判断；这是词法检查，不能替代内核 dentry/挂载解析。"""
    normalized_path, normalized_directory = _normal_path(path), _normal_path(directory)
    return normalized_path == normalized_directory or normalized_path.startswith(normalized_directory.rstrip("/") + "/")


@dataclass(frozen=True, slots=True)
class ProtectedDirectoryPolicy:
    mode: EnforcementMode
    protected_directories: tuple[str, ...]
    operations: frozenset[FileOperation] = frozenset(FileOperation)

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", EnforcementMode(self.mode))
        directories = tuple(_normal_path(item) for item in self.protected_directories)
        if not directories:
            raise ValueError("至少需要一个受保护目录")
        if "/" in directories:
            raise ValueError("不允许把根目录作为受保护目录")
        if len(directories) != len(set(directories)):
            raise ValueError("受保护目录不能重复")
        object.__setattr__(self, "protected_directories", directories)
        object.__setattr__(self, "operations", frozenset(FileOperation(item) for item in self.operations))
        if not self.operations:
            raise ValueError("至少需要一个受支持操作")


@dataclass(frozen=True, slots=True)
class OperationRequest:
    """待判定的文件操作。rename/link 同时必须给出源和目标。"""

    operation: FileOperation
    target_path: str
    source_path: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", FileOperation(self.operation))
        object.__setattr__(self, "target_path", _normal_path(self.target_path))
        if self.operation in (FileOperation.RENAME, FileOperation.LINK):
            if self.source_path is None:
                raise ValueError(f"{self.operation} 必须提供 source_path")
        elif self.source_path is not None:
            raise ValueError(f"{self.operation} 不能提供 source_path")
        if self.source_path is not None:
            object.__setattr__(self, "source_path", _normal_path(self.source_path))


@dataclass(frozen=True, slots=True)
class EnforcementDecision:
    allowed: bool
    would_deny: bool
    reason: RefusalReason | None
    protected_paths: tuple[str, ...]
    mode: EnforcementMode
    detail: str


def _paths_affected(request: OperationRequest) -> tuple[str, ...]:
    # rename/link 影响源和目标；两端都须保护，避免跨目录替换及硬链接绕过。
    return (request.target_path,) if request.source_path is None else (request.source_path, request.target_path)


def evaluate_operation(policy: ProtectedDirectoryPolicy, request: OperationRequest) -> EnforcementDecision:
    """离线判定一次请求，不触碰文件系统或安装任何内核对象。"""
    if request.operation not in policy.operations:
        return EnforcementDecision(True, False, RefusalReason.UNSUPPORTED_OPERATION, (), policy.mode,
            "该操作不在策略支持矩阵中；不会声称受到保护")
    protected = tuple(path for path in _paths_affected(request)
                      if any(path_is_within(path, directory) for directory in policy.protected_directories))
    if not protected:
        return EnforcementDecision(True, False, None, (), policy.mode, "操作不涉及受保护目录")
    if policy.mode is EnforcementMode.AUDIT:
        return EnforcementDecision(True, True, RefusalReason.PROTECTED_DIRECTORY, protected, policy.mode,
            "audit 模式仅记录本应拒绝的操作；调用仍被放行")
    return EnforcementDecision(False, True, RefusalReason.PROTECTED_DIRECTORY, protected, policy.mode,
        "enforce 模式应由已验证的内核 LSM 策略拒绝该操作")


def required_hooks(operations: Iterable[FileOperation]) -> frozenset[LsmHook]:
    mapping = {
        FileOperation.WRITE: LsmHook.FILE_PERMISSION,
        FileOperation.CREATE: LsmHook.INODE_CREATE,
        FileOperation.TRUNCATE: LsmHook.INODE_SETATTR,
        FileOperation.UNLINK: LsmHook.INODE_UNLINK,
        FileOperation.RENAME: LsmHook.INODE_RENAME,
        FileOperation.LINK: LsmHook.INODE_LINK,
    }
    return frozenset(mapping[FileOperation(item)] for item in operations)


@dataclass(frozen=True, slots=True)
class InstallationCapabilities:
    """由独立的内核能力探针提供的事实；本模块不会自行探测系统。"""

    bpf_lsm_enabled: bool
    available_hooks: frozenset[LsmHook]

    def __post_init__(self) -> None:
        object.__setattr__(self, "available_hooks", frozenset(LsmHook(item) for item in self.available_hooks))


@dataclass(frozen=True, slots=True)
class InstallationIssue:
    code: RefusalReason
    detail: str
    missing_hooks: tuple[LsmHook, ...] = ()


@dataclass(frozen=True, slots=True)
class InstallationValidation:
    ready: bool
    required_hooks: frozenset[LsmHook]
    issues: tuple[InstallationIssue, ...]


def validate_installation(policy: ProtectedDirectoryPolicy, capabilities: InstallationCapabilities) -> InstallationValidation:
    """在 agent 启动前验证 enforce 所需能力，返回结构化而非静默降级的结果。"""
    required = required_hooks(policy.operations)
    if policy.mode is EnforcementMode.AUDIT:
        return InstallationValidation(True, required, ())
    if not capabilities.bpf_lsm_enabled:
        return InstallationValidation(False, required, (InstallationIssue(
            RefusalReason.INSTALLATION_NOT_READY, "内核未启用 BPF LSM；不得以 audit 替代 enforce", tuple(sorted(required))),
        ))
    missing = tuple(sorted(required - capabilities.available_hooks))
    if missing:
        return InstallationValidation(False, required, (InstallationIssue(
            RefusalReason.INSTALLATION_NOT_READY, "目标内核缺少策略所需 LSM hook", missing),
        ))
    return InstallationValidation(True, required, ())
