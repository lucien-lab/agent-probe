"""M0 环境与能力检测：``probe doctor`` 的只读实现。

设计约束（对应 ``plan.md`` 的 M0 与任务边界）：

* **只读**：不创建、不修改任何文件、挂载或系统配置；执行外部命令时只允许
  :data:`ALLOWED_PROGRAMS` 中的程序，白名单之外的调用会被直接拒绝并记录。
* **结构化**：每项检查输出 ``id`` / ``status`` / ``summary`` / ``evidence``，
  整体结果可序列化为稳定的 JSON。
* **不推断**：某个线索存在（例如 BTF）**不代表**其它挂点可用。每个能力独立检查，
  并保留判断依据；凡仅凭线索得出的结论都标记为 ``warn`` 而不是 ``pass``。
* **可注入**：所有系统访问都经过 :class:`Host` 协议，测试可以构造 Linux 能力矩阵，
  不依赖运行测试的宿主平台（macOS/Linux）。
* **不抛异常**：非 Linux 主机、缺文件、命令缺失都会转换为 ``unsupported`` / ``fail``
  结果，而不是让 ``probe doctor`` 崩溃。

退出码见 :data:`EXIT_OK` / :data:`EXIT_REQUIRED_FAILED` / :data:`EXIT_REQUIRED_UNSUPPORTED`
/ :data:`EXIT_INTERNAL_ERROR`，并在 ``docs/00-env.md`` 中有完整解释。
"""

from __future__ import annotations

import gzip
import json
import os
import platform
import shutil
import ssl
import stat
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from agent_probe import __version__

__all__ = [
    "ALLOWED_PROGRAMS",
    "CHECKS",
    "EXIT_INTERNAL_ERROR",
    "EXIT_OK",
    "EXIT_REQUIRED_FAILED",
    "EXIT_REQUIRED_UNSUPPORTED",
    "SCHEMA_VERSION",
    "STATUSES",
    "CheckResult",
    "CommandResult",
    "DoctorReport",
    "Host",
    "LocalHost",
    "PathInfo",
    "PythonInfo",
    "Uname",
    "collect",
    "render_json",
    "render_text",
]

#: JSON 结构版本。字段语义变化时递增，便于下游解析器拒绝未知版本。
SCHEMA_VERSION = 1

STATUS_PASS = "pass"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_UNSUPPORTED = "unsupported"

#: 允许出现的检查状态。顺序即严重度递增（unsupported 单独处理）。
STATUSES: tuple[str, ...] = (STATUS_PASS, STATUS_WARN, STATUS_FAIL, STATUS_UNSUPPORTED)

EXIT_OK = 0
"""所有必需检查通过（必需检查为 ``warn`` 时仍算通过，但总体状态为 ``warn``）。"""

EXIT_REQUIRED_FAILED = 1
"""存在 ``fail`` 的必需检查：环境不满足，且原因可修复。"""

EXIT_REQUIRED_UNSUPPORTED = 2
"""存在 ``unsupported`` 的必需检查：当前主机不是受支持目标（例如 macOS 宿主）。"""

EXIT_INTERNAL_ERROR = 3
"""doctor 自身出错（无法生成报告）。"""

#: doctor 允许执行的外部程序白名单。这些都是只读的版本查询命令。
ALLOWED_PROGRAMS: frozenset[str] = frozenset({"clang", "bpftool", "pkg-config", "docker"})

#: M0 固定目标架构。
_TARGET_MACHINES = frozenset({"aarch64", "arm64"})

_VMLINUX_BTF = "/sys/kernel/btf/vmlinux"
_BTF_DIR = "/sys/kernel/btf"
_SECURITY_LSM = "/sys/kernel/security/lsm"
_SELF_STATUS = "/proc/self/status"
_PROC_MOUNTS = "/proc/mounts"
_UNPRIVILEGED_BPF = "/proc/sys/kernel/unprivileged_bpf_disabled"

_TRACEFS_CANDIDATES: tuple[str, ...] = ("/sys/kernel/tracing", "/sys/kernel/debug/tracing")

_FILTER_FUNCTIONS_CANDIDATES: tuple[str, ...] = tuple(
    f"{root}/available_filter_functions" for root in _TRACEFS_CANDIDATES
)

#: capability 位号（``include/uapi/linux/capability.h``）。
_CAP_SYS_ADMIN = 21
_CAP_PERFMON = 38
_CAP_BPF = 39

_FENTRY_CONFIG_KEYS: tuple[str, ...] = (
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_EVENTS",
    "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_FUNCTION_TRACER",
)

#: 在文本与 JSON 报告中都出现的边界声明，避免把 "pass" 误读为已完成验证。
LIMITATIONS_NOTE = (
    "只读检查：pass 表示所需线索/文件/工具满足，不代表已在 VM 内完成实际 attach、"
    "事件采集或 LSM 阻断验证。"
)


# --------------------------------------------------------------------------------------
# 宿主抽象：所有系统访问都经过 Host，便于测试注入与跨平台降级
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Uname:
    """内核/平台标识。"""

    system: str
    machine: str
    release: str
    node: str = ""


@dataclass(frozen=True)
class PathInfo:
    """只读路径元信息。``exists=False`` 时其余字段无意义。"""

    path: str
    exists: bool
    is_dir: bool = False
    size: int | None = None
    readable: bool = False


@dataclass(frozen=True)
class CommandResult:
    """外部命令结果。``returncode is None`` 表示命令未能启动（``error`` 说明原因）。"""

    argv: tuple[str, ...]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0


@dataclass(frozen=True)
class PythonInfo:
    """运行 doctor 的 Python 运行时信息（用于记录版本矩阵）。"""

    version: str
    version_info: tuple[int, int, int]
    implementation: str
    executable: str
    openssl_version: str | None


@runtime_checkable
class Host(Protocol):
    """doctor 需要的只读宿主能力集合。测试实现一个内存版本即可构造能力矩阵。"""

    def uname(self) -> Uname: ...

    def inspect(self, path: str) -> PathInfo: ...

    def listdir(self, path: str) -> tuple[str, ...]: ...

    def read_text(self, path: str, *, max_bytes: int = 262144) -> str | None: ...

    def read_bytes(self, path: str, *, max_bytes: int = 4194304) -> bytes | None: ...

    def which(self, name: str) -> str | None: ...

    def run(self, argv: Sequence[str], *, timeout: float = 5.0) -> CommandResult: ...

    def python_info(self) -> PythonInfo: ...

    def euid(self) -> int | None: ...


class LocalHost:
    """真实宿主实现：只做读取与白名单命令，任何失败都降级为 ``None``/错误结果。"""

    def uname(self) -> Uname:
        try:
            u = platform.uname()
        except Exception:  # pragma: no cover - 极端环境下的平台接口异常
            return Uname(system="unknown", machine="unknown", release="unknown")
        return Uname(system=u.system, machine=u.machine, release=u.release, node=u.node)

    def inspect(self, path: str) -> PathInfo:
        try:
            st = os.stat(path)
        except OSError:
            return PathInfo(path=path, exists=False)
        is_dir = stat.S_ISDIR(st.st_mode)
        size = None if is_dir else int(st.st_size)
        return PathInfo(
            path=path,
            exists=True,
            is_dir=is_dir,
            size=size,
            readable=os.access(path, os.R_OK),
        )

    def listdir(self, path: str) -> tuple[str, ...]:
        try:
            return tuple(sorted(os.listdir(path)))
        except OSError:
            return ()

    def read_text(self, path: str, *, max_bytes: int = 262144) -> str | None:
        data = self.read_bytes(path, max_bytes=max_bytes)
        if data is None:
            return None
        return data.decode("utf-8", errors="replace")

    def read_bytes(self, path: str, *, max_bytes: int = 4194304) -> bytes | None:
        try:
            with open(path, "rb") as handle:
                return handle.read(max_bytes)
        except OSError:
            return None

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def run(self, argv: Sequence[str], *, timeout: float = 5.0) -> CommandResult:
        argv_t = tuple(str(part) for part in argv)
        if not argv_t:
            return CommandResult(argv=(), returncode=None, error="空命令")
        program = Path(argv_t[0]).name
        if program not in ALLOWED_PROGRAMS:
            return CommandResult(
                argv=argv_t,
                returncode=None,
                error=f"拒绝执行非白名单命令: {program}（doctor 只允许只读查询命令）",
            )
        try:
            proc = subprocess.run(
                argv_t,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return CommandResult(argv=argv_t, returncode=None, error=f"{type(exc).__name__}: {exc}")
        return CommandResult(
            argv=argv_t,
            returncode=proc.returncode,
            stdout=proc.stdout[:4096],
            stderr=proc.stderr[:4096],
        )

    def python_info(self) -> PythonInfo:
        info = sys.version_info
        version = f"{info.major}.{info.minor}.{info.micro}"
        try:
            openssl_version: str | None = ssl.OPENSSL_VERSION
        except Exception:  # pragma: no cover - 极少见的 ssl 初始化失败
            openssl_version = None
        return PythonInfo(
            version=version,
            version_info=(info.major, info.minor, info.micro),
            implementation=platform.python_implementation(),
            executable=sys.executable or "",
            openssl_version=openssl_version,
        )

    def euid(self) -> int | None:
        getuid = getattr(os, "geteuid", None)
        if getuid is None:  # pragma: no cover - Windows 宿主
            return None
        try:
            return int(getuid())
        except OSError:  # pragma: no cover
            return None


# --------------------------------------------------------------------------------------
# 结果模型
# --------------------------------------------------------------------------------------


def _jsonify(value: Any) -> Any:
    """把 evidence 值规整成 JSON 可序列化类型，保持结构稳定。"""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(k): _jsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonify(v) for v in value]
    return str(value)


def _normalize_evidence(evidence: Mapping[str, Any] | None) -> dict[str, Any]:
    if not evidence:
        return {}
    return {str(k): _jsonify(v) for k, v in sorted(evidence.items(), key=lambda kv: str(kv[0]))}


@dataclass(frozen=True)
class CheckResult:
    """单项检查结果。``evidence`` 中的键按字典序稳定输出。"""

    id: str
    title: str
    status: str
    required: bool
    summary: str
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "required": self.required,
            "status": self.status,
            "summary": self.summary,
            "evidence": _normalize_evidence(self.evidence),
        }


@dataclass(frozen=True)
class DoctorReport:
    """``probe doctor`` 的完整结果。"""

    schema_version: int
    generated_at: str
    host: Uname
    checks: tuple[CheckResult, ...]

    @property
    def counts(self) -> dict[str, int]:
        counts = {status: 0 for status in STATUSES}
        for check in self.checks:
            counts[check.status] = counts.get(check.status, 0) + 1
        return counts

    def has(self, status: str, *, required_only: bool = False) -> bool:
        return any(
            check.status == status and (check.required or not required_only) for check in self.checks
        )

    @property
    def overall_status(self) -> str:
        if self.has(STATUS_FAIL, required_only=True):
            return STATUS_FAIL
        if self.has(STATUS_UNSUPPORTED, required_only=True):
            return STATUS_UNSUPPORTED
        if self.has(STATUS_WARN):
            return STATUS_WARN
        if self.has(STATUS_FAIL):
            # 仅非必需项失败：环境可用，但存在需要注意的缺口。
            return STATUS_WARN
        return STATUS_PASS

    @property
    def exit_code(self) -> int:
        if self.has(STATUS_FAIL, required_only=True):
            return EXIT_REQUIRED_FAILED
        if self.has(STATUS_UNSUPPORTED, required_only=True):
            return EXIT_REQUIRED_UNSUPPORTED
        return EXIT_OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": {"name": "agent-probe", "command": "probe doctor", "version": __version__},
            "generated_at": self.generated_at,
            "host": {
                "system": self.host.system,
                "machine": self.host.machine,
                "kernel_release": self.host.release,
                "node": self.host.node,
            },
            "overall": {
                "status": self.overall_status,
                "exit_code": self.exit_code,
                "counts": self.counts,
                "note": LIMITATIONS_NOTE,
            },
            "checks": [check.to_dict() for check in self.checks],
        }


# --------------------------------------------------------------------------------------
# 检查实现
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Outcome:
    status: str
    summary: str
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _CheckSpec:
    id: str
    title: str
    required: bool
    linux_only: bool
    handler: Callable[[Host], _Outcome]


def _safe_uname(host: Host) -> Uname:
    try:
        uname = host.uname()
    except Exception as exc:  # pragma: no cover - 防御性分支
        return Uname(system=f"unknown({type(exc).__name__})", machine="unknown", release="unknown")
    return Uname(
        system=str(uname.system),
        machine=str(uname.machine),
        release=str(uname.release),
        node=str(uname.node),
    )


def _is_linux(host: Host) -> bool:
    return _safe_uname(host).system == "Linux"


def _readable_size(host: Host, path: str) -> int | None:
    info = host.inspect(path)
    if not info.exists or info.is_dir or not info.readable:
        return None
    return info.size if info.size is not None else 0


def _first_readable(host: Host, paths: Iterable[str]) -> tuple[str | None, int | None]:
    for path in paths:
        size = _readable_size(host, path)
        if size is not None:
            return path, size
    return None, None


def _tracefs_root(host: Host) -> str | None:
    for root in _TRACEFS_CANDIDATES:
        if _readable_size(host, f"{root}/trace") is not None:
            return root
        if host.inspect(f"{root}/events").is_dir:
            return root
    return None


def _boot_config_paths(host: Host) -> tuple[str, ...]:
    release = _safe_uname(host).release
    return (f"/boot/config-{release}", "/proc/config.gz")


def _kernel_config(host: Host) -> tuple[dict[str, str] | None, str | None]:
    """读取内核配置。返回 ``(配置字典, 来源路径)``；读不到时为 ``(None, None)``。"""
    for path in _boot_config_paths(host):
        raw = host.read_bytes(path, max_bytes=4 * 1024 * 1024)
        if raw is None:
            continue
        if path.endswith(".gz"):
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError):
                continue
        config: dict[str, str] = {}
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("#") and line.endswith(" is not set"):
                config[line[2 : -len(" is not set")]] = "n"
            elif "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                config[key.strip()] = value.strip()
        return config, path
    return None, None


def _config_get(config: Mapping[str, str] | None, key: str) -> str | None:
    if config is None:
        return None
    return config.get(key)


def _check_platform_os(host: Host) -> _Outcome:
    uname = _safe_uname(host)
    evidence = {"system": uname.system, "release": uname.release, "machine": uname.machine}
    if uname.system == "Linux":
        return _Outcome(STATUS_PASS, f"运行于 Linux（内核 {uname.release}）", evidence)
    return _Outcome(
        STATUS_UNSUPPORTED,
        f"当前主机为 {uname.system}；eBPF 采集仅支持 Linux，macOS/Windows 仅作为 Linux VM 宿主",
        {**evidence, "target": "Linux"},
    )


def _check_platform_arch(host: Host) -> _Outcome:
    uname = _safe_uname(host)
    machine = uname.machine.lower()
    evidence = {"machine": machine, "target_machine": "aarch64"}
    if uname.system != "Linux":
        return _Outcome(
            STATUS_UNSUPPORTED, "非 Linux 主机，架构检查不适用（M0 目标为 Linux/ARM64）", evidence
        )
    if machine in _TARGET_MACHINES:
        return _Outcome(STATUS_PASS, f"架构 {machine} 与 M0 目标 ARM64 一致", evidence)
    return _Outcome(
        STATUS_WARN,
        f"架构为 {machine}，而 M0 目标为 ARM64；x86_64 只能作为本地回归环境",
        evidence,
    )


def _check_kernel_btf(host: Host) -> _Outcome:
    info = host.inspect(_VMLINUX_BTF)
    modules = host.listdir(_BTF_DIR)
    evidence: dict[str, Any] = {
        "path": _VMLINUX_BTF,
        "exists": info.exists,
        "readable": info.readable,
        "size_bytes": info.size,
        "btf_module_count": len(modules),
    }
    ok = info.exists and info.readable and (info.size or 0) > 0
    if ok:
        return _Outcome(
            STATUS_PASS,
            "vmlinux BTF 可读（仅证明 CO-RE 类型信息存在，不代表任何挂点可用）",
            evidence,
        )
    return _Outcome(
        STATUS_FAIL,
        f"{_VMLINUX_BTF} 缺失或不可读：需要 CONFIG_DEBUG_INFO_BTF=y 的内核",
        evidence,
    )


def _check_kernel_tracefs(host: Host) -> _Outcome:
    root = _tracefs_root(host)
    mounts = host.read_text(_PROC_MOUNTS) or ""
    tracefs_mounted = any(
        line.split()[2:3] == ["tracefs"] for line in mounts.splitlines() if line.split()
    )
    evidence = {
        "tracefs_root": root,
        "candidates": list(_TRACEFS_CANDIDATES),
        "proc_mounts_has_tracefs": tracefs_mounted,
    }
    if root is not None:
        return _Outcome(STATUS_PASS, f"tracefs 已挂载：{root}", evidence)
    return _Outcome(
        STATUS_FAIL,
        "tracefs 未挂载（未找到 /sys/kernel/tracing 或 /sys/kernel/debug/tracing）；"
        "tracepoint 与 ftrace 均不可用",
        evidence,
    )


def _check_tracepoint_sched_process_exec(host: Host) -> _Outcome:
    root = _tracefs_root(host)
    evidence: dict[str, Any] = {"tracefs_root": root}
    if root is None:
        return _Outcome(
            STATUS_FAIL,
            "tracefs 未挂载，无法确认 sched_process_exec tracepoint 是否可用",
            evidence,
        )
    event_dir = f"{root}/events/sched/sched_process_exec"
    id_path = f"{event_dir}/id"
    format_path = f"{event_dir}/format"
    id_size = _readable_size(host, id_path)
    format_size = _readable_size(host, format_path)
    tracepoint_id: int | None = None
    if id_size is not None:
        raw = (host.read_text(id_path) or "").strip()
        tracepoint_id = int(raw) if raw.isdigit() else None
    evidence.update(
        {
            "event_dir": event_dir,
            "id": tracepoint_id,
            "id_readable": id_size is not None,
            "format_readable": format_size is not None,
        }
    )
    if id_size is not None or format_size is not None:
        return _Outcome(
            STATUS_PASS,
            f"sched_process_exec tracepoint 可见（id={tracepoint_id}）",
            evidence,
        )
    return _Outcome(
        STATUS_FAIL,
        f"未找到 {event_dir}：内核缺少 sched_process_exec tracepoint 或 tracefs 内容不完整",
        evidence,
    )


def _check_fentry_fexit(host: Host) -> _Outcome:
    btf_info = host.inspect(_VMLINUX_BTF)
    btf_ok = btf_info.exists and btf_info.readable and (btf_info.size or 0) > 0
    filter_path, filter_size = _first_readable(host, _FILTER_FUNCTIONS_CANDIDATES)
    ftrace_ok = bool(filter_size)
    config, config_source = _kernel_config(host)

    clues: dict[str, bool] = {
        "vmlinux_btf": btf_ok,
        "available_filter_functions": ftrace_ok,
    }
    if config is not None:
        for key in _FENTRY_CONFIG_KEYS:
            clues[key] = _config_get(config, key) == "y"
    missing = sorted(name for name, present in clues.items() if not present)

    evidence: dict[str, Any] = {
        "clues": clues,
        "missing_clues": missing,
        "available_filter_functions": filter_path,
        "available_filter_functions_bytes": filter_size,
        "vmlinux_btf_bytes": btf_info.size,
        "kernel_config_source": config_source,
        "note": (
            "fentry/fexit 需要 vmlinux BTF(FUNC)、ftrace 与 CONFIG_BPF_EVENTS/CONFIG_FUNCTION_TRACER；"
            "线索满足仍须在固定 VM 内以实际 attach 验证"
        ),
    }

    if not btf_ok or not ftrace_ok:
        return _Outcome(
            STATUS_FAIL,
            f"缺少 fentry/fexit 的硬性前提：{', '.join(missing)}",
            evidence,
        )
    if config is None:
        return _Outcome(
            STATUS_WARN,
            "BTF 与 ftrace 过滤函数存在，但未找到内核配置（/boot/config-* 或 /proc/config.gz），"
            "无法交叉验证 CONFIG_BPF_EVENTS/CONFIG_FUNCTION_TRACER",
            evidence,
        )
    if missing:
        return _Outcome(
            STATUS_WARN,
            f"部分内核配置线索不满足：{', '.join(missing)}；需在 VM 内实测 attach",
            evidence,
        )
    return _Outcome(
        STATUS_PASS,
        "fentry/fexit 线索齐全（BTF + ftrace + 内核配置）；仍须在 VM 内以实际 attach 确认",
        evidence,
    )


def _check_bpf_lsm(host: Host) -> _Outcome:
    raw = host.read_text(_SECURITY_LSM)
    config, config_source = _kernel_config(host)
    config_value = _config_get(config, "CONFIG_BPF_LSM")
    config_lsm_param = _config_get(config, "CONFIG_LSM")

    active: list[str] | None = None
    if raw is not None:
        active = [part.strip() for part in raw.strip().split(",") if part.strip()]

    evidence: dict[str, Any] = {
        "security_lsm_path": _SECURITY_LSM,
        "active_lsm": active,
        "bpf_in_active_lsm": bool(active and "bpf" in active),
        "config_source": config_source,
        "CONFIG_BPF_LSM": config_value,
        "CONFIG_LSM": config_lsm_param,
    }

    if active is None:
        return _Outcome(
            STATUS_FAIL,
            f"无法读取 {_SECURITY_LSM}（securityfs 未挂载），不能确认 BPF LSM 是否启用",
            evidence,
        )
    if "bpf" not in active:
        if config_value == "y":
            return _Outcome(
                STATUS_FAIL,
                "内核已编译 BPF LSM（CONFIG_BPF_LSM=y）但未启用：需在 lsm= 引导参数中加入 bpf",
                evidence,
            )
        return _Outcome(
            STATUS_FAIL,
            "BPF LSM 未启用（活动 LSM 列表中没有 bpf，且内核配置未显示 CONFIG_BPF_LSM=y）",
            evidence,
        )
    if config is None:
        return _Outcome(
            STATUS_WARN,
            "活动 LSM 列表包含 bpf，但未找到内核配置，无法交叉验证 CONFIG_BPF_LSM",
            evidence,
        )
    if config_value == "y":
        return _Outcome(
            STATUS_PASS,
            "BPF LSM 已编译并在活动 LSM 列表中启用；阻断语义仍须在 VM 内实测",
            evidence,
        )
    return _Outcome(
        STATUS_WARN,
        f"活动 LSM 列表包含 bpf，但内核配置 CONFIG_BPF_LSM={config_value!r}，"
        "可能与运行内核不一致（/boot 配置陈旧）",
        evidence,
    )


def _parse_cap_effective(text: str | None) -> int | None:
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("CapEff:"):
            value = line.split(":", 1)[1].strip()
            try:
                return int(value, 16)
            except ValueError:
                return None
    return None


def _check_capabilities(host: Host) -> _Outcome:
    caps = _parse_cap_effective(host.read_text(_SELF_STATUS))
    euid = host.euid()
    unprivileged = (host.read_text(_UNPRIVILEGED_BPF) or "").strip() or None
    bits = {
        "CAP_SYS_ADMIN": bool(caps is not None and caps & (1 << _CAP_SYS_ADMIN)),
        "CAP_PERFMON": bool(caps is not None and caps & (1 << _CAP_PERFMON)),
        "CAP_BPF": bool(caps is not None and caps & (1 << _CAP_BPF)),
    }
    evidence: dict[str, Any] = {
        "euid": euid,
        "cap_effective_raw": f"{caps:#x}" if caps is not None else None,
        "capabilities": bits,
        "unprivileged_bpf_disabled": unprivileged,
    }
    if caps is None and euid is None:
        return _Outcome(
            STATUS_WARN,
            "无法读取 CapEff/EUID，不能判断采集所需 capability（该检查为可选）",
            evidence,
        )
    if euid == 0 or bits["CAP_SYS_ADMIN"] or (bits["CAP_BPF"] and bits["CAP_PERFMON"]):
        return _Outcome(
            STATUS_PASS,
            "当前身份具备 CAP_BPF/CAP_PERFMON（或 CAP_SYS_ADMIN/root），满足加载 eBPF 程序的前提",
            evidence,
        )
    return _Outcome(
        STATUS_WARN,
        "当前身份缺少 CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN；采集需要以受保护的特权身份运行",
        evidence,
    )


def _tool_check(
    program: str,
    argv: Sequence[str],
    *,
    version_prefix: str = "",
) -> Callable[[Host], _Outcome]:
    """构造 "命令存在且可执行" 类检查。"""

    def handler(host: Host) -> _Outcome:
        path = host.which(program)
        evidence: dict[str, Any] = {
            "program": program,
            "path": path,
            "argv": list(argv),
        }
        if path is None:
            return _Outcome(STATUS_FAIL, f"未找到 {program}（不在 PATH 中）", evidence)
        result = host.run(argv)
        evidence["returncode"] = result.returncode
        if result.error is not None:
            evidence["error"] = result.error
            return _Outcome(STATUS_WARN, f"{program} 存在但无法执行：{result.error}", evidence)
        output = (result.stdout or result.stderr).strip()
        evidence["version_output"] = output.splitlines()[0] if output else ""
        if result.returncode != 0:
            return _Outcome(
                STATUS_WARN, f"{program} 存在但 {' '.join(argv[1:])} 返回 {result.returncode}", evidence
            )
        first_line = output.splitlines()[0] if output else "未知版本"
        return _Outcome(STATUS_PASS, f"{version_prefix}{program}: {first_line}", evidence)

    return handler


def _check_libbpf(host: Host) -> _Outcome:
    evidence: dict[str, Any] = {"query": "pkg-config --modversion libbpf"}
    if host.which("pkg-config") is None:
        return _Outcome(STATUS_WARN, "缺少 pkg-config，无法确认 libbpf 开发包版本", evidence)
    result = host.run(["pkg-config", "--modversion", "libbpf"])
    evidence["returncode"] = result.returncode
    if result.error is not None:
        evidence["error"] = result.error
        return _Outcome(STATUS_WARN, f"pkg-config 无法执行：{result.error}", evidence)
    version = result.stdout.strip()
    evidence["version"] = version
    if result.returncode == 0 and version:
        return _Outcome(STATUS_PASS, f"libbpf（pkg-config）: {version}", evidence)
    return _Outcome(
        STATUS_WARN,
        "未通过 pkg-config 找到 libbpf；需要 libbpf-dev（由 scripts/setup-vm.sh 安装）",
        evidence,
    )


def _check_python_runtime(host: Host) -> _Outcome:
    info = host.python_info()
    evidence: dict[str, Any] = {
        "version": info.version,
        "implementation": info.implementation,
        "executable": info.executable,
        "required_min": "3.11",
    }
    if tuple(info.version_info) >= (3, 11):
        return _Outcome(STATUS_PASS, f"Python {info.version}（{info.implementation}）满足 >=3.11", evidence)
    return _Outcome(STATUS_FAIL, f"Python {info.version} 低于要求的 3.11", evidence)


def _check_python_openssl(host: Host) -> _Outcome:
    info = host.python_info()
    evidence: dict[str, Any] = {
        "openssl_version": info.openssl_version,
        "python_version": info.version,
        "note": "仅记录 Python 链接的 OpenSSL 版本；SSL_read/write 实际调用点须在 M0 单独定位",
    }
    if info.openssl_version:
        return _Outcome(STATUS_PASS, f"Python OpenSSL: {info.openssl_version}", evidence)
    return _Outcome(STATUS_FAIL, "无法获取 Python 的 OpenSSL 版本（ssl 模块不可用）", evidence)


def _check_docker(host: Host) -> _Outcome:
    path = host.which("docker")
    socket = host.inspect("/var/run/docker.sock")
    evidence: dict[str, Any] = {
        "path": path,
        "socket_path": "/var/run/docker.sock",
        "socket_exists": socket.exists,
    }
    if path is None:
        return _Outcome(STATUS_FAIL, "未找到 docker CLI（M3 容器映射需要）", evidence)
    result = host.run(["docker", "version", "--format", "{{.Server.Version}}"])
    evidence["returncode"] = result.returncode
    if result.error is not None:
        evidence["error"] = result.error
        return _Outcome(STATUS_WARN, f"docker CLI 存在但无法执行：{result.error}", evidence)
    server_version = result.stdout.strip()
    evidence["server_version"] = server_version
    if result.returncode == 0 and server_version:
        return _Outcome(STATUS_PASS, f"docker daemon 可达：server {server_version}", evidence)
    evidence["stderr"] = result.stderr.strip()[:200]
    return _Outcome(
        STATUS_WARN,
        "docker CLI 存在但 daemon 不可达（容器映射在 M3 才使用；VM 内需启动 docker）",
        evidence,
    )


#: 检查注册表。顺序即报告顺序，新增检查必须显式声明 ``required`` 与 ``linux_only``。
CHECKS: tuple[_CheckSpec, ...] = (
    _CheckSpec("platform.os", "运行平台", True, False, _check_platform_os),
    _CheckSpec("platform.arch", "目标架构", False, False, _check_platform_arch),
    _CheckSpec("kernel.btf", "vmlinux BTF", True, True, _check_kernel_btf),
    _CheckSpec("kernel.tracefs", "tracefs 挂载", True, True, _check_kernel_tracefs),
    _CheckSpec(
        "kernel.tracepoint.sched_process_exec",
        "sched_process_exec tracepoint",
        True,
        True,
        _check_tracepoint_sched_process_exec,
    ),
    _CheckSpec("kernel.fentry_fexit", "fentry/fexit 线索", True, True, _check_fentry_fexit),
    _CheckSpec("security.bpf_lsm", "BPF LSM", True, True, _check_bpf_lsm),
    _CheckSpec("security.capabilities", "采集所需 capability", False, True, _check_capabilities),
    _CheckSpec("tools.clang", "clang", True, True, _tool_check("clang", ["clang", "--version"])),
    _CheckSpec("tools.bpftool", "bpftool", True, True, _tool_check("bpftool", ["bpftool", "version"])),
    _CheckSpec(
        "tools.pkg_config", "pkg-config", True, True, _tool_check("pkg-config", ["pkg-config", "--version"])
    ),
    _CheckSpec("tools.libbpf", "libbpf", False, True, _check_libbpf),
    _CheckSpec("python.runtime", "Python 运行时", True, False, _check_python_runtime),
    _CheckSpec("python.openssl", "Python OpenSSL", True, False, _check_python_openssl),
    _CheckSpec("docker.engine", "Docker", True, True, _check_docker),
)


# --------------------------------------------------------------------------------------
# 采集与渲染
# --------------------------------------------------------------------------------------


def collect(host: Host | None = None, *, now: datetime | None = None) -> DoctorReport:
    """执行全部检查并返回报告。任何宿主异常都会被降级，函数本身不抛出。"""
    host = host if host is not None else LocalHost()
    uname = _safe_uname(host)
    linux = uname.system == "Linux"
    results: list[CheckResult] = []
    for spec in CHECKS:
        results.append(_run_check(spec, host, linux=linux, uname=uname))
    timestamp = (now if now is not None else datetime.now(timezone.utc)).astimezone(timezone.utc)
    return DoctorReport(
        schema_version=SCHEMA_VERSION,
        generated_at=timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        host=uname,
        checks=tuple(results),
    )


def _run_check(spec: _CheckSpec, host: Host, *, linux: bool, uname: Uname) -> CheckResult:
    if spec.linux_only and not linux:
        return CheckResult(
            id=spec.id,
            title=spec.title,
            status=STATUS_UNSUPPORTED,
            required=spec.required,
            summary=f"非 Linux 主机（{uname.system}）：该检查只在 Linux 采集目标上适用",
            evidence={"system": uname.system},
        )
    try:
        outcome = spec.handler(host)
    except Exception as exc:  # 单项异常不能中断整份报告
        return CheckResult(
            id=spec.id,
            title=spec.title,
            status=STATUS_FAIL,
            required=spec.required,
            summary="检查执行时发生内部错误",
            evidence={"error": f"{type(exc).__name__}: {exc}"},
        )
    status = outcome.status if outcome.status in STATUSES else STATUS_FAIL
    return CheckResult(
        id=spec.id,
        title=spec.title,
        status=status,
        required=spec.required,
        summary=outcome.summary,
        evidence=outcome.evidence,
    )


def render_json(report: DoctorReport) -> str:
    """稳定的 JSON 表示（缩进 2，键顺序由 :meth:`DoctorReport.to_dict` 固定）。"""
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def _format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, Mapping):
        # 嵌套结构（例如 fentry 的 clues）用排序后的紧凑 JSON，保证文本输出稳定。
        return json.dumps(_normalize_evidence(value), ensure_ascii=False, sort_keys=True)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(str(v) for v in value) + "]"
    return str(value)


def render_text(report: DoctorReport) -> str:
    """人类可读输出。不含时间戳，便于 diff 与稳定性检查。"""
    counts = report.counts
    lines = [
        f"probe doctor · schema v{report.schema_version} · agent-probe {__version__}",
        f"host: {report.host.system} {report.host.machine} (kernel {report.host.release})",
        (
            f"overall: {report.overall_status.upper()} · exit={report.exit_code} · "
            + " ".join(f"{status}={counts[status]}" for status in STATUSES)
        ),
        "",
    ]
    for check in report.checks:
        requirement = "required" if check.required else "optional"
        lines.append(f"[{check.status}] {check.id} ({requirement})")
        lines.append(f"    {check.summary}")
        for key, value in sorted(_normalize_evidence(check.evidence).items()):
            lines.append(f"    - {key}: {_format_value(value)}")
    lines.append("")
    lines.append(f"note: {LIMITATIONS_NOTE}")
    return "\n".join(lines)
