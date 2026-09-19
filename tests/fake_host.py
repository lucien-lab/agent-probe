"""测试用的内存 :class:`~agent_probe.doctor.Host` 实现。

目的：把 "Linux 能力矩阵" 变成显式数据，使 doctor 的测试**不依赖运行测试的宿主平台**
（本地开发机是 macOS，但不能因此让 Linux 检查路径得不到覆盖）。

用法::

    host = make_linux_host()                 # 默认：所有必需检查通过
    host.remove("/sys/kernel/btf/vmlinux")   # 构造 "缺 BTF" 场景
    report = doctor.collect(host=host)
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from agent_probe.doctor import CommandResult, PathInfo, PythonInfo, Uname

DEFAULT_RELEASE = "6.8.0-40-generic"

#: 一份 "全能力" 的内核配置片段（含 "is not set" 标记，用于验证解析逻辑）。
DEFAULT_KERNEL_CONFIG = """\
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_FUNCTION_TRACER=y
CONFIG_BPF_LSM=y
CONFIG_LSM="lockdown,yama,integrity,apparmor,bpf"
# CONFIG_DEBUG_INFO_BTF_MODULES is not set
"""

DEFAULT_PYTHON = PythonInfo(
    version="3.12.3",
    version_info=(3, 12, 3),
    implementation="CPython",
    executable="/usr/bin/python3.12",
    openssl_version="OpenSSL 3.0.13 30 Jan 2024",
)


def _as_bytes(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


def command(
    *argv: str,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    error: str | None = None,
) -> CommandResult:
    """构造一条命令结果；``error`` 非空表示命令未能启动。"""
    return CommandResult(
        argv=tuple(argv),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        error=error,
    )


def normalize_key(key: object) -> tuple[str, ...]:
    """把 ``"clang --version"`` 或 ``("clang", "--version")`` 统一成 argv 元组。"""
    if isinstance(key, str):
        return tuple(key.split())
    if isinstance(key, Sequence):
        return tuple(str(part) for part in key)
    raise TypeError(f"无法识别的命令键：{key!r}")


@dataclass
class FakeHost:
    """内存宿主。所有访问都命中预置数据；未预置的路径 / 命令视为不存在。"""

    system: str = "Linux"
    machine: str = "aarch64"
    release: str = DEFAULT_RELEASE
    node: str = "agent-probe-vm"
    files: dict[str, bytes] = field(default_factory=dict)
    dirs: dict[str, tuple[str, ...]] = field(default_factory=dict)
    programs: dict[str, str] = field(default_factory=dict)
    command_results: dict[tuple[str, ...], CommandResult] = field(default_factory=dict)
    python: PythonInfo = DEFAULT_PYTHON
    euid_value: int | None = 0
    calls: list[tuple[str, ...]] = field(default_factory=list)

    # ---- 测试构造辅助 ------------------------------------------------------------

    def set_file(self, path: str, content: str | bytes) -> None:
        self.files[path] = _as_bytes(content)

    def remove(self, path: str) -> None:
        self.files.pop(path, None)
        self.dirs.pop(path, None)

    def set_dir(self, path: str, entries: Sequence[str]) -> None:
        self.dirs[path] = tuple(entries)

    def set_command_result(self, key: object, result: CommandResult) -> None:
        self.command_results[normalize_key(key)] = result

    def remove_program(self, name: str) -> None:
        self.programs.pop(name, None)

    def used_programs(self) -> set[str]:
        return {call[0] for call in self.calls if call}

    # ---- Host 协议 ---------------------------------------------------------------

    def uname(self) -> Uname:
        return Uname(
            system=self.system, machine=self.machine, release=self.release, node=self.node
        )

    def inspect(self, path: str) -> PathInfo:
        if path in self.dirs:
            return PathInfo(path=path, exists=True, is_dir=True, size=None, readable=True)
        if path in self.files:
            return PathInfo(
                path=path, exists=True, is_dir=False, size=len(self.files[path]), readable=True
            )
        return PathInfo(path=path, exists=False)

    def listdir(self, path: str) -> tuple[str, ...]:
        return self.dirs.get(path, ())

    def read_text(self, path: str, *, max_bytes: int = 262144) -> str | None:
        data = self.read_bytes(path, max_bytes=max_bytes)
        if data is None:
            return None
        return data.decode("utf-8", errors="replace")

    def read_bytes(self, path: str, *, max_bytes: int = 4194304) -> bytes | None:
        data = self.files.get(path)
        if data is None:
            return None
        return data[:max_bytes]

    def which(self, name: str) -> str | None:
        return self.programs.get(name)

    def run(self, argv: Sequence[str], *, timeout: float = 5.0) -> CommandResult:
        call = tuple(str(part) for part in argv)
        self.calls.append(call)
        result = self.command_results.get(call)
        if result is not None:
            return result
        return CommandResult(argv=call, returncode=None, error="测试未配置该命令结果")

    def python_info(self) -> PythonInfo:
        return self.python

    def euid(self) -> int | None:
        return self.euid_value


def _default_files(release: str) -> dict[str, str | bytes]:
    return {
        "/proc/mounts": (
            "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
            "tracefs /sys/kernel/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0\n"
        ),
        "/proc/self/status": "Name:\tprobe\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n",
        "/proc/sys/kernel/unprivileged_bpf_disabled": "2\n",
        "/sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor,bpf\n",
        f"/boot/config-{release}": DEFAULT_KERNEL_CONFIG,
        "/sys/kernel/tracing/trace": "",
        "/sys/kernel/tracing/available_filter_functions": "__do_sys_open\nkfree\n",
        "/sys/kernel/tracing/events/sched/sched_process_exec/id": "298\n",
        "/sys/kernel/tracing/events/sched/sched_process_exec/format": (
            "name: sched_process_exec\nID: 298\n"
        ),
        "/sys/kernel/btf/vmlinux": b"\x9f\xeb\x01\x00" + b"\x00" * 64,
    }


def _default_dirs() -> dict[str, tuple[str, ...]]:
    return {
        "/sys/kernel/btf": ("6.8.0-40-generic", "vmlinux"),
        "/sys/kernel/tracing/events": ("sched",),
    }


def _default_programs() -> dict[str, str]:
    return {
        "clang": "/usr/bin/clang",
        "bpftool": "/usr/bin/bpftool",
        "pkg-config": "/usr/bin/pkg-config",
        "docker": "/usr/bin/docker",
    }


def _default_results() -> dict[tuple[str, ...], CommandResult]:
    return {
        normalize_key("clang --version"): command(
            "clang", "--version", stdout="Ubuntu clang version 18.1.3\n"
        ),
        normalize_key("bpftool version"): command("bpftool", "version", stdout="1.3.0\n"),
        normalize_key("pkg-config --version"): command(
            "pkg-config", "--version", stdout="1.8.1\n"
        ),
        normalize_key("pkg-config --modversion libbpf"): command(
            "pkg-config", "--modversion", "libbpf", stdout="1.3.0\n"
        ),
        normalize_key("docker version --format {{.Server.Version}}"): command(
            "docker", "version", "--format", "{{.Server.Version}}", stdout="26.1.4\n"
        ),
    }


def make_linux_host(
    *,
    system: str = "Linux",
    machine: str = "aarch64",
    release: str = DEFAULT_RELEASE,
    node: str = "agent-probe-vm",
    euid: int | None = 0,
    python: PythonInfo | None = None,
    files: Mapping[str, str | bytes] | None = None,
    dirs: Mapping[str, Sequence[str]] | None = None,
    programs: Mapping[str, str] | None = None,
    command_results: Mapping[object, CommandResult] | None = None,
    use_defaults: bool = True,
) -> FakeHost:
    """返回一台默认 "全能力" 的主机矩阵；``use_defaults=False`` 时从空矩阵开始。"""
    merged_files: dict[str, str | bytes] = _default_files(release) if use_defaults else {}
    merged_files.update(files or {})
    merged_dirs: dict[str, tuple[str, ...]] = _default_dirs() if use_defaults else {}
    merged_dirs.update({path: tuple(entries) for path, entries in (dirs or {}).items()})
    merged_programs: dict[str, str] = _default_programs() if use_defaults else {}
    merged_programs.update(programs or {})
    merged_results: dict[tuple[str, ...], CommandResult] = (
        _default_results() if use_defaults else {}
    )
    merged_results.update(
        {normalize_key(key): result for key, result in (command_results or {}).items()}
    )
    return FakeHost(
        system=system,
        machine=machine,
        release=release,
        node=node,
        files={path: _as_bytes(value) for path, value in merged_files.items()},
        dirs=merged_dirs,
        programs=merged_programs,
        command_results=merged_results,
        python=python or DEFAULT_PYTHON,
        euid_value=euid,
    )


def make_darwin_host(
    *,
    machine: str = "arm64",
    programs: Mapping[str, str] | None = None,
    command_results: Mapping[object, CommandResult] | None = None,
    python: PythonInfo | None = None,
    euid: int | None = 501,
) -> FakeHost:
    """返回一台 macOS 宿主：无 ``/sys``、无 Linux 工具链预置。

    刻意不继承 :func:`make_linux_host` 的默认矩阵，以便测试真正的 "非 Linux" 路径。
    """
    return FakeHost(
        system="Darwin",
        machine=machine,
        release="24.5.0",
        node="mac-host",
        files={},
        dirs={},
        programs=dict(programs or {}),
        command_results={
            normalize_key(key): result for key, result in (command_results or {}).items()
        },
        python=python or DEFAULT_PYTHON,
        euid_value=euid,
    )
