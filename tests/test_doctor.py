"""``probe doctor`` 能力检测测试。

核心原则：**不依赖运行测试的宿主平台**。所有 Linux 检查路径都用
``tests/fake_host.py`` 的内存宿主构造能力矩阵，因此这些用例在 macOS 开发机上
与在 Linux CI 上得到完全相同的结论。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from agent_probe import __version__, doctor
from agent_probe.doctor import (
    ALLOWED_PROGRAMS,
    CHECKS,
    EXIT_OK,
    EXIT_REQUIRED_FAILED,
    EXIT_REQUIRED_UNSUPPORTED,
    STATUSES,
    CheckResult,
    DoctorReport,
    Uname,
)
from fake_host import command, make_darwin_host, make_linux_host

GENERATED_AT = "2026-01-01T00:00:00Z"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def collect(host) -> DoctorReport:  # noqa: ANN001 - 测试辅助
    return doctor.collect(host=host, now=NOW)


def by_id(report: DoctorReport) -> dict[str, CheckResult]:
    return {check.id: check for check in report.checks}


# --------------------------------------------------------------------------------------
# 基线：完整 Linux ARM64 能力矩阵
# --------------------------------------------------------------------------------------


def test_full_linux_matrix_passes_required_checks() -> None:
    report = collect(make_linux_host())

    assert report.exit_code == EXIT_OK
    assert report.overall_status == "pass"
    assert report.counts["fail"] == 0
    assert report.counts["unsupported"] == 0
    assert report.counts["warn"] == 0
    assert [check.status for check in report.checks] == ["pass"] * len(CHECKS)


def test_every_check_reports_required_contract_fields() -> None:
    report = collect(make_linux_host())

    for check in report.checks:
        payload = check.to_dict()
        assert set(payload) >= {"id", "status", "summary", "evidence"}
        assert payload["status"] in STATUSES
        assert payload["summary"]
        assert isinstance(payload["evidence"], dict)


def test_btf_alone_does_not_prove_other_hooks() -> None:
    """BTF 存在但 tracefs / tracepoint 缺失时，其余检查必须独立失败。"""
    host = make_linux_host()
    host.remove("/sys/kernel/tracing/trace")
    host.remove("/sys/kernel/tracing/events")
    host.set_file("/proc/mounts", "sysfs /sys sysfs rw 0 0\n")

    report = collect(host)
    checks = by_id(report)

    assert checks["kernel.btf"].status == "pass"
    assert checks["kernel.tracefs"].status == "fail"
    assert checks["kernel.tracepoint.sched_process_exec"].status == "fail"
    assert report.exit_code == EXIT_REQUIRED_FAILED


# --------------------------------------------------------------------------------------
# 缺文件场景
# --------------------------------------------------------------------------------------


def test_missing_vmlinux_btf_fails() -> None:
    host = make_linux_host()
    host.remove("/sys/kernel/btf/vmlinux")

    report = collect(host)
    check = by_id(report)["kernel.btf"]

    assert check.status == "fail"
    assert check.evidence["exists"] is False
    assert "CONFIG_DEBUG_INFO_BTF" in check.summary
    assert report.exit_code == EXIT_REQUIRED_FAILED


def test_missing_tracepoint_directory_fails() -> None:
    host = make_linux_host()
    host.remove("/sys/kernel/tracing/events/sched/sched_process_exec/id")
    host.remove("/sys/kernel/tracing/events/sched/sched_process_exec/format")

    check = by_id(collect(host))["kernel.tracepoint.sched_process_exec"]

    assert check.status == "fail"
    assert check.evidence["id_readable"] is False
    assert check.evidence["format_readable"] is False


def test_tracefs_unmounted_fails_and_reports_evidence() -> None:
    host = make_linux_host()
    host.remove("/sys/kernel/tracing/trace")
    host.remove("/sys/kernel/tracing/events")
    host.set_file("/proc/mounts", "sysfs /sys sysfs rw 0 0\n")

    check = by_id(collect(host))["kernel.tracefs"]

    assert check.status == "fail"
    assert check.evidence["tracefs_root"] is None
    assert check.evidence["proc_mounts_has_tracefs"] is False


# --------------------------------------------------------------------------------------
# fentry/fexit：线索 vs 硬性前提
# --------------------------------------------------------------------------------------


def test_fentry_without_kernel_config_is_only_a_warning() -> None:
    host = make_linux_host()
    host.remove(f"/boot/config-{host.release}")

    report = collect(host)
    check = by_id(report)["kernel.fentry_fexit"]

    assert check.status == "warn"
    assert "未找到内核配置" in check.summary
    # 必需项为 warn 时仍算环境可用，但总体状态降级为 warn。
    assert report.exit_code == EXIT_OK
    assert report.overall_status == "warn"


def test_fentry_missing_config_clue_is_a_warning() -> None:
    host = make_linux_host()
    host.set_file(
        f"/boot/config-{host.release}",
        "CONFIG_BPF_SYSCALL=y\nCONFIG_BPF_EVENTS=y\nCONFIG_DEBUG_INFO_BTF=y\n"
        "# CONFIG_FUNCTION_TRACER is not set\nCONFIG_BPF_LSM=y\n",
    )

    check = by_id(collect(host))["kernel.fentry_fexit"]

    assert check.status == "warn"
    assert check.evidence["clues"]["CONFIG_FUNCTION_TRACER"] is False


def test_fentry_without_available_filter_functions_fails() -> None:
    host = make_linux_host()
    host.remove("/sys/kernel/tracing/available_filter_functions")

    report = collect(host)
    check = by_id(report)["kernel.fentry_fexit"]

    assert check.status == "fail"
    assert "available_filter_functions" in check.summary
    assert report.exit_code == EXIT_REQUIRED_FAILED


# --------------------------------------------------------------------------------------
# BPF LSM
# --------------------------------------------------------------------------------------


def test_bpf_lsm_compiled_but_not_enabled_fails() -> None:
    host = make_linux_host()
    host.set_file("/sys/kernel/security/lsm", "lockdown,capability,landlock,yama,apparmor\n")

    report = collect(host)
    check = by_id(report)["security.bpf_lsm"]

    assert check.status == "fail"
    assert check.evidence["CONFIG_BPF_LSM"] == "y"
    assert check.evidence["bpf_in_active_lsm"] is False
    assert "lsm=" in check.summary
    assert report.exit_code == EXIT_REQUIRED_FAILED


def test_bpf_lsm_missing_from_kernel_config_fails() -> None:
    host = make_linux_host()
    host.set_file("/sys/kernel/security/lsm", "lockdown,capability,apparmor\n")
    host.set_file(
        f"/boot/config-{host.release}",
        "CONFIG_BPF_SYSCALL=y\n# CONFIG_BPF_LSM is not set\n",
    )

    check = by_id(collect(host))["security.bpf_lsm"]

    assert check.status == "fail"
    assert check.evidence["CONFIG_BPF_LSM"] == "n"


def test_bpf_lsm_enabled_without_config_warns() -> None:
    host = make_linux_host()
    host.remove(f"/boot/config-{host.release}")

    check = by_id(collect(host))["security.bpf_lsm"]

    assert check.status == "warn"
    assert check.evidence["bpf_in_active_lsm"] is True


def test_securityfs_not_mounted_fails_lsm_check() -> None:
    host = make_linux_host()
    host.remove("/sys/kernel/security/lsm")

    check = by_id(collect(host))["security.bpf_lsm"]

    assert check.status == "fail"
    assert check.evidence["active_lsm"] is None


# --------------------------------------------------------------------------------------
# 工具链与 Python / Docker
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("program", "check_id"),
    [
        ("clang", "tools.clang"),
        ("bpftool", "tools.bpftool"),
        ("pkg-config", "tools.pkg_config"),
        ("docker", "docker.engine"),
    ],
)
def test_missing_command_fails(program: str, check_id: str) -> None:
    host = make_linux_host()
    host.remove_program(program)

    report = collect(host)
    check = by_id(report)[check_id]

    assert check.status == "fail"
    assert check.evidence["path"] is None
    assert report.exit_code == EXIT_REQUIRED_FAILED


def test_missing_libbpf_is_optional_warning() -> None:
    host = make_linux_host()
    host.set_command_result(
        "pkg-config --modversion libbpf", command("pkg-config", "--modversion", "libbpf", returncode=1)
    )

    report = collect(host)
    check = by_id(report)["tools.libbpf"]

    assert check.status == "warn"
    assert check.required is False
    assert report.exit_code == EXIT_OK


def test_docker_daemon_unreachable_is_warning() -> None:
    host = make_linux_host()
    host.set_command_result(
        "docker version --format {{.Server.Version}}",
        command(
            "docker",
            "version",
            "--format",
            "{{.Server.Version}}",
            returncode=1,
            stderr="Cannot connect to the Docker daemon",
        ),
    )

    report = collect(host)
    check = by_id(report)["docker.engine"]

    assert check.status == "warn"
    assert report.exit_code == EXIT_OK
    assert "daemon" in check.summary


def test_tool_version_command_failure_is_warning_not_crash() -> None:
    host = make_linux_host()
    host.set_command_result("clang --version", command("clang", "--version", error="TimeoutExpired"))

    check = by_id(collect(host))["tools.clang"]

    assert check.status == "warn"
    assert "TimeoutExpired" in check.evidence["error"]


def test_old_python_fails_runtime_check() -> None:
    from fake_host import DEFAULT_PYTHON
    from agent_probe.doctor import PythonInfo

    host = make_linux_host(
        python=PythonInfo(
            version="3.9.18",
            version_info=(3, 9, 18),
            implementation="CPython",
            executable="/usr/bin/python3.9",
            openssl_version=DEFAULT_PYTHON.openssl_version,
        )
    )

    report = collect(host)
    assert by_id(report)["python.runtime"].status == "fail"
    assert report.exit_code == EXIT_REQUIRED_FAILED


def test_python_without_openssl_fails() -> None:
    from agent_probe.doctor import PythonInfo

    host = make_linux_host(
        python=PythonInfo("3.12.3", (3, 12, 3), "CPython", "/usr/bin/python3.12", None)
    )

    check = by_id(collect(host))["python.openssl"]

    assert check.status == "fail"
    assert check.evidence["openssl_version"] is None


def test_capabilities_missing_is_optional_warning() -> None:
    host = make_linux_host(euid=1000)
    host.set_file("/proc/self/status", "Name:\tprobe\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n")

    report = collect(host)
    check = by_id(report)["security.capabilities"]

    assert check.status == "warn"
    assert check.required is False
    assert report.exit_code == EXIT_OK


# --------------------------------------------------------------------------------------
# 非 Linux 宿主机：必须给出 unsupported，而不是抛异常
# --------------------------------------------------------------------------------------


def test_non_linux_host_is_unsupported_without_exception() -> None:
    report = collect(make_darwin_host())

    assert report.exit_code == EXIT_REQUIRED_UNSUPPORTED
    assert report.overall_status == "unsupported"
    checks = by_id(report)

    assert checks["platform.os"].status == "unsupported"
    assert checks["platform.arch"].status == "unsupported"
    for check_id in (
        "kernel.btf",
        "kernel.tracefs",
        "kernel.tracepoint.sched_process_exec",
        "kernel.fentry_fexit",
        "security.bpf_lsm",
        "tools.clang",
        "tools.bpftool",
        "tools.pkg_config",
        "docker.engine",
    ):
        assert checks[check_id].status == "unsupported", check_id
        assert "非 Linux 主机" in checks[check_id].summary

    # 平台无关的检查仍然执行。
    assert checks["python.runtime"].status == "pass"
    assert checks["python.openssl"].status == "pass"


def test_missing_paths_on_linux_never_raise() -> None:
    """空白 Linux 宿主（所有文件都缺）也必须产出完整报告。"""
    report = collect(make_linux_host(use_defaults=False))

    assert len(report.checks) == len(CHECKS)
    assert report.exit_code == EXIT_REQUIRED_FAILED
    assert by_id(report)["kernel.btf"].status == "fail"


class _BrokenHost:
    """所有访问都抛异常，用于验证单项异常被降级而不是冒泡。"""

    def uname(self):  # noqa: ANN201
        raise RuntimeError("uname 爆炸")

    def inspect(self, path: str):  # noqa: ANN201
        raise RuntimeError(f"inspect 爆炸: {path}")

    def listdir(self, path: str):  # noqa: ANN201
        raise RuntimeError("listdir 爆炸")

    def read_text(self, path: str, *, max_bytes: int = 0):  # noqa: ANN201
        raise RuntimeError("read_text 爆炸")

    def read_bytes(self, path: str, *, max_bytes: int = 0):  # noqa: ANN201
        raise RuntimeError("read_bytes 爆炸")

    def which(self, name: str):  # noqa: ANN201
        raise RuntimeError("which 爆炸")

    def run(self, argv, *, timeout: float = 0.0):  # noqa: ANN001, ANN201
        raise RuntimeError("run 爆炸")

    def python_info(self):  # noqa: ANN201
        raise RuntimeError("python_info 爆炸")

    def euid(self):  # noqa: ANN201
        raise RuntimeError("euid 爆炸")


def test_broken_host_is_converted_to_failures() -> None:
    report = collect(_BrokenHost())

    assert report.host.system.startswith("unknown")
    assert len(report.checks) == len(CHECKS)
    assert report.counts["fail"] > 0
    failed = [check for check in report.checks if check.status == "fail"]
    assert any("内部错误" in check.summary for check in failed)
    assert report.exit_code in (EXIT_REQUIRED_FAILED, EXIT_REQUIRED_UNSUPPORTED)


# --------------------------------------------------------------------------------------
# 只读性：doctor 只允许白名单程序
# --------------------------------------------------------------------------------------


def test_doctor_only_runs_allowlisted_read_only_programs() -> None:
    host = make_linux_host()
    collect(host)

    assert host.used_programs()
    assert host.used_programs() <= ALLOWED_PROGRAMS
    for call in host.calls:
        argv = " ".join(call)
        for verb in (" install", " add", " rm ", " remove", " apply", " -i ", " update"):
            assert verb not in f" {argv} ", call


def test_local_host_rejects_non_allowlisted_program() -> None:
    result = doctor.LocalHost().run(["apt-get", "install", "bpftool"])

    assert result.returncode is None
    assert result.error is not None
    assert "白名单" in result.error


# --------------------------------------------------------------------------------------
# JSON schema 与退出码
# --------------------------------------------------------------------------------------


def test_json_schema_is_stable_and_serializable() -> None:
    report = collect(make_linux_host())
    payload = json.loads(doctor.render_json(report))

    assert payload["schema_version"] == 1
    assert payload["tool"] == {
        "name": "agent-probe",
        "command": "probe doctor",
        "version": __version__,
    }
    assert payload["generated_at"] == GENERATED_AT
    assert payload["host"] == {
        "system": "Linux",
        "machine": "aarch64",
        "kernel_release": "6.8.0-40-generic",
        "node": "agent-probe-vm",
    }
    assert set(payload["overall"]) == {"status", "exit_code", "counts", "note"}
    assert payload["overall"]["exit_code"] == report.exit_code
    assert payload["overall"]["counts"] == report.counts
    assert sum(payload["overall"]["counts"].values()) == len(payload["checks"])

    assert [check["id"] for check in payload["checks"]] == [spec.id for spec in CHECKS]
    assert len({check["id"] for check in payload["checks"]}) == len(CHECKS)
    for check in payload["checks"]:
        assert set(check) == {"id", "title", "required", "status", "summary", "evidence"}
        assert check["status"] in STATUSES
        assert isinstance(check["required"], bool)
        assert list(check["evidence"]) == sorted(check["evidence"])


def test_json_is_deterministic_apart_from_timestamp() -> None:
    first = doctor.render_json(collect(make_linux_host()))
    second = doctor.render_json(collect(make_linux_host()))

    assert first == second


def _report(*checks: CheckResult) -> DoctorReport:
    return DoctorReport(
        schema_version=1,
        generated_at=GENERATED_AT,
        host=Uname("Linux", "aarch64", "6.8.0-40-generic"),
        checks=tuple(checks),
    )


def _check(status: str, *, required: bool) -> CheckResult:
    return CheckResult(
        id=f"fake.{status}.{required}",
        title="fake",
        status=status,
        required=required,
        summary="fake",
    )


@pytest.mark.parametrize(
    ("status", "required", "expected_exit"),
    [
        ("pass", True, EXIT_OK),
        ("warn", True, EXIT_OK),
        ("warn", False, EXIT_OK),
        ("fail", False, EXIT_OK),
        ("fail", True, EXIT_REQUIRED_FAILED),
        ("unsupported", True, EXIT_REQUIRED_UNSUPPORTED),
        ("unsupported", False, EXIT_OK),
    ],
)
def test_exit_code_matrix(status: str, required: bool, expected_exit: int) -> None:
    assert _report(_check(status, required=required)).exit_code == expected_exit


def test_required_failure_takes_precedence_over_unsupported() -> None:
    report = _report(
        _check("fail", required=True),
        _check("unsupported", required=True),
    )

    assert report.exit_code == EXIT_REQUIRED_FAILED
    assert report.overall_status == "fail"


def test_optional_failure_only_downgrades_overall_status() -> None:
    report = _report(_check("pass", required=True), _check("fail", required=False))

    assert report.exit_code == EXIT_OK
    assert report.overall_status == "warn"


# --------------------------------------------------------------------------------------
# 文本渲染
# --------------------------------------------------------------------------------------


def test_text_render_contains_all_check_ids_and_overall_line() -> None:
    report = collect(make_linux_host())
    text = doctor.render_text(report)

    assert "overall: PASS" in text
    assert "exit=0" in text
    for spec in CHECKS:
        assert f"[pass] {spec.id} (required)" in text or f"[pass] {spec.id} (optional)" in text
    assert doctor.LIMITATIONS_NOTE in text
