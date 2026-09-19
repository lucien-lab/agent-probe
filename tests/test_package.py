"""包级与 ``python -m agent_probe`` 行为测试。"""

from __future__ import annotations

import importlib.metadata
import json
import re
import subprocess
from collections.abc import Callable

import pytest

import agent_probe
from agent_probe import __version__

RunCliModule = Callable[..., subprocess.CompletedProcess[str]]


def test_version_is_a_pre_alpha_pep440_release() -> None:
    assert __version__ == agent_probe.__version__
    assert re.fullmatch(r"0\.0\.\d+\.dev\d+", __version__), __version__


def test_package_exports_only_version_for_now() -> None:
    assert agent_probe.__all__ == ["__version__"]


def test_installed_distribution_version_matches_dunder_version() -> None:
    try:
        dist_version = importlib.metadata.version("agent-probe")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("agent-probe 尚未安装（骨架阶段允许先运行测试、后执行可编辑安装）")

    assert dist_version == __version__


def test_module_entrypoint_reports_version(run_cli_module: RunCliModule) -> None:
    result = run_cli_module("--version")

    assert result.returncode == 0
    assert result.stdout.strip() == f"probe {__version__}"
    assert result.stderr == ""


def test_module_entrypoint_doctor_emits_report_with_matching_exit_code(
    run_cli_module: RunCliModule,
) -> None:
    result = run_cli_module("doctor", "--json")

    payload = json.loads(result.stdout)
    # 退出码必须与报告一致；具体值取决于宿主（Linux=0/1，macOS 等非 Linux=2），
    # 不在测试中硬编码，以免测试随开发机平台漂移。
    assert result.returncode == payload["overall"]["exit_code"]
    assert result.returncode in (0, 1, 2)
    assert payload["schema_version"] == 1
    assert payload["checks"]
    assert result.stderr == ""


def test_module_entrypoint_doctor_text_mode_is_not_a_placeholder(
    run_cli_module: RunCliModule,
) -> None:
    result = run_cli_module("doctor")

    assert result.returncode in (0, 1, 2)
    assert "overall:" in result.stdout
    assert "kernel.btf" in result.stdout
    assert "尚未实现" not in result.stdout
    assert result.stderr == ""
