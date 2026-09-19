"""包级与 ``python -m agent_probe`` 行为测试。"""

from __future__ import annotations

import importlib.metadata
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


def test_module_entrypoint_doctor_is_a_placeholder(run_cli_module: RunCliModule) -> None:
    result = run_cli_module("doctor")

    assert result.returncode == 0
    assert "尚未实现" in result.stdout
    assert result.stderr == ""
