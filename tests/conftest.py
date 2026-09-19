"""pytest 共享夹具。

子进程测试需要 ``python -m agent_probe`` 可导入。由于验证流程允许
"先跑测试、后执行可编辑安装"，这里显式把 ``src/`` 注入子进程的
``PYTHONPATH``，使测试结果不依赖安装顺序。
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

RunCliModule = Callable[..., subprocess.CompletedProcess[str]]


@pytest.fixture
def run_cli_module() -> RunCliModule:
    """以子进程方式运行 ``python -m agent_probe``（携带 PYTHONPATH=src）。"""

    def _run(*args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(SRC_DIR) if not existing else str(SRC_DIR) + os.pathsep + existing
        return subprocess.run(
            [sys.executable, "-m", "agent_probe", *args],
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    return _run
