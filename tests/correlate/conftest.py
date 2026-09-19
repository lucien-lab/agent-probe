"""``tests/correlate`` 的 pytest 夹具（场景构造器在 ``correlate.fixtures``）。"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from agent_probe.correlate import AssistantMarkers, CorrelationConfig, Task
from agent_probe.events import Event
from agent_probe.llm import LlmCallRecord

from correlate.fixtures import corpus_scenario, serial_scenario


@pytest.fixture
def serial() -> tuple[tuple[Event, ...], tuple[LlmCallRecord, ...], tuple[Task, ...]]:
    return serial_scenario()


@pytest.fixture
def corpus() -> (
    tuple[tuple[Event, ...], tuple[LlmCallRecord, ...], tuple[Task, ...], AssistantMarkers]
):
    return corpus_scenario()


@pytest.fixture
def assisted_config() -> CorrelationConfig:
    return CorrelationConfig(use_assisted_markers=True)


@pytest.fixture
def write_text_file(tmp_path: Path) -> Callable[[str, str], Path]:
    """把文本写到 ``tmp_path``（需要文件输入时使用，绝不污染仓库）。"""

    def _write(name: str, text: str) -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    return _write
