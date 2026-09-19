"""CLI 行为测试：只断言骨架阶段对外承诺的行为。"""

from __future__ import annotations

import pytest

from agent_probe import __version__
from agent_probe.cli import DOCTOR_PLACEHOLDER, PROG, build_parser, main


def test_parser_uses_probe_command_name() -> None:
    assert PROG == "probe"
    parser = build_parser()
    assert parser.prog == "probe"


def test_version_flag_prints_probe_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == f"probe {__version__}"
    assert captured.err == ""


def test_doctor_prints_placeholder_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor"]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.strip() == DOCTOR_PLACEHOLDER.strip()


def test_doctor_placeholder_states_it_is_unimplemented(capsys: pytest.CaptureFixture[str]) -> None:
    main(["doctor"])
    out = capsys.readouterr().out

    # 必须明确说明未实现，且指出后续里程碑与计划中的检查项。
    assert "尚未实现" in out
    assert "骨架" in out
    assert "M0" in out
    for keyword in ("BTF", "BPF LSM", "tracepoint"):
        assert keyword in out
    # 占位说明不能暗示已完成检查。
    assert "本次调用未执行任何检查" in out


def test_doctor_rejects_unknown_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["doctor", "--unexpected"])

    assert excinfo.value.code == 2
    assert "usage: probe" in capsys.readouterr().err


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0

    captured = capsys.readouterr()
    assert "usage: probe" in captured.out
    assert "doctor" in captured.out
    assert captured.err == ""


def test_unknown_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["run"])

    assert excinfo.value.code == 2
    assert "usage: probe" in capsys.readouterr().err
