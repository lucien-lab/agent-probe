"""CLI 行为测试：断言 `probe` 对外承诺的行为。

doctor 的检查逻辑在 ``tests/test_doctor.py`` 中用内存宿主覆盖；这里只验证
CLI 契约（参数解析、输出格式、退出码传递）。
"""

from __future__ import annotations

import json

import pytest

import agent_probe.doctor as doctor_module
from agent_probe import __version__, doctor
from agent_probe.cli import PROG, build_parser, main
from fake_host import FakeHost, make_darwin_host, make_linux_host


def _patch_collect(monkeypatch: pytest.MonkeyPatch, host: FakeHost) -> None:
    """让 CLI 在固定能力矩阵上运行：先取出原函数，避免自递归。"""
    real_collect = doctor_module.collect
    monkeypatch.setattr(doctor_module, "collect", lambda: real_collect(host=host))


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


def test_doctor_prints_structured_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_collect(monkeypatch, make_linux_host())

    exit_code = main(["doctor"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "overall: PASS" in captured.out
    assert "[pass] kernel.btf (required)" in captured.out
    assert "尚未实现" not in captured.out


def test_doctor_json_flag_emits_valid_schema(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_collect(monkeypatch, make_linux_host())

    exit_code = main(["doctor", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == payload["overall"]["exit_code"] == 0
    assert payload["schema_version"] == 1
    assert payload["tool"]["version"] == __version__
    assert payload["overall"]["status"] == "pass"
    assert len(payload["checks"]) > 0


def test_doctor_exit_code_follows_report_on_unsupported_host(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_collect(monkeypatch, make_darwin_host())

    exit_code = main(["doctor", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["overall"]["status"] == "unsupported"
    assert payload["overall"]["exit_code"] == 2


def test_doctor_internal_error_returns_three(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _boom():  # noqa: ANN202
        raise RuntimeError("collect 爆炸")

    monkeypatch.setattr(doctor_module, "collect", _boom)

    exit_code = main(["doctor"])
    captured = capsys.readouterr()

    assert exit_code == doctor.EXIT_INTERNAL_ERROR == 3
    assert captured.out == ""
    assert "内部错误" in captured.err


def test_doctor_on_real_host_still_emits_parseable_json(capsys: pytest.CaptureFixture[str]) -> None:
    """真实宿主（本地为 macOS）必须给出合法 JSON 与一致的退出码，而不是崩溃。"""
    exit_code = main(["doctor", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == payload["overall"]["exit_code"]
    assert exit_code in (0, 1, 2)
    assert payload["schema_version"] == 1
    assert len(payload["checks"]) == len(doctor.CHECKS)


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
