"""CLI 行为测试：断言 `probe` 对外承诺的行为。

doctor 的检查逻辑在 ``tests/test_doctor.py`` 中用内存宿主覆盖；这里只验证
CLI 契约（参数解析、输出格式、退出码传递）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import agent_probe.doctor as doctor_module
from agent_probe import __version__, doctor
from agent_probe.cli import PROG, build_parser, main
from agent_probe.events import EventResult, EventSource, EventType, JsonlEventLedger, new_event
from fake_host import FakeHost, make_darwin_host, make_linux_host


def _patch_collect(monkeypatch: pytest.MonkeyPatch, host: FakeHost) -> None:
    """让 CLI 在固定能力矩阵上运行：先取出原函数，避免自递归。"""
    real_collect = doctor_module.collect
    monkeypatch.setattr(doctor_module, "collect", lambda: real_collect(host=host))


def _write_audit_inputs(tmp_path: Path) -> tuple[Path, Path, str]:
    """写入真正的 M2 信封账本及 M4 策略，供 CLI 全链路读取。"""
    policy_path = tmp_path / "policy.yaml"
    ledger_path = tmp_path / "ledger.jsonl"
    policy_path.write_text(
        """schema_version: 1
rules:
  - id: protect-src
    kind: forbidden_write
    paths:
      - /work/src
""",
        encoding="utf-8",
    )
    event = new_event(
        run_id="00000000-0000-4000-8000-000000000002",
        event_id="00000000-0000-4000-8000-000000000001",
        event_type=EventType.FILE_WRITE,
        source=EventSource.SYNTHETIC,
        result=EventResult.OK,
        pid=100,
        tid=100,
        process_start_id=1,
        monotonic_ns=1,
        wall_time=1,
        payload={"fd": 3, "path": "/work/src/main.py", "count": 2, "bytes_written": 2},
    )
    with JsonlEventLedger(ledger_path) as ledger:
        ledger.append(event)
    return policy_path, ledger_path, event.event_id


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


def test_report_json_replays_temporary_authoritative_ledger(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    policy, ledger, event_id = _write_audit_inputs(tmp_path)

    exit_code = main(["report", "--policy", str(policy), "--ledger", str(ledger), "--format", "json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert captured.err == ""
    assert payload["summary"]["event_count"] == 1
    assert payload["findings"][0]["verdict"] == "violation"
    assert payload["findings"][0]["event_ids"] == [event_id]
    assert payload["summary"]["data_quality"]["ledger_digest"].startswith("sha256:")


def test_report_html_writes_a_self_contained_timeline(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    policy, ledger, event_id = _write_audit_inputs(tmp_path)
    output = tmp_path / "audit.html"

    exit_code = main([
        "report", "--policy", str(policy), "--ledger", str(ledger), "--format", "html", "--output", str(output),
    ])

    assert exit_code == 0
    assert capsys.readouterr().out == ""
    page = output.read_text(encoding="utf-8")
    assert "<!doctype html>" in page
    assert "原始事件时间线" in page
    assert f'id="event-{event_id}"' in page
    assert f'href="#event-{event_id}"' in page


def test_explain_event_returns_original_evidence_and_finding(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    policy, ledger, event_id = _write_audit_inputs(tmp_path)

    exit_code = main(["explain", event_id, "--policy", str(policy), "--ledger", str(ledger)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["event"]["event_id"] == event_id
    assert payload["findings"][0]["finding"]["rule_id"] == "protect-src"
    assert payload["findings"][0]["evidence_events"][0]["event_id"] == event_id


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (["report", "--policy", "missing.yaml", "--ledger", "missing.jsonl"], "无法读取规则文件"),
        (["explain", "missing-event", "--policy", "missing.yaml", "--ledger", "missing.jsonl"], "无法读取规则文件"),
    ],
)
def test_audit_cli_reports_invalid_inputs_as_exit_two(command, expected: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(command) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert expected in captured.err
