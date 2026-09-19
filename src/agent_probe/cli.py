"""``probe`` 命令行入口。

当前稳定契约：

* ``probe --version``：输出版本号，供打包与安装自检使用。
* ``probe doctor [--json]``：执行 M0 的只读环境与能力检查（见 :mod:`agent_probe.doctor`），
  文本或 JSON 输出，退出码区分 "通过 / 必需项失败 / 主机不受支持 / doctor 自身出错"。

本模块刻意不包含任何采集、协议解析、事件模型、存储或执行控制逻辑；
这些内容由后续里程碑（见 ``plan.md``）负责，新增子命令时同样遵循
"不实现即不注册" 的原则，避免出现无实现的业务入口。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from collections.abc import Sequence

from agent_probe import __version__, doctor
from agent_probe.audit import (
    AuditError,
    audit_ledger,
    explain_event,
    load_calls_artifact,
    load_policy,
    render_report,
)

__all__ = ["PROG", "build_parser", "main"]

#: 对外命令名（控制台脚本与 python -m 均使用该名称展示用法）。
PROG = "probe"


def _cmd_doctor(args: argparse.Namespace) -> int:
    """执行 ``probe doctor``，返回 doctor 退出码。"""
    as_json = bool(getattr(args, "as_json", False))
    try:
        report = doctor.collect()
    except Exception as exc:  # doctor.collect 设计上不抛异常；这里是最后一道防线
        print(f"probe doctor: 内部错误：{type(exc).__name__}: {exc}", file=sys.stderr)
        return doctor.EXIT_INTERNAL_ERROR
    print(doctor.render_json(report) if as_json else doctor.render_text(report))
    return report.exit_code


def _audit_report_from_args(args: argparse.Namespace):
    policy = load_policy(args.policy)
    calls = None if args.calls is None else load_calls_artifact(args.calls)
    return audit_ledger(policy, args.ledger, calls=calls)


def _cmd_report(args: argparse.Namespace) -> int:
    try:
        rendered = render_report(_audit_report_from_args(args), args.format)
    except (AuditError, OSError, ValueError) as exc:
        print(f"probe report: 输入错误：{exc}", file=sys.stderr)
        return 2
    if args.output is None:
        print(rendered, end="")
    else:
        try:
            Path(args.output).write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"probe report: 无法写入输出：{exc}", file=sys.stderr)
            return 2
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    try:
        view = explain_event(_audit_report_from_args(args), args.event_id)
        import json
        print(json.dumps(view, ensure_ascii=False, sort_keys=True, indent=2))
    except (AuditError, OSError, ValueError) as exc:
        print(f"probe explain: 输入错误：{exc}", file=sys.stderr)
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    """构造顶层参数解析器。

    仅注册已实现的选项与子命令：``--version`` 和 ``doctor``。
    """
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="agent-probe：Coding Agent 的系统审计、行为关联与受限执行控制。",
        epilog="当前提供 --version 与 doctor（M0 只读环境检查）；其余子命令将随里程碑逐步加入。",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROG} {__version__}",
        help="打印版本号并退出",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="M0 只读环境与能力检查（BTF/tracefs/tracepoint/fentry-fexit/BPF LSM/工具链）",
        description=(
            "只读检查当前主机是否满足 M0 的采集前提，并在报告中保留判断依据（evidence）。"
            "退出码：0=必需项通过，1=存在必需项失败，2=当前主机不受支持，3=doctor 自身出错。"
            "非 Linux 主机会给出 unsupported 结果而不是报错。"
        ),
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="以稳定 JSON（schema_version=1）输出，便于机器解析",
    )
    doctor_parser.set_defaults(handler=_cmd_doctor)
    report_parser = subparsers.add_parser("report", help="从权威账本重算 M4 审计报告")
    report_parser.add_argument("--policy", required=True, help="M4 YAML 规则文件")
    report_parser.add_argument("--ledger", required=True, help="M2 权威 JSONL 账本")
    report_parser.add_argument("--calls", help="可选的版本化 calls artifact JSON")
    report_parser.add_argument("--format", choices=("text", "json", "html"), default="text")
    report_parser.add_argument("--output", help="输出文件；默认标准输出")
    report_parser.set_defaults(handler=_cmd_report)
    explain_parser = subparsers.add_parser("explain", help="从原始账本回溯一个事件的审计证据")
    explain_parser.add_argument("event_id", help="要解释的原始 event ID")
    explain_parser.add_argument("--policy", required=True, help="M4 YAML 规则文件")
    explain_parser.add_argument("--ledger", required=True, help="M2 权威 JSONL 账本")
    explain_parser.add_argument("--calls", help="可选的版本化 calls artifact JSON")
    explain_parser.set_defaults(handler=_cmd_explain)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI 主入口，返回进程退出码。

    ``argv`` 为 ``None`` 时使用 ``sys.argv[1:]``（便于测试传入固定参数）。
    未给出子命令时打印帮助并返回 0；参数错误由 argparse 以退出码 2 处理。
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    return int(handler(args))
