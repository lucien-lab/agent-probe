"""``probe`` 命令行入口。

骨架阶段只提供两条稳定契约：

* ``probe --version``：输出版本号，供打包与安装自检使用。
* ``probe doctor``：打印占位说明，说明该命令尚未实现以及后续会检查什么。

本模块刻意不包含任何采集、协议解析、事件模型、存储或执行控制逻辑；
这些内容由后续里程碑（见 ``plan.md``）负责，新增子命令时同样遵循
"不实现即不注册" 的原则，避免出现无实现的业务入口。
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from agent_probe import __version__

__all__ = ["PROG", "DOCTOR_PLACEHOLDER", "build_parser", "main"]

#: 对外命令名（控制台脚本与 python -m 均使用该名称展示用法）。
PROG = "probe"

#: ``probe doctor`` 的占位说明。仅描述计划，不代表已实现的检查。
DOCTOR_PLACEHOLDER = """\
probe doctor：环境自检尚未实现（当前为工程骨架阶段）。

该命令计划在 M0（环境与能力验证）实现，届时将检查并打印：
  - 内核版本、架构与 BTF 可用性
  - tracepoint / fentry-fexit / BPF LSM 挂点可用性
  - 被测 agent 与 Docker 的版本、容器镜像摘要
  - 探针工具链（libbpf、clang、bpftool、Python/OpenSSL）版本

本次调用未执行任何检查，也未修改任何环境。"""


def _cmd_doctor(_args: argparse.Namespace) -> int:
    """打印占位说明；不做环境探测，返回 0 表示命令本身执行成功。"""
    print(DOCTOR_PLACEHOLDER)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """构造顶层参数解析器。

    仅注册已实现的选项与子命令：``--version`` 和 ``doctor``。
    """
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="agent-probe：Coding Agent 的系统审计、行为关联与受限执行控制。",
        epilog="骨架阶段仅提供 --version 与 doctor；其余子命令将随里程碑逐步加入。",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROG} {__version__}",
        help="打印版本号并退出",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    doctor = subparsers.add_parser(
        "doctor",
        help="环境自检（占位，尚未实现）",
        description="检查内核、eBPF 挂点与探针工具链（占位，尚未实现）。",
    )
    doctor.set_defaults(handler=_cmd_doctor)
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
