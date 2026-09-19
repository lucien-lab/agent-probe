# agent-probe

为 Coding Agent 提供**独立于应用日志**的系统审计、可解释的行为关联与受限执行控制：
回答“任务动了哪些文件、连了哪些网络、消耗了多少 token、是否违反策略，以及这些结论有多可靠”。

> ## 当前状态：M0 早期（只读能力检测可用，采集功能未实现）
>
> 仓库目前有：可安装的 src-layout 包、基于 `argparse` 的 CLI 入口、
> **`probe doctor` 的只读环境能力检测**（M0）、pytest 配置与行为测试。
>
> - `probe --version` 输出包版本。
> - `probe doctor [--json]` 检查 Linux/ARM64、BTF、tracefs、`sched_process_exec` tracepoint、
>   fentry/fexit 线索、BPF LSM、工具链（clang/bpftool/pkg-config/libbpf）、Python/OpenSSL 与 Docker。
>   结构化输出 + 明确退出码；**只读**，不安装软件、不修改系统配置；非 Linux 主机会给出
>   `unsupported` 结果而不是报错（因此 macOS 上退出码非零是预期结果）。
>
> 尚未实现：eBPF 探针、TLS/HTTP 协议重建、事件模型与事件账本、存储与索引、
> 关联引擎、审计规则与报告、Docker 映射、执行控制、Docker 镜像与 CI。
> 完整计划见 [`plan.md`](plan.md)，环境基线、退出码与 M0 验收证据清单见
> [`docs/00-env.md`](docs/00-env.md)。

### `probe doctor` 速览

```bash
probe doctor            # 人类可读报告（每项含 id/status/summary/evidence）
probe doctor --json     # 稳定 JSON（schema_version = 1）
```

状态语义：`pass`（线索满足） / `warn`（线索不完整，不阻塞） / `fail`（硬性前提缺失） /
`unsupported`（当前主机不适用）。退出码：`0` 必需项通过、`1` 必需项失败、
`2` 主机不受支持、`3` doctor 自身出错。BTF 可读**不代表**其它挂点可用，
`pass` 也不代表已完成实际 attach/阻断验证。

## 目标平台

- **采集目标：Linux（ARM64 为主，QEMU + 固定 Ubuntu 环境）**，依赖 eBPF：libbpf + CO-RE、
  uprobe/tracepoint、fentry/fexit、BPF LSM。挂点可用性需在 M0 实测确认，不做未经验证的承诺。
- macOS/Windows **仅作为 Linux VM 宿主**，不提供原生采集。
- `probe doctor` 在 macOS 上返回 `unsupported`（退出码 2）属于**预期正确结果**：
  当前开发机只是 VM 宿主，本仓库尚未在 Linux 中验证任何挂点或 LSM 阻断。

## 目录结构

```
.
├── plan.md                    # 四个月实施计划（勿在本任务中修改）
├── pyproject.toml             # setuptools 构建、probe 入口、pytest 配置
├── README.md
├── .gitignore
├── docs/
│   ├── 00-env.md              # M0 环境基线、doctor 契约与验收证据清单
│   └── delegation-progress.md
├── scripts/
│   └── setup-vm.sh            # 幂等环境脚本（--check-only / --apply）
├── src/
│   └── agent_probe/
│       ├── __init__.py        # 包元信息（__version__ 为版本单一来源）
│       ├── __main__.py        # python -m agent_probe 入口
│       ├── cli.py             # argparse CLI：--version 与 doctor
│       └── doctor.py          # M0 只读能力检测（可注入 Host，结构化输出）
└── tests/
    ├── conftest.py            # 共享夹具（子进程运行 CLI）
    ├── fake_host.py           # 内存 Host：构造 Linux 能力矩阵，不依赖宿主平台
    ├── test_cli.py            # CLI 行为测试
    ├── test_doctor.py         # doctor 检查/JSON schema/退出码测试
    └── test_package.py        # 包与 python -m 行为测试
```

## 开发环境与最小命令

Python >= 3.11，包名 `agent_probe`，命令名 `probe`。以下命令以 conda 环境为例
（把 `<env>` 替换为本地环境名，本仓库开发时使用 `ms_pointcloud_midterm`）：

```bash
# 推荐：离线/本地可编辑安装（不创建隔离构建环境、不解析依赖）
# 前提：当前环境已装有满足 pyproject.toml 中 [build-system] requires 的 setuptools
#       （本项目实测 pip 26.1.2 + setuptools 83.0.0；下限为 setuptools 64）
conda run -n <env> python -m pip install --no-build-isolation --no-deps -e .

# 运行测试
conda run -n <env> python -m pytest -q

# 版本与能力自检
conda run -n <env> python -m agent_probe --version
conda run -n <env> python -m agent_probe doctor --json

# （在仓库根目录、未安装时）可直接用源码运行：
PYTHONPATH=src conda run -n <env> python -m agent_probe doctor
```

### 环境脚本（不在自动验证中执行安装）

```bash
bash scripts/setup-vm.sh                # 只打印计划与影响（退出码 2，不修改任何东西）
bash scripts/setup-vm.sh --check-only   # 只读检查宿主/VM 是否满足固定清单
bash scripts/setup-vm.sh --apply        # 显式安装（幂等）；由人工在确认后运行
```

固定目标：Ubuntu 24.04.4 LTS（noble）arm64 + 包清单见脚本内常量，
版本矩阵、权限影响、QEMU/VM 边界与 M0 证据清单见 [`docs/00-env.md`](docs/00-env.md)。

未执行可编辑安装时也能直接运行测试：`pyproject.toml` 中的
`[tool.pytest.ini_options] pythonpath = ["src"]` 会把 `src/` 加入导入路径。

### 关于 `--no-deps` 与构建隔离（易误判）

- `--no-deps` **只**跳过 `[project.dependencies]` / extras 的解析与安装，
  **不会**阻止 pip 为 `[build-system] requires`（即 setuptools）创建隔离构建环境并从索引下载。
  因此单独使用 `pip install --no-deps -e .` 在无网络环境下仍会失败。
- 完全离线必须显式加上 `--no-build-isolation`，它让 pip 直接使用当前环境已有的 setuptools，
  不下载任何东西。前提条件是环境中的 setuptools 版本满足 `requires = ["setuptools>=64"]`；
  若环境过旧，pip 会直接报错，此时应先离线升级 setuptools。
- 需要 dev 依赖且允许联网时，可使用常规命令：
  `conda run -n <env> python -m pip install -e '.[dev]'`。

## 约定

- src-layout；源码位于 `src/agent_probe/`，测试位于 `tests/`，两者不混放。
- **不实现即不注册**：CLI 只暴露已实现的子命令，未实现的能力不得提供看似可用的入口。
- doctor 的检查逻辑必须通过 `Host` 协议访问系统，测试用 `tests/fake_host.py` 构造能力矩阵，
  不得依赖运行测试的宿主平台。
- 运行时依赖为空（`dependencies = []`）。新增依赖需说明其解决的具体问题、
  维护成本与可验证收益（见 `plan.md` 第 7 节）；Linux 侧工具链（libbpf、clang、bpftool）
  属于系统依赖，不通过 Python 包安装。
- 不修改 `plan.md` 中的计划口径；实现与计划有偏差时记录在文档中，而不是调整指标。

## 后续任务边界

按 `plan.md` 的 M0–M6 顺序推进。当前已完成 M0 的只读环境能力检测
（`probe doctor` + `scripts/setup-vm.sh` + `docs/00-env.md`）；M0 仍未完成的是
**VM 内实测**：Linux 挂点实际 attach、BPF LSM 启用与阻断验证、真实 TLS 调用点定位、
本地 TLS 测试服务与无探针性能基线。在完成这些实测前，不得声称任何挂点已验证可用。
