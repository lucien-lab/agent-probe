# agent-probe

为 Coding Agent 提供**独立于应用日志**的系统审计、可解释的行为关联与受限执行控制：
回答“任务动了哪些文件、连了哪些网络、消耗了多少 token、是否违反策略，以及这些结论有多可靠”。

> ## 当前状态：工程骨架（skeleton），无可用功能
>
> 仓库目前**只有**：可安装的 src-layout 包、基于 `argparse` 的 CLI 入口、pytest 配置与行为测试。
>
> - `probe --version` 输出包版本。
> - `probe doctor` 只打印占位说明，**不执行任何环境检查**，也不修改环境。
>
> 尚未实现：eBPF 探针、TLS/HTTP 协议重建、事件模型与事件账本、存储与索引、
> 关联引擎、审计规则与报告、Docker 映射、执行控制、Docker 镜像与 CI。
> 完整计划、里程碑与验收口径见 [`plan.md`](plan.md)。

## 目标平台

- **采集目标：Linux（ARM64 为主，QEMU + 固定 Ubuntu 环境）**，依赖 eBPF：libbpf + CO-RE、
  uprobe/tracepoint、fentry/fexit、BPF LSM。挂点可用性需在 M0 实测确认，不做未经验证的承诺。
- macOS/Windows **仅作为 Linux VM 宿主**，不提供原生采集。
- 当前骨架是纯 Python 代码（`--version` / `doctor` 占位），因此在任意平台都能安装运行，
  但这**不代表**具备任何采集或审计能力。

## 目录结构

```
.
├── plan.md                    # 四个月实施计划（勿在骨架任务中修改）
├── pyproject.toml             # setuptools 构建、probe 入口、pytest 配置
├── README.md
├── .gitignore
├── src/
│   └── agent_probe/
│       ├── __init__.py        # 包元信息（__version__ 为版本单一来源）
│       ├── __main__.py        # python -m agent_probe 入口
│       └── cli.py             # argparse CLI：--version 与 doctor 占位
└── tests/
    ├── conftest.py            # 共享夹具（子进程运行 CLI）
    ├── test_cli.py            # CLI 行为测试
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

# 版本与占位自检
conda run -n <env> python -m agent_probe --version
conda run -n <env> probe doctor
```

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
- **不实现即不注册**：CLI 只暴露已实现的子命令，占位命令必须明确说明未实现，
  避免出现看似可用的业务入口。
- 骨架阶段运行时依赖为空（`dependencies = []`）。新增依赖需说明其解决的具体问题、
  维护成本与可验证收益（见 `plan.md` 第 7 节）；Linux 侧工具链（libbpf、clang、bpftool）
  属于系统依赖，不通过 Python 包安装。
- 不修改 `plan.md` 中的计划口径；实现与计划有偏差时记录在文档中，而不是调整指标。

## 后续任务边界

按 `plan.md` 的 M0–M6 顺序推进。骨架之后的第一批工作属于 M0：
虚拟机与工具链固定、BTF/tracepoint/fentry-fexit/BPF LSM 能力验证、
真实 TLS 调用点定位，以及 `probe doctor` 的实际检查实现。
