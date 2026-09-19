# agent-probe

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)](https://kernel.org/)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-00599C)](https://docs.kernel.org/bpf/)
[![Status](https://img.shields.io/badge/Status-Pre--alpha-orange)](https://github.com/lucien-lab/agent-probe)

`agent-probe` 是面向 Coding Agent 的 Linux 可观测性与策略分析工具集。它将低层执行证据组织为可审计记录，回答 Agent 尝试了什么、实际发生了什么、行为如何归因，以及是否满足既定策略。

项目遵循一条原则：**未知不等于通过**。缺失的 usage、未完整采集的数据、歧义归因和不支持的控制路径会被保留在报告中，而不会被悄然转为“正常”。

## 为什么需要 agent-probe

应用日志很有价值，但它由被观测的应用自身控制。`agent-probe` 提供独立的分析路径，可用于回答：

- 一个任务实际读取或修改了哪些文件？
- 连接了哪些目的地址，哪些模型调用消耗了 token？
- 哪些证据将系统事件关联到任务、工具或模型调用？
- 任务是否违反文件系统、敏感数据、网络或成本策略？
- 一条结论是事实、推断，还是证据不足？

其架构将采集、近似不可变的事件记录、关联、策略评估与执行控制分析分离，使报告可从源工件重算，也使不确定性可被检查。

## 当前能力

仓库包含已测试的 Python 核心与最小化原生 BPF LSM attach 探针：

| 范畴 | 已交付能力 |
| --- | --- |
| 环境发现 | `probe doctor` 对 Linux、BTF、tracefs、tracepoint、BPF LSM、工具链、Python/OpenSSL 与 Docker 前提进行只读检查。 |
| LLM 计账 | 离线 HTTP/1.1 分帧、chunked/gzip/SSE 解析、usage 状态处理、重试登记与版本化 `Decimal` 定价。 |
| 事件账本 | 版本化事件模型、追加式 JSONL 权威账本、可重建 SQLite 索引、重放、序列与丢失计数。 |
| 行为归因 | 证据图、外部和辅助两种关联模式、置信度/歧义传播，以及 Docker 任务到宿主机的映射抽象。 |
| 审计报告 | 受限 YAML 规则、确定性 finding、可重算汇总、证据解释，以及文本/JSON/独立 HTML 输出。 |
| 执行控制模型 | 明确的 audit/enforce 语义、受保护目录决策、操作支持矩阵与已记录盲区。 |
| 评估工具集 | 分类指标、Wilson 置信区间、性能摘要与可复现实验清单校验。 |
| 原生验证 | 小型 CO-RE/libbpf 程序验证可用 BPF LSM hook 可干净地 attach 与 detach，不执行策略。 |

采集管线的能力边界明确：当前尚无生产级 TLS uprobe 采集器、内核事件采集器或 BPF LSM 策略加载器。原生探针只证明可 attach；Python 执行控制模型不会阻断文件系统操作。相关影响见[范围与安全边界](#范围与安全边界)。

## 架构

```text
未来采集源                               已支持的离线输入
TLS 探针 / 内核事件 / 适配器  ------>    calls 工件 + JSONL 账本
                                                    |
                                                    v
                    事件校验、重放、丢失计数、SQLite 索引
                                                    |
                                                    v
        关联证据图 <--- 进程 / 任务 / 容器 / 辅助标记
                                                    |
                                                    v
       YAML 策略 ---> 确定性审计 finding ---> report / explain / HTML
                                                    |
                                                    v
                          控制支持分析与 BPF attach 验证
```

M2 JSONL 账本是权威数据格式。报告由原始账本、策略与可选 calls 工件重建，而非使用缓存汇总。

## 快速开始

Python 组件需要 Python 3.11+。原生 BPF 探针另需 Linux、BTF、clang、libbpf、libelf 与内核头文件。

```bash
# 本地可编辑安装，适合已配置完成的开发环境。
python -m pip install --no-build-isolation --no-deps -e .

# 运行完整测试。
python -m pytest -q

# 只读检查主机环境。
probe doctor
probe doctor --json
```

使用 Conda 开发：

```bash
conda run -n ms_pointcloud_midterm python -m pip install --no-build-isolation --no-deps -e .
conda run -n ms_pointcloud_midterm python -m pytest -q
```

`probe doctor` 为只读命令。在 macOS 和 Windows 上会返回 `unsupported`，因为这两个系统预期用作 Linux VM 宿主，而非直接运行采集器。

## 报告与证据解释

审计报告接收策略、权威 JSONL 事件账本，以及可选的版本化 calls 工件：

```bash
probe report \
  --policy /path/to/policy.yaml \
  --ledger /path/to/events.jsonl \
  --calls /path/to/calls.json \
  --format html \
  --output report.html

probe explain EVENT_ID \
  --policy /path/to/policy.yaml \
  --ledger /path/to/events.jsonl \
  --calls /path/to/calls.json
```

`probe report` 支持 `text`、`json` 与独立 `html` 渲染器。`probe explain` 可从 finding 回溯至原始事件，并明确结果属于已验证违规、通过，还是证据不足。

受限 YAML 策略格式支持四类规则：

- 禁止的文件系统修改；
- 对敏感路径的实际读取；
- 网络活动的目的地址白名单；
- 估算成本上限。

规则评估的是已观测到的结果，而非仅系统调用尝试。例如，失败的写入尝试不能证明文件被修改；缺失 token usage 也不能证明成本限制被满足。

规则、报告与渲染的详细语义见 [docs/04-audit.md](docs/04-audit.md)。

## 原生 BPF LSM attach 探针

该探针被刻意保持为小型且安全的程序：其 `file_permission` hook 始终返回 `0`，attach 后立即 detach。它用于验证重要环境前提，不安装持久策略。

```bash
scripts/build-lsm-attach-probe.sh
sudo bpf/lsm_attach_probe/lsm_attach_probe
```

第二个命令需要提升权限并会加载一个短生命周期 BPF 程序，应仅在预期的 Linux 测试 VM 中执行。构建与清理细节见 [docs/05-bpf-lsm-attach-probe.md](docs/05-bpf-lsm-attach-probe.md)。

## 仓库结构

```text
src/agent_probe/
  audit/          策略加载、评估、finding、报告与渲染
  container/      Docker 任务/容器/PID/cgroup/挂载视图映射契约
  correlate/      证据图与归因算法
  enforce/        文件系统控制模型与支持矩阵
  events/         事件模式、账本、索引、重放与一致性检查
  evaluation/     指标、置信区间、性能摘要与实验清单
  llm/            HTTP/SSE 重建、usage、重试与定价
  doctor.py       只读环境能力发现
bpf/              CO-RE/libbpf BPF LSM attach 探针
docs/             设计契约、操作流程与评估指南
tests/            确定性单元与集成测试
scripts/          VM 配置与原生探针构建辅助脚本
```

## 开发与验证

项目采用 `src/` 布局与 pytest。测试使用确定性字节夹具、内存 Host 抽象、fake 容器查询和临时工件；不需要 Docker、网络连接或 root 权限。

```bash
conda run -n ms_pointcloud_midterm python -m pytest -q
conda run -n ms_pointcloud_midterm python -m agent_probe --version
conda run -n ms_pointcloud_midterm python -m agent_probe doctor --json
```

VM 配置脚本会明确展示其影响范围：

```bash
bash scripts/setup-vm.sh              # 仅输出将执行的变更
bash scripts/setup-vm.sh --check-only # 只读前提检查
bash scripts/setup-vm.sh --apply      # 显式进行软件包与配置变更
```

新增运行时依赖前，应记录它解决的运行问题、维护成本与可验证收益。Python 运行时依赖刻意保持为空；原生工具链由操作系统负责管理。

## 范围与安全边界

`agent-probe` 当前提供离线分析基础组件，而非完整沙箱或可普遍部署的监控 Agent。

- 可信计算基包括宿主内核、root 与采集器管理员；root 或内核被攻破不在范围内。
- 当前 LLM 重建核心不支持 HTTP/2、HTTP/3、静态 TLS 及未知提供方载荷。
- `mmap`、`io_uring`、继承文件描述符、符号链接/硬链接边界情形与容器挂载视图尚未由完整内核强制执行实现覆盖。
- 网络与成本策略是报告控制，而不是网络级阻断或账单保证。
- 现有指标与实验清单支持评估工作，但不能替代真实 Agent 基准运行。

相关设计文档：

- [环境与 doctor 契约](docs/00-env.md)
- [LLM 重建与计账](docs/01-llm.md)
- [事件账本语义](docs/02-event-ledger.md)
- [关联与容器映射](docs/03-correlation.md)
- [审计策略与报告模型](docs/04-audit.md)
- [执行控制模型与 BPF 验证](docs/05-enforcement.md)
- [评估协议](docs/evaluation.md)

## 参与贡献

贡献应保持项目的证据模型：

1. 为正常结果、违规或错误路径，以及适用时的证据不足情况添加确定性测试。
2. 在模式与报告中始终区分事实、推断和不可用数据。
3. 未实现且未经测试的能力不得作为可用 CLI 命令暴露。
4. 对原生代码记录平台假设、权限要求、采集缺口与清理行为。

涉及大规模采集器或策略引擎集成时，请先创建 issue，以便先对事件语义与兼容性边界达成一致。

## 许可证

仓库目前尚未包含许可证文件。在项目所有者添加许可证前，保留所有权利，未授权外部再分发。
