# 03b · M3 Docker 任务映射（库层实现说明）

> 状态：M3 的 **Docker 任务映射库**已实现（标签 → 容器 → 宿主 PID/cgroup → 挂载视图）。
> 关联引擎（证据图、置信度、外部/辅助两种模式）是 T05 的 `agent_probe.correlate`，
> 与本文档描述的库按**结构化协议**解耦：T05 可以只依赖冻结的公开 API，
> **不 import** `agent_probe.container`（见 §11）。
>
> 代码：`src/agent_probe/container/`；测试：`tests/container/`（288 个用例）。
> 根包 `agent_probe.__init__` 仍只导出 `__version__`；本能力通过
> `agent_probe.container` 子包使用，**不接入 CLI**。

---

## 1. 前提与信任模型

### 1.1 容器不是 agent 的子进程

**容器由 Docker daemon 创建。** `docker run` 只是向 daemon 发一条 API 请求，
真正的容器进程由 `dockerd`（或 containerd → runc）fork/exec，其宿主进程
**不在** agent 的进程树里。由此得出本模块的硬规则：

* **不允许**用进程树/父进程链推断"哪个容器属于哪个任务"；
* **不允许**把"最近创建的容器""最近退出的容器"直接当成唯一映射；
* 允许使用的真值只有三样：容器 **label 值**、`docker inspect` 的
  **显式字段**（状态/宿主 PID/挂载/时间）、调用方给出的**时间窗**。

这三样都不足以判定时，结果必须显式表达不确定性（`AMBIGUOUS`），
而不是猜一个"最像"的容器。

### 1.2 本库只做解析与映射

* 不执行 `docker exec`/`docker run` 等写操作（`DockerCli` 只跑
  `docker ps -a` 与 `docker inspect`）；只有被显式调用时才执行 docker。
* 不采集 eBPF、不读事件账本、不做关联推理、不做因果判断。
* 不访问网络；不新增第三方依赖（仅 Python 标准库）。

---

## 2. 公开 API（冻结名称）

| 名称 | 类型 | 职责 |
|---|---|---|
| `ContainerQuery` | Protocol | 查询端口：`list_container_ids()` / `inspect(container_id)` |
| `DockerCli` | class | `ContainerQuery` 的真实实现（`docker ps -a` / `docker inspect`，可注入 runner） |
| `ContainerState` | StrEnum | `created` / `running` / `exited` / `paused` / `unknown` |
| `MountType` | StrEnum | `bind` / `volume` / `tmpfs` / `other` |
| `ContainerMount` | frozen dataclass | `mount_type`、`source`、`destination`、`read_write`、`raw_type` |
| `ContainerInfo` | frozen dataclass | 容器 ID、名、labels、state、`host_pid`、`cgroup_id`、`cgroup_path`、三个 wall-clock ns |
| `MappingOutcome` | StrEnum | `mapped` / `ambiguous` / `unmapped` / `error` |
| `ContainerMapping` | frozen dataclass | outcome、task_label、mapping、candidates、mounts、evidence、reason、observed_monotonic_ns |
| `MountResolver` | class | 容器内路径 ↔ 宿主路径双向解析（不可映射返回 `None`） |
| `ContainerTaskMapper` | class | `map_label()` / `map_labels()` / `resolver_for()` |
| `ContainerQueryError` 等 | 异常 | 见 `src/agent_probe/container/errors.py` |

辅助入口（非冻结、便于离线使用）：`parse_inspect()`、`parse_mounts()`、
`ContainerInfo.from_inspect()`、`ContainerMount.from_inspect()`、
`validate_container_id()`、`parse_container_state()`、`parse_rfc3339_ns()`、
`canonical_json()`、`ProcCgroupReader`、`SubprocessRunner`。

所有 dataclass 都提供 `to_dict()` / `from_dict()`（JSON 可序列化、字段顺序固定），
`ContainerMapping` 另有 `to_json()`（规范化字节，见 §7.3）。

---

## 3. 数据模型与"缺失"语义

### 3.1 `ContainerInfo`

| 字段 | 类型 | 缺失时的值 | 说明 |
|---|---|---|---|
| `container_id` | str | 必填 | 12 或 64 位十六进制（统一小写）；形状非法直接报错 |
| `name` | str | 必填 | docker 的 `Name` 带前导 `/`，本层去掉单个前导 `/` |
| `labels` | Mapping[str, str] | 必填（可空映射） | 按 key 排序并冻结；空串值是合法数据 |
| `state` | ContainerState | 必填 | 未知/缺失字符串 → `unknown`（**不是** running） |
| `host_pid` | int \| None | `None` | 容器主进程的**宿主** PID；docker 的 `Pid=0` 记为 `None`，构造器**拒绝** 0 |
| `cgroup_id` | int \| None | `None` | cgroupfs inode（`bpf_get_current_cgroup_id()`）；`None` ≠ "没有 cgroup" |
| `cgroup_path` | str \| None | `None` | cgroupfs 绝对路径；`None` ≠ "根 cgroup" |
| `created_at_ns` | int \| None | `None` | Unix epoch 纳秒；docker 零时间（`0001-01-01T00:00:00Z`）→ `None` |
| `started_at_ns` | int \| None | `None` | 同上 |
| `finished_at_ns` | int \| None | `None` | 同上；仍在运行时为 docker 零时间 → `None` |

**不伪造规则（写死在实现里）**

* `host_pid` / `cgroup_id` 拿不到就是 `None`，**绝不**填 0、-1 或"猜测值"；
  `ContainerInfo(host_pid=0)` 与 `ContainerInfo(cgroup_id=0)` 会直接抛
  `ContainerValidationError`（防的是上游把哨兵值当真实数据传进来）。
* 缺失的字段在解析时都会产生一条 **note** 进入 `ContainerMapping.evidence`
  （"State.Pid=0 表示没有宿主进程"、"state=running 但 State.Pid 缺失"、
  "CgroupID=0 不是合法标识"…），因此"缺失"在报告里可见。
* 时间戳必须带时区；小数字段最多 9 位，按**纳秒**保留精度（不经过 float）。
* 三个时间之间的先后**不做校验**：它们都来自 daemon 时钟，可能被 NTP/手动调整
  影响，硬校验会把真实数据判成非法。报告里不要把 `created_at_ns` 当作
  "事件时间轴"使用。

### 3.2 `ContainerMount`

| 字段 | 说明 |
|---|---|
| `mount_type` | 规范化类型：`bind` / `volume` / `tmpfs` / `other`（未知 `Type` → `other`） |
| `source` | **宿主**路径；空串与缺失都记为 `None`（不伪造路径）；要求是规范化绝对路径 |
| `destination` | **容器内**绝对路径；要求规范化（无重复/结尾斜杠、无 `.`/`..`） |
| `read_write` | docker 的 `RW`；**必填**，缺失即报错（不默认成只读或读写） |
| `raw_type` | docker 原始 `Type` 字符串，原样保留（解释"为什么折叠成 other"） |

挂载项解析时允许 docker 的书写差异（`/data//x/` → `/data/x`），
但相对路径与含 `..` 的路径一律报错：不访问文件系统就无法判定其真实指向。

单容器挂载数量上限 `MAX_MOUNTS = 1024`，**超限报错而不是截断**
（截断挂载会让路径解析给出错误答案）。

---

## 4. 映射算法（含竞态判定规则）

### 4.1 步骤

```
map_label(label, created_after_ns=None, created_before_ns=None, observed_monotonic_ns=None)
  1. 校验 label / 时间窗 / 观测时刻（非法输入直接抛 ContainerValidationError）
  2. container_ids = query.list_container_ids()          # 含已退出容器
  3. 对每个 ID（按 ID 升序，保证 evidence 与报告可复现）inspect + parse_inspect
  4. matched = labels[label_key] == label 的容器         # 严格相等，不做模糊匹配
  5. 逐个做时间窗判定（见 §4.2），得到候选 / 被排除 / 不确定
  6. 候选按 container_id 升序，按 max_candidates 截断（截断事实写入 evidence）
  7. 依据候选数量与不确定标注给出 outcome（见 §4.3）
```

`list_container_ids()` 使用 `docker ps -a --no-trunc`：**已退出容器必须可见**，
否则短命任务在映射时就没有真值了。由于 `ContainerQuery` 没有标签过滤接口，
实现需要 inspect 全部容器再按 label 过滤（O(N) 次 docker 调用）；
这是刻意的取舍（先保证正确与完整），见 §9 的性能说明。

### 4.2 时间窗判定（§"竞态与短命任务"）

调用方给出的 `container_created_after_ns` / `container_created_before_ns` 是
**闭区间**创建时间窗。判定规则（实现见 `mapper._evaluate_window`）：

| 情形 | 结果 | 理由 |
|---|---|---|
| 未给出窗口 | 候选，无标注 | 调用方没有约束 |
| `created_at_ns` 未知（`None`） | 候选 + **不确定标注** | 无法验证窗口；丢弃会丢掉真值，假确定更糟 |
| `created_at_ns > before` | **排除** | 创建晚于窗口上界，不可能属于该窗口 |
| `created_at_ns < after`，且 `finished_at_ns < after` | **排除** | 窗口开始前就已结束 |
| `created_at_ns < after`，结束时间未知或 ≥ `after` | 候选 + **不确定标注** | 创建约束不满足，但容器跨越窗口 |
| 其余（`after ≤ created ≤ before`） | 候选，无标注 | 约束验证通过 |

要点：

* **不丢弃已退出容器**：同一 label 的容器即使 `state=exited`，只要在窗口内
  （创建时间命中，或无法证明它已结束）就进入候选，`state` 如实呈现。
* **不做"取最近"**：窗口内多个候选一律 `AMBIGUOUS`，绝不按时间排序取第一个。
* **被排除不是静默丢弃**：每个被排除的容器都会在 `evidence` 里留下
  "排除容器 `<ID>`：created_at_ns=… 晚于窗口上界/就已结束" 的记录。
* **短命任务**：`created/started/finished` 落在同一秒（甚至同一纳秒）时，
  纳秒精度必须保留，窗口比较按纳秒进行（测试
  `test_short_lived_container_same_second_*`）。
* 窗口是闭区间：`created_at_ns` 恰好等于端点时命中
  （`test_short_lived_container_same_second_window_boundary_is_inclusive`）。

### 4.3 outcome 判定

| outcome | 条件 | `mapping` | `candidates` | `mounts` | `reason` |
|---|---|---|---|---|---|
| `mapped` | 恰好 1 个候选且**没有**不确定标注 | 该容器 | `(mapping,)` | 该容器的挂载视图 | 必须为 `None` |
| `ambiguous` | 候选 ≥ 2，或唯一候选带不确定标注 | `None` | 全部候选（受截断） | `()` | 必填 |
| `unmapped` | 没有候选 | `None` | `()` | `()` | 必填 |
| `error` | 查询/解析任一步失败 | `None` | `()` | `()` | 必填（含失败步骤与容器 ID） |

`AMBIGUOUS` 的两种子情形由 `reason` 区分：

* 多候选：`标签 'agent-probe.task'='run-7' 有 2 个候选容器，无法唯一确定（不做"取最近"猜测）`
* 唯一候选但约束无法确定：`唯一候选 <ID> 的时间约束无法验证或与调用方窗口不一致：created_at_ns 缺失…`

这些不变式由 `ContainerMapping.__post_init__` **强制校验**：
`outcome=mapped` 必须有 `mapping` 且不得有 `reason`；
`ambiguous/unmapped/error` 不得有 `mapping`/`mounts`，且必须有 `reason`。
换句话说，"拿不准"无法被表示成"确定"。

**ERROR 覆盖的失败**（全部显式，绝不静默成功）：

* `list_container_ids()` 抛错（daemon 不可用、输出含非法 ID、…）；
* 任意一个容器的 `inspect()` 抛错（不存在、超时、非 JSON、字段缺失）；
* `inspect` 返回的容器 ID 与请求不一致（可能查错容器）；
* 任意解析失败（`inspect` 缺 `State`/`Mounts`、挂载路径非法、labels 类型非法…）。

只要有一个容器无法判定，就返回 ERROR：不能因为"大部分容器都查到了"而
给出一个候选集合不完整的映射。

---

## 5. 挂载视图与目录边界

`MountResolver` 只做**纯词法**的前缀映射，不访问文件系统、不解符号链接。

### 5.1 规则

| 规则 | 说明 |
|---|---|
| 目录边界匹配 | `/data` 匹配 `/data`、`/data/x`；**不匹配** `/database` |
| 最长 destination 优先 | `/data` 与 `/data/special` 同时挂载时，`/data/special/x` 走后者（更深的挂载覆盖更浅的） |
| 同级冲突不猜测 | 两个挂载的 destination 相同（或 source 相同）时返回 `None` + "无法唯一确定"，**不按顺序取第一个** |
| 类型支持 | `bind`/`volume` 可映射到宿主路径；`tmpfs`（内存，无宿主路径）与 `other`（npipe/cluster…语义未知）返回 `None` 并说明 |
| `source` 缺失 | 返回 `None` + "该挂载没有宿主 source" |
| 路径清理 | 查询路径折叠重复 `/`、去掉结尾 `/` 与 `.` 分量 |
| 相对路径 / `..` | 直接返回 `None` + 原因（不知道 cwd、词法 `..` 在符号链接下不可靠） |
| 双向 | `container_to_host()`（别名 `to_host`）与 `host_to_container()`（别名 `to_container`） |
| 证据 | 每次解析都在 `resolver.evidence` 里记下"命中哪个挂载 → 结果"或"为什么映射不到"，条数有上限 |

### 5.2 示例

```python
resolver = MountResolver([
    ContainerMount(MountType.BIND, "/host/data", "/data", True, "bind"),
    ContainerMount(MountType.VOLUME, "/var/lib/docker/volumes/t/_data", "/work", True, "volume"),
])
resolver.to_host("/data/report.json")            # '/host/data/report.json'
resolver.to_host("/database/x")                  # None（目录边界）
resolver.to_container("/host/data/a.txt")        # '/data/a.txt'
resolver.to_container(resolver.to_host("/data/a.txt"))  # '/data/a.txt'（round-trip）
```

### 5.3 典型获取路径

`mapper.resolver_for(mapping)` 只在 `outcome == mapped` 时可用
（否则抛 `ContainerValidationError`）：没有唯一容器就没有挂载视图。

---

## 6. 查询层

### 6.1 `ContainerQuery`（端口）

```python
class ContainerQuery(Protocol):
    def list_container_ids(self) -> tuple[str, ...]: ...        # 含已退出容器
    def inspect(self, container_id: str) -> Mapping[str, Any]: ...  # 等价 `docker inspect <id>` 的 JSON 对象
```

`inspect()` 的返回值可以携带**可选扩展键**（标准 `docker inspect` 不提供）：

| 扩展键 | 含义 |
|---|---|
| `CgroupPath` | cgroupfs 绝对路径 |
| `CgroupID` | cgroupfs inode（cgroup id） |
| `CgroupProbeNote` | cgroup 读取过程的说明（失败原因等），会进入 evidence |

### 6.2 `DockerCli`

* 命令固定为 `docker ps -a --no-trunc --format {{.ID}}` 与 `docker inspect <id>`；
  `argv` 直接传给子进程，不经 shell。
* **可注入 runner**：`runner(argv) -> (returncode, stdout, stderr)` 或
  `RunnerResult`。测试注入 fake 即覆盖全部失败路径，**不执行真实 docker**。
* **失败即失败**：非零退出、`returncode=None`（超时/无法启动）、stdout 不是 JSON、
  JSON 不是"单个容器对象"（空数组 → `ContainerNotFoundError`）、必需字段缺失、
  返回 ID 与请求不一致——一律抛 `ContainerQueryError`（或其子类）。
* **自定义 `ContainerQuery` 的失败契约**：实现必须抛 `ContainerQueryError`。
  `ContainerTaskMapper` 只把 `ContainerError` 子类转为 `outcome=ERROR`；
  其他异常原样向上传播（fail-loud），**不会**被降级成 `UNMAPPED`——
  "查询失败"与"确实没有匹配容器"必须能区分开。
* `DockerCli(query=upstream)` 可用于**委托**：把别的后端（cri/containerd/mock）
  包装成同一接口；此时不执行 docker。`query` 与 `runner` 互斥。
* **cgroup 增强是显式的**：默认 `cgroup_reader=None`，`inspect()` 的输出与
  `docker inspect` 完全一致。需要宿主 PID → cgroup 映射时显式注入：

  ```python
  cli = DockerCli(cgroup_reader=ProcCgroupReader(proc_root="/proc",
                                                cgroup_root="/sys/fs/cgroup"))
  ```

  `ProcCgroupReader` 读 `/proc/<pid>/cgroup`（v2 取 `0::` 行；v1 按
  `name=systemd` → `pids` → 首行选择并说明），再用 `os.stat()` 取 cgroupfs inode
  作为 `cgroup_id`。读不到就是 `None` + note，**不抛异常、不填 0**。
  注意 `pid` 必须是**宿主命名空间**的 PID；容器内进程可能被移到更深层子 cgroup，
  本模块只报告容器主进程所在位置。

### 6.3 `SubprocessRunner`

默认 runner：`subprocess.run(argv, capture_output=True, timeout=…)`；
超时抛 `ContainerTimeoutError`（**不是**"空结果"），无法启动抛
`ContainerQueryError`。它可以用任意 argv 单独测试（例如 `sys.executable`），
因此超时/失败路径无需 docker 也能验证。

---

## 7. 有界性、确定性与序列化

### 7.1 有界性

| 上限 | 值 | 超限行为 |
|---|---|---|
| `max_candidates` | 默认 64，硬上界 4096 | 候选按 `container_id` 升序截断，截断事实写入 evidence 与 reason |
| `MAX_EVIDENCE_ITEMS` | 128 | 只保留前 128 条 + 一条"已截断"提示 |
| `MAX_RESOLVER_EVIDENCE` | 64 | 同上（解析器自己的 evidence） |
| `MAX_MOUNTS` | 1024 | 报错（不截断） |
| `MAX_LABELS` | 256 | 报错 |
| `MAX_TEXT_BYTES` / `MAX_PATH_BYTES` | 4096 | 报错 |
| `MAX_CGROUP_LINES` | 64 | 只解析前 64 行 |

候选截断是**保留 `container_id` 最小的前 N 个**：与 docker 的返回顺序无关，
因此同一真值集合的报告可复现。被截掉的候选依然存在于系统里，
evidence 会明确写出"未列出的候选仍然存在"。

### 7.2 确定性

* 容器扫描顺序、候选顺序都按 `container_id` 升序；
* evidence 的构造顺序固定（头信息 → 每个容器的解析说明（按 ID）→ 计数 → 命中
  统计 → 排除/不确定/候选说明（按 ID）→ 截断提示）；
* labels 在构造时按 key 排序。

因此同一真值集合（即使 docker 返回顺序不同）得到**字节一致**的
`ContainerMapping.to_json()`。

### 7.3 序列化

`canonical_json` 与事件账本同规则：`sort_keys=True`、紧凑分隔符
（`,`/`:`）、`ensure_ascii=False`、`allow_nan=False`。
`from_dict()` 是**严格**的：缺字段报错（未知值必须显式写 `null`），未知字段报错。
`ContainerMapping.to_dict()` 的顶层键顺序固定为
`outcome / task_label / mapping / candidates / mounts / evidence / reason /
observed_monotonic_ns`。

### 7.4 schema 演进

本模块没有独立的 schema 版本号（映射结果是**派生物**，可从真值重新计算）。
兼容性规则：

* 新增可选字段时同步更新 `ContainerInfo.FIELDS` / `to_dict` / `from_dict`
  与本文档 §3；
* `from_dict` 默认拒绝未知字段：读比当前实现更新的报告需要显式代码改动，
  而不是静默丢弃；
* `ContainerState` / `MountType` / `MappingOutcome` 的枚举值增删属于不兼容变更，
  必须同时更新本文档与测试。

---

## 8. wall-clock 与 monotonic 的限制

映射结果里有两类**不可互换**的时间：

| 字段 | 时钟 | 用途 | 限制 |
|---|---|---|---|
| `ContainerInfo.created_at_ns` / `started_at_ns` / `finished_at_ns` | wall clock（docker daemon 的 RFC3339） | 与调用方时间窗比较、跨机器大致对齐 | 可被 NTP/手动调时影响；可能与真实顺序不一致；同一秒内的先后只能靠纳秒 |
| `ContainerMapping.observed_monotonic_ns` | `CLOCK_MONOTONIC` | 记录"这次映射是什么时候做的"、报告内排序 | 只在**同一 boot** 内有效，跨重启/跨机器不可比较 |

因此：

* 不要拿 `observed_monotonic_ns` 与 `created_at_ns` 相减（不同时钟基）；
* 时间窗过滤用的是 wall clock，与事件账本的 `monotonic_ns` 属于不同时间轴，
  跨轴关联只能做"近似时间窗"（M3/T05 的职责，不是本层承诺）；
* 容器时间来自**另一个进程**（daemon）的时钟读取点，与探针在同一机器上仍可能有
  毫秒级偏差；短命任务的窗口边界不要收得比这个偏差更紧。

---

## 9. 支持 / 不支持矩阵

| 能力 | 状态 | 说明 |
|---|---|---|
| 标签 → 容器唯一匹配 | ✅ | `label_key` 严格相等；空值不匹配非空查询 |
| 同标签多容器 → 歧义（列出全部候选） | ✅ | 候选完整性 + 排序 + 截断证据 |
| 状态解析 `created/running/exited/paused` | ✅ | 未知/缺失 → `unknown` + 说明 |
| 宿主 PID（`State.Pid`） | ✅ | `0`/缺失 → `None`，绝不伪造 |
| cgroup 路径 / cgroup id | ⚠️ 显式增强 | 标准 `docker inspect` 不提供；需注入 `ProcCgroupReader`（读 `/proc/<pid>/cgroup` + `stat` inode） |
| 挂载解析 bind/volume/tmpfs/other | ✅ | 未知 `Type` → `other`（原始串保留在 `raw_type`） |
| 容器内 ↔ 宿主路径双向解析 | ✅ | 纯词法；目录边界 & 最长前缀；不可映射返回 `None` |
| 覆盖只读挂载 | ✅ | `read_write` 如实呈现；解析不受 rw 影响 |
| 已退出/短命容器进入候选 | ✅ | `docker ps -a` + 时间窗规则 |
| 时间窗不一致 → 显式不确定 | ✅ | 唯一候选带标注时降级为 `ambiguous` |
| 序列化 round-trip / 字节可复现 | ✅ | 严格 `from_dict` + `canonical_json` |
| 离线可测（无 docker/网络/root） | ✅ | 注入 `ContainerQuery` / runner / cgroup reader（fake + `tmp_path`） |
| **进程树/父进程推断** | ❌ 明确不支持 | 容器不是 agent 的子进程，推断没有依据 |
| **"最近创建/最近退出"当唯一映射** | ❌ 明确不支持 | 只做窗口过滤，不做排序取首 |
| 符号链接 / `..` 的真实解析 | ❌ 不支持 | 纯词法；含 `..` 的查询路径直接返回 `None` |
| 宿主路径是否存在/可读 | ❌ 不检查 | 映射是命名空间前缀映射，不是文件系统校验 |
| 容器内 PID（PID namespace）→ 宿主 PID | ❌ 不支持 | 只用 `docker inspect` 给出的宿主 PID |
| 跨主机 / 远程 daemon 的容器 | ⚠️ 仅当 `inspect` 真值可靠 | 远程 `host_pid`/cgroup 是**对端**宿主的值，与本地事件不可直接比较 |
| 非 Docker 运行时（containerd/CRI/k8s） | ⚠️ 需适配 | 通过 `ContainerQuery` 端口或 `DockerCli(query=…)` 委托接入 |
| 关联引擎（证据图/置信度/因果） | ❌ 不在本层 | T05 `agent_probe.correlate`（不 import 本包） |
| eBPF 采集、事件账本读取、CLI 子命令 | ❌ 不在本层 | 分别属于 M2 采集侧与 M4 |

---

## 10. 验收方法

### 10.1 门禁命令（离线，指定 Conda 环境）

```bash
conda run -n ms_pointcloud_midterm python -m pytest tests/container -q   # 本任务范围
conda run -n ms_pointcloud_midterm python -m pytest -q                   # 全仓库回归
conda run -n ms_pointcloud_midterm python -m compileall -q src/agent_probe/container
```

测试全部离线：不执行真实 docker、不联网、不要求 root/Linux 平台；
文件系统相关用例（`ProcCgroupReader`）只用 pytest 的 `tmp_path`。

### 10.2 每个测试文件证明什么

| 文件 | 覆盖的验收点 |
|---|---|
| `tests/container/test_container_model.py` | 容器 ID 形状（12/64 位十六进制、非十六进制、长度非法、非字符串）；state 解析（四种已知 + `restarting/removing/dead/空串` → `unknown`、缺失 → `unknown`）；纳秒精度与带时区的 RFC3339 解析、零时间 → `None`、非法日期拒绝；`host_pid=0` → `null`、构造器拒绝 0、缺失不伪造；cgroup 扩展键（含 `CgroupID=0`、空 `CgroupPath`）；labels 缺失/null/非字符串/排序/冻结/上限；挂载项解析（Type 折叠、空 Source、重复与结尾斜杠、相对路径与 `..` 拒绝、缺 `RW`）；inspect 必需键缺失报错；`to_dict/from_dict` round-trip、未知字段拒绝、`canonical_json` 确定性与紧凑性；`ContainerMapping` 四种 outcome 的不变式 |
| `tests/container/test_container_mounts.py` | 路径原语（规范化、目录边界、`join_path`、clean 判定）；bind/volume/tmpfs/other 的映射与不可映射原因；只读挂载；`/data` vs `/database`；最长 destination/source 优先；同级冲突 → `None`（不取第一个）；容器内↔宿主 round-trip；空挂载列表；非字符串/相对/`..` 路径 → `None` + 原因；evidence 上限；`resolver_for` 只接受 `mapped` |
| `tests/container/test_container_query.py` | `DockerCli` 注入 runner：`ps` 解析/去重/空输出/非法 ID/非零退出/`returncode=None`/runner 返回形状非法；`inspect` 正常、短 ID 前缀校验、裸对象、ID 不一致、空数组 → `ContainerNotFoundError`、多对象、非 JSON、空 stdout、标量 JSON、非零退出、缺 `State`、缺 `Config` 不算错、非法 ID 参数在调用前被拒；超时与 runner 异常传播；cgroup 增强（注入/不注入/Null/Pid=0 不调用）；`ProcCgroupReader` 的 v2/v1/缺失/不可解析/stat 失败/根 cgroup（用 `tmp_path`）；委托模式与构造校验；`SubprocessRunner` 的成功/非零退出/超时/无法启动/空 argv |
| `tests/container/test_container_mapper.py` | 四种 outcome；MAPPED 带挂载与 resolver；已退出容器在窗口内仍为候选；短命容器同秒（含窗口边界与窗口之外）；UNMAPPED 的多因（无容器、无标签、空标签值、窗口排除）；AMBIGUOUS 的候选完整性与排序无关性、`max_candidates` 截断证据、唯一候选但 `created_at` 缺失/创建早于窗口 → `ambiguous`；ERROR 的多因（list 失败、inspect 失败、缺字段、ID 不一致、非法 ID）；缺失值不伪造 + evidence（`host_pid=null`、`state=unknown`、cgroup 缺失、`Pid=0`）；evidence 上限；时间窗参数校验；自定义 `label_key`；`max_candidates`/`label_key`/query 契约校验；`map_labels` 顺序与共享观测时刻；mapping round-trip 与 JSON 确定性 |

### 10.3 端到端手工核验（库层，不依赖 CLI，也不执行真实 docker）

```python
from agent_probe.container import ContainerTaskMapper, DockerCli

FULL_ID = "ab" * 32
INSPECT = (
    '[{"Id": "%s", "Name": "/probe-run-7", "Created": "2023-11-14T22:13:20.123456789Z",'
    ' "State": {"Status": "exited", "Pid": 0,'
    '           "StartedAt": "2023-11-14T22:13:21.000000001Z",'
    '           "FinishedAt": "2023-11-14T22:13:25.000000002Z"},'
    ' "Config": {"Labels": {"agent-probe.task": "run-7"}},'
    ' "Mounts": [{"Type": "bind", "Source": "/srv/agent-probe/run-7",'
    '              "Destination": "/work", "RW": true}]}]'
) % FULL_ID

def runner(argv):                      # 注入 runner：不执行真实 docker
    return (0, FULL_ID + "\n", "") if argv[1] == "ps" else (0, INSPECT, "")

mapper = ContainerTaskMapper(DockerCli(runner=runner))
mapping = mapper.map_label("run-7", observed_monotonic_ns=12345)
print(mapping.outcome, mapping.reason)                  # mapped None
print(mapping.mapping.host_pid, mapping.mapping.cgroup_id)   # None None
print(mapper.resolver_for(mapping).to_host("/work/a.txt"))
# /srv/agent-probe/run-7/a.txt
print(mapper.resolver_for(mapping).to_host("/worker"))   # None（目录边界）
for line in mapping.evidence:
    print("-", line)
```

判定标准：`outcome == mapped`、`reason is None`、`host_pid`/`cgroup_id` 为 `None`
（inspect 未提供，不伪造）、`/work/a.txt` 映射成功而 `/worker` 返回 `None`
（目录边界），且 evidence 明确写出
"`State.Pid=0 表示没有宿主进程，host_pid=null`"。

### 10.4 M3 计划中仍需真实环境完成的部分

本任务只交付**映射库**。下列 M3 验收项需要真实 Docker/VM 与 eBPF 侧配合：
真机容器（含短命容器）标签映射实测、`/proc/<pid>/cgroup` 在 cgroup v1/v2
宿主上的实测、容器启动/停止竞态下的映射稳定性、与事件 cgroup 的端到端对齐，
以及 ≥200 条带独立预期关系的样本评估（那是 T05 + M3 出口项）。

---

## 11. 与 T05 关联引擎的接口约定

* T05 自行定义 `ContainerResolver` 之类的协议，**不 import**
  `agent_probe.container`；两侧通过"结构化数据（`to_dict()` + `canonical_json`）
  + 结果语义"解耦。
* T05 可以依赖的语义：§4.3 的四种 outcome、`reason` 必填规则、
  `candidates` 的排序与截断语义、`evidence` 是"人可读但不参与判定"的说明、
  `mapping.mounts` 只在 `mapped` 时非空。
* 本层不提供任何置信度/概率；`ambiguous` 就是"不能唯一确定"，
  调用方不得把它降级成"取第一个候选"。

---

## 12. 不在范围

* 关联引擎与证据图、置信度、外部/辅助两种关联模式（T05 `agent_probe.correlate`）。
* eBPF C 探针、事件账本读写、丢失统计（M2 采集侧）。
* CLI 子命令与报告渲染（M4）；本子包不注册任何 `probe` 命令。
* 跨主机的容器发现、远程 daemon 的凭据处理、Docker API 版本协商
  （`docker` CLI 已处理；本层不解析 `/var/run/docker.sock` 协议）。
* 抗篡改：`docker inspect` 的输出被 root 伪造时本层无法识别
  （信任模型见 `plan.md` §1）。

## 13. 真值边界与已知限制

**真值边界（一句话）**：本层能证明的只是"某个 label 在某个时间窗内对应到某个容器，
以及该容器的 inspect 真值字段是什么"；它**不能**证明该容器里的进程做了什么，
也不声称容器的行为与 agent 的任务存在因果关系（那是 T05 + 事件账本的事）。

1. **每个容器一次 `inspect`**：`ContainerQuery` 没有标签过滤接口，映射一次要
   遍历全部容器（O(N) 次 docker 调用）。容器数量很大时应先缩小范围
   （例如用独立的 daemon/标签前缀），或给 `ContainerQuery` 增加带过滤的
   `list_container_ids`。本层刻意不做"只查最近创建的容器"这类优化，
   因为它会破坏候选完整性。
2. **`cgroup_path` 是容器主进程所在 cgroup**：容器内进程被显式移到子 cgroup 时，
   该路径不等于子 cgroup 的路径；cgroup id 只在同一 cgroupfs 挂载内可比。
3. **时间来自 daemon 时钟**：窗口判定受时钟偏差影响（§8）；
   三个时间之间的先后不做校验。
4. **纯词法路径映射**：不解析符号链接、不检查宿主路径存在性；
   含 `..` 的查询路径直接返回 `None`。
5. **`tmpfs` 与 `other` 挂载不可映射到宿主路径**：语义上就不存在宿主路径
   （`other` 可能是 npipe/cluster 等），返回 `None` 并说明原因。
6. **未知 `State.Status` 折叠为 `unknown`**：原始字符串保留在 evidence 里，
   但 `ContainerInfo` 不保存原始 state 串（字段集由冻结 API 决定）。
7. **严格性带来的失败**：挂载项/时间戳/必需字段的任何异常形状都会让整次映射
   变成 `ERROR`（而不是跳过该容器）。这是刻意的：候选集合不完整的"成功"
   比明确失败更危险。
8. **`evidence` 只保证可读与有界**：它不是结构化字段，解析它做机器判定
   属于误用；机器判定请用 outcome/mapping/candidates/reason。
