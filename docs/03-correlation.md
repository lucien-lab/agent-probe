# 03 · M3 可解释行为关联（库层实现说明）

> 状态：M3 **关联引擎核心**已实现（证据图、外部/辅助两种关联模式、置信度与歧义、
> 可序列化结果、解释接口、消融开关）。**不接入 CLI**、**不做 eBPF 采集**、
> **不做 Docker 查询本身**（由调用方注入 `ContainerResolver`）、**不做因果推断**。
>
> 代码：`src/agent_probe/correlate/`；测试：`tests/correlate/`。
> 根包 `agent_probe.__init__` 仍只导出 `__version__`，关联能力由
> `agent_probe.correlate` 子包提供。

---

## 1. 这个模块回答什么

> "这条系统事件 / 这次 LLM 调用，**属于哪个任务**？**依据是什么**？**有多确定**？"

三个问题的答案分别落在三类地方：

| 问题 | 答案载体 |
|---|---|
| 属于什么 | `EvidenceNode` + `NodeAttribution`（任务级归因） |
| 依据是什么 | `EvidenceEdge.basis` / `.evidence` / `.method_version` |
| 有多确定 | `EvidenceEdge.confidence` / `.candidates`、`Ambiguity`、`AttributionStats` |

**明确不做**（写进代码 docstring 与本节，避免后续被当作缺陷）：

* 不做因果推断。所有结论都是"关联 + 依据 + 置信"，没有"因为所以"。
* 不用"时间最近"当唯一归因。时间接近最多给出 `PROBABLE`，多候选时必须保留全部候选。
* 不猜进程归属。`run_id` 相同**不等于**属于该任务；采集不到父链时输出 `UNKNOWN`。
* 不假装知道容器归属。没有注入 `ContainerResolver` 就没有任何容器边。
* 不静默截断。节点/边超限抛 `CorrelationLimitError`；只有"歧义候选过多"允许截断，
  且截断事实必须写进边的 `evidence` 与结果的 `notes`。

---

## 2. 数据模型

### 2.1 节点（`EvidenceNode`）

`node_id` 由**内容**派生：`sha256("node" + "\x1f" + kind + "\x1f" + key)` 的前 32 位
十六进制，前缀 `n:`。因此同一 key 在任何进程、任何时间、任何输入顺序下都得到同一
ID；`from_dict` 会校验 `node_id` 与内容是否一致（被篡改的 JSON 直接报错）。

| kind | `key` | 说明 |
|---|---|---|
| `TASK` | `run:<run_id>` | 任务 = 一次 probe run。**只**由调用方传入的 `Task` 声明创建 |
| `PROCESS` | `run:<r>:pid:<p>:start:<start_id 或 unknown>` | 进程实例；**按 run 分节点**（同一进程被两次 run 观测 → 两个节点） |
| `LLM_CALL` | `<physical_request_id>` | 一次物理 LLM 请求；同一 ID 重复出现时确定性去重并记 note |
| `TOOL_CALL` | `tool:<声明身份的规范 JSON>` | 工具调用；**只**来自应用侧声明（辅助模式） |
| `FILE_EFFECT` | `run:<r>:pid:<p>:start:<s>:path:<路径>` 或 `:fd:<n>` | 同一进程 + 同一文件身份的事件聚合 |
| `NET_EFFECT` | `…:net:<proto>:<addr>:<port>` / `…:tls:<connection_id>` | 网络目的聚合 / TLS 连接节点 |
| `CONTAINER` | `container:<container_id>` | 仅当注入 resolver 且解析命中时存在 |

`monotonic_ns` 是节点在单调时钟上的代表时刻（首个事件；未知写 `null`）。
`attributes` 全部为 JSON 原生类型、键已排序、列表已排序——这是"逐字节可复现"的前提。

进程身份的粒度是 `(run_id, pid, process_start_id)`：

* `process_start_id` 未采集的事件会形成 `start:unknown` 节点，**不会**被合并到已知
  实例上（合并需要猜测 PID 复用，明确不做）。这是一个有意的保守选择，代价是同
  一个进程可能被拆成两个节点，收益是绝不串味。
* `process.fork` 的 `child_pid`/`child_start_id` 会**额外**造出子进程节点，因此
  "fork 后立刻 exit、没有任何其他事件"的短命子进程不会从图里消失。

### 2.2 边（`EvidenceEdge`）

`edge_id = sha256("edge" + src + dst + basis + method_version)`，前缀 `e:`。
`confidence` / `evidence` 刻意**不**参与身份：同一条关联被更多证据支持时合并为一条边
（置信取最强、证据取并集），而不是产生一堆同身份边。

**方向约定：边从"被归属者"指向"归属者"（自下而上）。** 即：

```
FILE_EFFECT / NET_EFFECT / TOOL_CALL / PROCESS / LLM_CALL / CONTAINER  ──►  归属节点
```

* `process.fork` 的父子关系也按此方向：`子进程 → 父进程`。
* plan.md 里"任务 → LLM 请求 → 工具执行 → 系统事件"描述的是**概念链**；本实现把
  边的方向取成"证据自下而上"，好处是 `explain(node_id=…)` 直接读该节点的出边就等于
  读它的归属，M4 的 `probe explain <event-id>` 不需要反向索引，也不需要把
  `candidates`（"其他候选 **dst**"）反过来解释。

每条边**必须**携带：`basis`（7 类之一）、`method_version`、`confidence`、至少一条
`evidence` 字符串；`AMBIGUOUS` 必须有非空 `candidates`，其他置信度必须为空
（构造时强校验，见 `EvidenceEdge.__post_init__`）。`AMBIGUOUS` 的 `dst` 是按
`node_id` 升序确定性选出的**占位主候选**，不代表归因成立。

| `basis` | 含义 | 外部模式 | 辅助模式 | 上限 |
|---|---|---|---|---|
| `PROCESS_LINEAGE` | `(pid, process_start_id)` 精确身份；`process.fork` 父子链；任务根进程集合及其后代 | ✅ | ✅ | `CERTAIN` |
| `CONNECTION_ID` | `tls.bytes.payload.connection_id` == `LlmCallRecord.connection_id` | ✅ | ✅ | `CERTAIN` |
| `RUN_ID_MARKER` | 系统侧 `run_id` 相同；或任务自带 `cgroup_id` 与事件 `cgroup_id` 精确相同 | ✅ | ✅ | 仅 `cgroup_id` 命中可 `CERTAIN`，仅 `run_id` 相同最高 `PROBABLE` |
| `TIME_WINDOW` | 同一 `run_id` 内按 `monotonic_ns` 的包含关系 | ✅ | ✅ | `PROBABLE`（**永不** `CERTAIN`） |
| `CONTAINER_MAPPING` | 容器 → 任务（标签 + resolver）、进程 → 容器（resolver 的宿主 pid/cgroup 命中） | 需 resolver | 需 resolver | `CERTAIN`（PID 复用命中时 `PROBABLE`） |
| `CALL_ID_MARKER` | 应用声明的 `call_id`（**声明**） | ✗ | ✅ | 有身份桥才 `CERTAIN`，否则 `PROBABLE` |
| `TOOL_ID_MARKER` | 应用声明的 `tool_id`（**声明**） | ✗ | ✅ | 同上 |

### 2.3 置信度（`Confidence`）

`UNKNOWN < AMBIGUOUS < PROBABLE < CERTAIN`（`CONFIDENCE_RANK`）。路径合成取
**最弱一环**（`compose_confidence`）。把 `AMBIGUOUS` 排在 `PROBABLE` 之下是刻意的：
对**某一个具体候选**而言，"多个候选并列"比"唯一候选但非精确匹配"更弱。

| 等级 | 定义 | 典型来源 |
|---|---|---|
| `CERTAIN` | 精确标识匹配且候选唯一 | `connection_id` 精确相等；`(pid, start_id)` 精确身份；`cgroup_id` 精确相同；声明 + 身份桥 + 全字段核验通过；resolver 命中 |
| `PROBABLE` | 系统证据方向一致、候选唯一，但不是精确标识匹配 | 时间窗内唯一候选；仅 `run_id` 相同（且进程不是"run 前已存在"）；声明没有身份桥；声明冲突但无替代候选 |
| `AMBIGUOUS` | ≥2 个同等强度候选 | 同进程并发调用共享连接；同一进程同一时刻多条声明；声明与系统证据冲突且存在替代候选 |
| `UNKNOWN` | 没有可用证据或证据不足以产生候选 | 任务声明缺失；只有一个事件没有 `connection_id`；run 开始前已存在且无血缘/cgroup 的进程 |

**候选唯一性优先于强度**：两个 `CERTAIN` 候选仍然是 `AMBIGUOUS`（例如同一
`connection_id` 被两个任务的进程使用）。归因合成见 §4。

---

## 3. 两种关联模式

### 3.1 外部模式（`use_assisted_markers=False`，默认）

只用**系统侧可观测的东西**：进程血缘、连接 ID、时间窗、容器映射、`run_id`/`cgroup`。

任务级（主要承诺）：

1. 进程命中任务根集合（`process_start_ids`）→ `PROCESS_LINEAGE` + `CERTAIN`。
2. 进程经 `process.fork` 链到达任务根 → `PROCESS_LINEAGE` + 路径最弱一环
   （`child_start_id` 未采集 / fork 事件无 `process_start_id` / 事件自相矛盾 → `PROBABLE`；
   PID 复用导致同 pid 多实例 → `AMBIGUOUS` 且保留全部候选）。
3. `cgroup_id` 与任务声明精确相同 → `RUN_ID_MARKER` + `CERTAIN`。
4. 进程首次出现在任务窗口**之前**且上述都不成立 → **`UNKNOWN`**（不猜）。
5. 其余（`run_id` 相同、窗口内首次出现）→ `RUN_ID_MARKER` + `PROBABLE`，
   并在证据里写明"未观测到诞生事件（process.fork）"。

副作用节点（文件/网络）先按 `(pid, process_start_id)` 归到进程（`PROCESS_LINEAGE`，
`start_id` 未知时降到 `PROBABLE`），再经进程归到任务。

调用级（**不承诺**任意并发可唯一归因）：

* 调用**没有** `run_id`、没有时间戳。它唯一能"落地"的方式是
  `connection_id` 与 `tls.bytes` 事件精确相等 → `LLM_CALL → NET_EFFECT(tls)`
  （`CONNECTION_ID` + `CERTAIN`），再经连接节点 → 进程 → 任务。
* 调用的时间锚点 = 同连接节点聚合事件的 `[first_seen, last_seen]`。副作用落在
  某调用的活动区间 `± time_window_ns` 内 → `EFFECT → LLM_CALL`（`TIME_WINDOW`）：
  唯一候选 → `PROBABLE`，多候选 → `AMBIGUOUS`（**保留全部候选**）。
* 连接节点本身**不**归因到单个调用：连接可被多次调用复用，硬绑一个就是制造假歧义。
* 没有 `connection_id` 匹配的调用 → `UNKNOWN`（外部模式没有别的办法把它放上时间轴）。

### 3.2 辅助模式（`use_assisted_markers=True`）

应用侧的 `run_id` / `call_id` / `tool_id` / `task_label` / `pid` /
`process_start_id` / `monotonic_ns` / `wall_time_ns` 都是**声明**。流程：

1. **逐字段核验**（`checks`）：每个已声明字段标 `verified` / `unverifiable` / `conflict`。
   * `unverifiable`（例如声明了 `call_id` 但系统没捕获到该调用）是**采集缺口**，不是反证。
   * `conflict` 才是反证：声明的 `pid` 在系统事件里不存在、`pid` 存在但
     `process_start_id` 对不上（PID 复用）、声明内部的 `call_id` 与 `connection_id`
     指向不同调用。
2. **身份桥**（`identity_bridge`）决定能否升到 `CERTAIN`。桥 =
   * 声明的 `connection_id` 与系统捕获到的调用/连接对得上；**或**
   * 系统事件携带的 `correlation_id` 与声明的 `call_id`/`tool_id` 一致。
3. **置信档位**：
   * 存在 `conflict` → `AMBIGUOUS`（有替代候选）或 `PROBABLE`（无替代候选），
     声明与系统证据**都**留在 `evidence` 里；
   * 全部字段 `verified` 且有桥 → `CERTAIN`；
   * 其余 → `PROBABLE`，并明确写出"没有可用的身份桥"。
   * `wall_time_ns` 推算出的时刻一律把上限压到 `PROBABLE`（见 §3.3）。
4. **效果归属**：声明把进程的时间轴切成互斥区间，区间内的副作用归到该声明的所有者
   （`TOOL_CALL` 或 `LLM_CALL`），`dst` 固定为确定性主候选。证据串里**同时**写：
   * `declared: …`（声明内容）
   * `system: …`（系统侧得到了什么）
   * `system: 外部时间窗候选（basis=time_window，最高只到 PROBABLE）= […]`

   **收敛 vs 降级**：若声明指向的调用落在系统时间窗候选集合内（或集合为空），
   声明把候选收敛成它自己（`CERTAIN`/`PROBABLE` 由档位决定）；若声明指向的调用
   **不在**候选集合内，或声明自身有 `conflict`，则取并集 → `AMBIGUOUS`，
   候选全部保留。同一时刻的多条声明 → 该区间的候选是所有这些声明（`AMBIGUOUS`）。
5. `correlation_id` 命中是**强交叉核验**：系统事件带的 `correlation_id` 与声明的
   `call_id`/`tool_id` 相等 → 直接 `CERTAIN`（这是"声明 + 系统证据"双向成立的唯一情况），
   并且优先于时间片推断。
6. **工具身份不参与"全部已声明字段已核验"判定**。外部可观测的量里没有工具名，
   若把 `tool_id` 当作必须核验的字段，任何没做 `correlation_id` 传播的应用都会被
   永久压在 `PROBABLE`。工具身份依赖 `call_id`/进程/时间等字段的核验。

### 3.3 时钟纪律（wall_time 与 monotonic_ns 混用）

* 排序、时间窗一律用 `monotonic_ns`，且**只在同一 `run_id` 内比较**。
* 声明只给 `wall_time_ns` 时，用该 run 内 `wall_time - monotonic_ns` 的偏移区间
  反推单调区间，并显式标注 `wall_clock_fallback`，置信上限 `PROBABLE`。
* 反推区间与该 run 的观测区间**无交集** → 判为"疑似跨 boot"，**拒绝**该声明的时间窗
  比较，并把原因写进结果 `notes`。缺 `run_id` 或该 run 没有带 `wall_time` 的事件时
  同样拒绝（无法确定 boot 偏移）。
* 永不跨 boot 比较：不做任何"用 wall 时间补偿不同 boot"的猜测。

---

## 4. 任务级归因合成与统计口径

### 4.1 归因合成（`resolve_attribution`）

从每个非 `TASK` 节点沿出边向上走（深度上限 12，禁止重复节点），到达 `TASK` 节点即记一条
候选：

* 路径置信 = 路径上各边置信的**最弱一环**；同一任务的多条路径取最强的（同强度取更短）。
* 最高强度候选**唯一** → 该节点有唯一归因（`CERTAIN`/`PROBABLE`）。
* 最高强度候选 ≥2 个 → `AMBIGUOUS`，`targets` 列出全部候选，`primary` 只是占位。
* 全部候选都是 `UNKNOWN`（含没有任何候选）→ `UNKNOWN`。

副作用 → 进程 → 任务是一条**三跳路径**，`explain(node_id=…)` 会给出这条路径的边 id 与证据。

### 4.2 统计字段（`AttributionStats`）

| 字段 | 口径 |
|---|---|
| `tasks_total` | TASK 节点数 |
| `nodes_total` | **除 TASK 之外**的全部节点（归因目标不算待归因节点） |
| `nodes_certain` / `nodes_probable` / `nodes_ambiguous` / `nodes_unknown` | 按 §4.1 的归因等级计数；四者之和 == `nodes_total` |
| `determinate_coverage` | `(certain + probable) / nodes_total`；`nodes_total == 0` 时为 `0.0` |
| `ambiguity_rate` | `ambiguous / nodes_total`；`nodes_total == 0` 时为 `0.0` |
| `precision` | 见 §4.3；无真值时 `None` |
| `recall` / `f1` | 见 §4.3；无真值时 `None` |
| `edges_total` / `edges_certain` / `edges_probable` / `edges_ambiguous` / `edges_unknown` | 边级别置信分布（观察调用级退化用；调用级歧义表现在这里，而不是 `nodes_ambiguous`） |

**高精确率必须与覆盖率一起解释**：把一切都标成 `UNKNOWN` 可以得到"不犯错"的
precision，代价是 `determinate_coverage` 归零。M3/M6 的报告必须同时给出
`determinate_coverage`、`ambiguity_rate` 与 P/R。

### 4.3 真值评估（`evaluate_against_truth`）

真值形如 `{node_id: 任务}`，任务可以是任务 `node_id`、`run_id` 或 `label`。

* **召回分母** = 真值里除 TASK 节点以外的全部条目。结果里根本不存在的节点、
  `UNKNOWN` 归因的节点、`AMBIGUOUS` 的节点**都不从分母里删除**（它们都是漏检）。
* **精确分母** = 真值覆盖到的节点中"给出了唯一归因"的那些；一个都没给出时
  `precision = None`（"没有给出关联"不是"0 精确率"）。
* `f1` 由精确率与召回率算出；两者任一为 `None` 时 `f1` 也是 `None`。
* 真值只有一份来源（`truth` 参数），模块**不**自己造真值；辅助标记也**不能**直接当
  真值使用，必须与系统事件交叉核验后才有资格参与结论（§3.2）。

### 4.4 歧义记录（`Ambiguity`）

* 节点级：任务级归因为 `AMBIGUOUS` → `Ambiguity(node_id=…, candidates=全部候选任务)`。
* 边级：`AMBIGUOUS` 边 → `Ambiguity(edge_id=…, candidates={dst} ∪ candidates)`。
* PID 复用导致"哪个是被 fork 的子进程"不可判定时，`candidates` 列出其他候选
  **被归属者**，并有一条边级记录（这是唯一一处 `candidates` 不是"候选 dst"的情形，
  因为 API 里歧义的承载方是 `dst` 而这里歧义在被归属者一侧）。

---

## 5. 消融开关与实验接口

`CorrelationConfig` 的每个 `use_*` 开关都能**独立关闭**；默认值：

| 开关 | 默认 | 关闭后的效果 |
|---|---|---|
| `use_time_window` | `True` | 不产生任何 `TIME_WINDOW` 边（含"标记时间片"之外的兜底归属） |
| `use_process_lineage` | `True` | 不产生 `fork` 父子边与"根进程/后代"归属；进程退化为 `run_id`/`cgroup` 档位（覆盖率通常保持、确定性下降） |
| `use_connection_id` | `True` | 不产生 `CONNECTION_ID` 边 → 调用失去系统侧落点（辅助模式下仍可由声明 + 进程/时间给出 `PROBABLE`） |
| `use_container_mapping` | `True` | 完全不查询 resolver，不产生 `CONTAINER` 边/节点，`Task` 节点标 `container_mapping="disabled_by_config"` |
| `use_assisted_markers` | `False` | 忽略全部声明（结果 `notes` 显式说明"已全部忽略"），无 `TOOL_CALL` 节点 |

`ablation_report(events, calls, tasks, truths=None, *, markers=None, config=None,
container_resolver=None) -> dict[str, AttributionStats]` 返回固定顺序的字典：

```
{"baseline": …, "without_use_time_window": …, "without_use_process_lineage": …,
 "without_use_connection_id": …, "without_use_container_mapping": …,
 "without_use_assisted_markers": …}
```

* **baseline 是"全部开关打开"**（因此 baseline 里 `use_assisted_markers=True`）。
  配置默认值是"辅助标记关闭"，它服务常规关联；baseline 服务消融对比。两者不同是
  有意的，写在这里避免误读。
* 传入 `truths` 时每个条目都带上 precision/recall/f1；不传则为 `None`。
* 引擎上的同名方法 `CorrelationEngine.ablation_report(...)` 复用同一配置与 resolver。

---

## 6. 解释接口（`explain`）

`CorrelationEngine.explain(result, node_id=… | edge_id=…)`（模块级 `explain()` 同签名）
返回 JSON 可序列化字典：

* 都不传 → `summary`（按 kind/basis/confidence 的计数、`stats`、`notes`、`mode`、
  `method_version`）+ `basis_guide` + `confidence_guide`。
* `node_id` → 节点内容、`attribution`（等级、是否 `determinate`、候选、`primary`、
  **到达任务的边路径**）、`outgoing` / `incoming`（逐条边的依据与证据）、
  `ambiguities`（该节点自身或其任一条边的歧义记录）。
* `edge_id` → 该边完整内容 + `basis_explanation` + `confidence_explanation` +
  `meaning`（人类可读的"这条边能怎么用"）+ 全部候选的节点摘要。

7 类 `basis` 都有说明文本（`BASIS_EXPLANATIONS`），4 个置信等级都有
（`CONFIDENCE_EXPLANATIONS`）——`explain` 对结果里的**每一条**边都能解释。
查不到的 id 抛 `CorrelationNotFoundError`；同时传 `node_id` 与 `edge_id` 抛
`CorrelationInputError`。

---

## 7. 可复现性与离线重算

* 输入先排序（事件按 `(run_id, monotonic_ns, event_id)`、调用按
  `(physical_request_id, logical_call_id, connection_id, attempt_index)`、任务按
  `run_id`、声明按 `(run_id, monotonic_ns（未知为 -1）, call_id, tool_id,
  connection_id, task_label, pid, process_start_id, 身份 JSON)`），输出再排序
  （节点按 `node_id`、边按 `(src, dst, basis)`、歧义按
  `(node_id|edge_id, reason)`）。
* ID 一律由内容哈希派生；证据列表在序列化时排序去重。**没有** `id()`、时间戳、
  随机数、字典迭代顺序依赖。测试用"输入整体倒序"验证逐字节一致。
* `CorrelationResult.to_json()` 用 `agent_probe.events.canonical_json`
  （`sort_keys` + 紧凑分隔符 + `ensure_ascii=False`），因此同一输入逐字节相同。
* `to_dict() → from_dict() → to_json()` 恒等；`from_dict` 校验 `node_id`/`edge_id`
  与内容一致，并拒绝缺失/未知键。
* 结果**自足**：`CorrelationResult` 带 `config`（含 `method_version`）与 `stats`，
  离线只有 JSON 文件也能重新打分（`tests/correlate/test_offline_artifacts.py`）。

`method_version` 当前为 `m3-correlate-1`。**任何会改变关联结论的语义改动都必须递增它**，
否则历史报告与消融表会被悄悄混在一起。

---

## 8. 边界与失败模式（都有测试）

| 情形 | 行为 |
|---|---|
| 空输入 | 空节点/边/歧义，`stats` 全 0，`precision/recall/f1 = None`，`notes` 说明缺什么 |
| 只有事件没有调用 | 任务级照常；`notes` 说明调用级为空 |
| 只有调用没有事件 | 只有 `LLM_CALL` 节点，全部 `UNKNOWN`（没有时间锚点，不猜） |
| 没有任务声明 | 没有 TASK 节点 → 全部 `UNKNOWN`（`notes` 明确说明） |
| `quality.*` 事件 | **刻意忽略**：它们是采集器自身的质量信号，pid 是采集器的 pid，当成 agent 进程只会造假节点 |
| `process_start_id` 未采集 | 节点键为 `start:unknown`，相关边降为 `PROBABLE`，不与已知实例合并 |
| `result=error` 的文件事件 | 保留在节点 `attributes["results"]`（`{"error": n}`），不伪装成成功 |
| 重复 `physical_request_id` | 确定性去重 + `notes`（不双计） |
| 同一 `run_id` 两条内容不同的 `Task` | `CorrelationInputError` |
| 输入类型错误 / `markers` 传了裸 dict | `CorrelationInputError`（显式要求 `AssistantMarkers`） |
| `max_nodes` / `max_edges` 超限 | `CorrelationLimitError`（不静默截断） |
| `max_candidates` 超限 | 截断候选，并把 `candidates_truncated: kept X of Y` 写进 `evidence`，同时结果 `notes` 报警；被截断候选的**全集**仍写在同一行证据里 |
| `wall_time` 疑似跨 boot | 拒绝该声明的时间窗比较 + `notes` + 无 `TIME_WINDOW` 边 |
| `process.fork` 的 `parent_pid` 与事件 `pid` 矛盾 | `PROBABLE` + 证据写明"数据自相矛盾，不采用该事件的 start_id" |

---

## 9. 与 T06（Docker 映射）的接口

本包**自行定义**协议，**绝不 import `agent_probe.container`**（两个任务并行开发、
合并无冲突）：

```python
class ContainerResolver(Protocol):
    def resolve_host_pid(self, container_id: str) -> int | None: ...
    def resolve_cgroup_id(self, container_id: str) -> int | None: ...

class CorrelationEngine:
    def __init__(self, config=None, container_resolver: ContainerResolver | None = None): ...
```

* 容器 ID 来自 `Task.labels`（键按优先级、大小写不敏感：`container_id`、
  `docker_container_id`、`container`、`docker`、`containerid`）。
* 返回 `None` 表示**解析不到**，绝不当成 0；`None` + `None` → 不建节点/边 + `note`。
* `use_container_mapping=False` 时**一次都不查询** resolver（测试用 fake 的查询记录断言）。
* resolver 抛异常会向上传播（不静默吞掉）；契约由注入方负责。
* T06 的实现只需满足这两个方法，不需要知道本模块的内部结构。

---

## 10. 已知限制与残留风险

1. **调用级外部模式天然不完整**：`LlmCallRecord` 没有时间戳，只有 `connection_id`。
   连接复用（HTTP keep-alive 是常态）下，同进程多路并发无法区分 → 这是设计上承认的
   歧义，而不是缺陷；M6 报告应给出 `edges_ambiguous` 与 `determinate_coverage`。
2. **`run_id` 相同的 `PROBABLE` 归属可能偏乐观**：run 开始后才被首次观测到的、
   并非任务后代的进程（例如共享守护进程）会得到 `PROBABLE`。缓解：证据里明确写
   "未观测到诞生事件（process.fork）"，M4 报告可据此单列"血缘缺失"的比例。
3. **`start:unknown` 拆分**：同进程的"已知 start_id"与"未采集 start_id"事件会形成两个
   节点，覆盖率与语义都会保守一些（不合并是需要，不是可以妥协的选项）。
4. **标记时间片依赖声明质量**：应用不声明工具开始时间就无法把效果切到具体工具；
   同一时刻多条声明会退化为 `AMBIGUOUS`。
5. **`task_label` 重复**：多个任务共用同一标签时，声明会同时指向多个任务
   （多目标 → `AMBIGUOUS`），不会任取一个。
6. **容器映射只覆盖"任务标签里有容器 ID"的场景**：Docker 查询本身的正确性、
   短命容器的映射竞争属于 T06 的范围。
7. **时间窗默认 5 秒**：`time_window_ns` 对长尾工具（>5s 后落盘的副作用）会漏掉调用级
   关联；这会降低调用级覆盖率而**不影响**任务级归因。M6 应报告该参数的敏感性。
8. **不做因果推断**：本模块的边只表示"带证据的关联"。任何"因为调用了 X 所以文件被改"
   的表述都超出本层结论，需要 M4 的规则层与人工复核。

---

## 11. 不在本次范围

* CLI 子命令（`probe explain` / `probe report`）与静态 HTML 时间线 → M4。
* eBPF 采集器、挂点验证与资源预算 → M2/M0 遗留。
* Docker 查询实现、挂载视图 → T06。
* YAML 规则引擎、告警与成本汇总 → M4。
* 对照实验、性能与消融的**实验报告**（本模块只提供 `ablation_report` 与统计口径）→ M6。
