# 02 · M2 可靠事件账本（库层实现说明）

> 状态：M2 **核心库**已实现（事件模型 / JSONL 权威日志 / SQLite 派生索引 /
> 丢失统计 / 离线重放）。eBPF C 探针与 CLI 集成**不在本次范围**，
> 见文末「不在范围」。
>
> 代码：`src/agent_probe/events/`；测试：`tests/events/`。
> 根包 `agent_probe.__init__` 仍只导出 `__version__`（骨架阶段约定），
> 账本能力由 `agent_probe.events` 子包提供。

---

## 1. 数据模型

### 1.1 事件头（恒定 17 个键，未知值写 `null`）

| 字段 | 类型 | 语义与约束 |
|---|---|---|
| `schema_version` | int ≥ 0 | 事件 schema 版本；当前 `1`，不在集合内即拒绝 |
| `event_id` | UUID 字符串 | 规范化小写连字符形式；nil UUID 拒绝；索引去重主键 |
| `run_id` | UUID 字符串 | probe run 标识；与 `event_id` 同样的规范化要求 |
| `source` | enum | `ebpf` / `userspace` / `synthetic`；序号与顺序流按 `(run_id, source)` 划分 |
| `event_type` | enum | 见 §1.3 |
| `monotonic_ns` | int ≥ 0 | `CLOCK_MONOTONIC` 纳秒；**同一 boot 内**的排序依据 |
| `wall_time` | int ≥ 0 | Unix epoch 纳秒；`0` = 未采集（不是 1970-01-01 的真实时刻） |
| `pid` / `tid` | int ∈ [0, 2³¹−1] | 线程组/线程 ID |
| `process_start_id` | int ≥ 0 或 `null` | `/proc/<pid>/stat` starttime，用于识别 PID 复用；`null` = 未采集 |
| `cgroup_id` | int ≥ 0 或 `null` | `null` ≠ "无 cgroup"，只表示未采集 |
| `pid_namespace` | int ∈ [0, 2³²−1] 或 `null` | 同上 |
| `result` | enum | `ok` / `error` / `unknown`；**必填，无默认值** |
| `seq` | int ≥ 0 或 `null` | 同一 `(run_id, source)` 流内的连续序号；不连续 = 丢失信号 |
| `error_code` | int ≥ 0 或 `null` | errno；与 `result` 强绑定（见下） |
| `correlation_id` | 文本 ≤ 128B 或 `null` | 关联令牌，本层不解释语义（M3 使用） |
| `payload` | object | 按事件类型的字段表校验，见 §1.3 |

**不把未知/缺失当成功**，具体机制：

* `result` 没有默认值：构造/反序列化时缺 `result` 直接报错；
  拿不到返回值必须写 `unknown`。
* `result=ok` 时**禁止**携带 `error_code`；`result=error` 时**必须**提供非负
  `errno`；`result=unknown` 时禁止携带 `error_code`。
* 头字段缺失（即使值可空）也报错——未知值必须**显式写 `null`**，
  禁止用"省略键"隐式表达未知。
* `file.truncate` 必须至少给出 `path` 或 `fd`；`process.exit` 必须至少给出
  `exit_code` 或 `signal`（未观测到退出状态不允许记为正常退出）。
* `quality.sequence_gap` 强制算术自洽：`missing == received_seq - expected_seq` 且
  `received_seq > expected_seq`。

### 1.2 边界与硬上限（`model.py`）

| 常量 | 值 | 作用 |
|---|---|---|
| `MAX_EVENT_BYTES` | 65536 | 单条事件规范化 JSON 的 UTF-8 字节上限；超限抛 `EventTooLargeError` |
| `MAX_STRING_BYTES` | 4096 | 一般文本字段（reason、connection_id、argv 元素…）上限 |
| `MAX_PATH_BYTES` | 4096 | 路径字段上限，且禁止空串与 NUL |
| `MAX_LIST_ITEMS` / `MAX_ARGV_ITEMS` | 256 / 128 | 数组字段元素上限 |
| `MAX_COUNTER_KEYS` | 64 | 计数器映射键上限 |
| `MAX_PAYLOAD_DEPTH` | 8 | payload 嵌套深度上限 |
| `MAX_LINE_BYTES` | `MAX_EVENT_BYTES + 4096` | 账本单物理行上限（信封开销余量） |

payload 值只允许 JSON 原生类型；`bool` 不会被当成 `int`（`pid=True` 直接报错）；
`NaN`/`Infinity` 被拒绝（JSON 无法表示，且会造成校验值不可复现）。

payload 在构造时被**深度冻结**：对象 → `MappingProxyType`，数组 → `tuple`，
构造后不可就地篡改；需要 JSON 原生结构时用 `Event.to_dict()`（内部 `_thaw`）。

### 1.3 事件类型与 payload 字段表

| 事件类型 | payload（★ = 必填） |
|---|---|
| `process.fork` | ★`child_pid`, ★`parent_pid`, `child_start_id` |
| `process.exec` | ★`exe`, ★`argv[]`, `cwd` |
| `process.exit` | `exit_code` 或 `signal`（至少一个） |
| `file.open` | ★`path`, ★`flags`, `fd`, `mode` |
| `file.read` | ★`fd`, ★`count`, ★`bytes_read`, `path` |
| `file.write` | ★`fd`, ★`count`, ★`bytes_written`, `path` |
| `file.truncate` | ★`length`, `path` / `fd`（至少一个） |
| `file.rename` | ★`old_path`, ★`new_path`, `flags` |
| `file.unlink` | ★`path`, `dir_fd` |
| `net.connect` | ★`family`(inet/inet6), ★`protocol`(tcp/udp), ★`dest_addr`, ★`dest_port`, `local_port` |
| `net.send` | ★`family`, ★`protocol`, ★`dest_addr`, ★`dest_port`, ★`bytes_sent` |
| `tls.bytes` | ★`direction`(read/write), ★`bytes`, ★`connection_id`, ★`plaintext_included`, ★`truncated` |
| `quality.sequence_gap` | ★`stream`, ★`expected_seq`, ★`received_seq`, ★`missing` |
| `quality.ring_drop` / `quality.queue_drop` / `quality.storage_drop` | ★`count`(≥1), ★`reason` |
| `quality.counter_snapshot` | ★`counters{name: int}` |

M2 语义要点：

* **入口 vs 成功**：`file.open` 记的是"尝试"，`result`/`error_code` 才是结果；
  只有 `result=ok` 且有 `fd` 才能说"成功打开"。
* **实际读写**：`file.read`/`file.write` 的 `bytes_read`/`bytes_written` 是返回值，
  `count` 是请求量；二者不等不是错误，但报告时应分别呈现。
* **TLS**：默认只记元数据；`plaintext_included` 显式声明该事件是否包含原文，
  M2 不带原文内容字段（调试原文属 M4 保留策略范围）。
* **明确盲区**：`mmap` 写、`io_uring`、静态链接 TLS 不产生受支持事件；
  它们既不出现在事件里，也**不会**出现在丢失计数里（这是"覆盖盲区"与
  "传输丢失"必须分开报告的原因，见 §5）。

### 1.4 未知字段兼容策略

`UnknownFieldPolicy` 只有两个取值，没有"静默忽略"：

* `REJECT`（默认）：未知**头字段**或未知 **payload 字段**立即抛
  `UnknownFieldError`，避免拼写错误/版本错配被当成有效数据。
* `PRESERVE`：未知字段原样保留（头字段进 `extra`，payload 字段留在 payload），
  写出时原样回写，但**永不参与校验判定与语义解释**。用于读比当前实现更新的
  schema 版本时不丢数据。

读账本/索引时使用的策略必须与写入时一致；默认 `REJECT`。索引回放固定使用
`PRESERVE`（内容在写入时已严格校验过），从而未知字段也能在索引中往返。

---

## 2. JSONL：权威记录

### 2.1 行格式（信封）

每行是一个完整事件的规范化 JSON 信封，以 `\n` 结束：

```json
{"v":1,"len":412,"checksum":"sha256:…","event":{ … 17 个头字段 + payload … }}
```

* `v`：**信封**版本（与事件 `schema_version` 独立），当前 `1`。
* `len`：`event` 规范化 JSON 的 UTF-8 字节数。
* `checksum`：`sha256:` + `event` 规范化字节的 SHA-256。
* 规范化 = `sort_keys=True` + 紧凑分隔符 `,`/`:` + `ensure_ascii=False` +
  `allow_nan=False`（`model.canonical_json`）。

因此：**同一事件在任何进程/时间写出的字节完全相同**，账本文件可字节级比较
（`test_ledger_file_bytes_are_deterministic`）；任何非规范化字节（即使语义相同，
例如手工缩进过）都会被判为 `CHECKSUM_MISMATCH`。

### 2.2 append-only 与写入路径

* 文件以 `O_RDWR|O_CREAT|O_APPEND` 打开；写入缓冲 64 KiB；
  `O_APPEND` 保证单次 `write` 的偏移定位原子。
* 唯一允许的就地修改是**显式请求**的 `truncate_tail=True` 尾部修复
  （`ftruncate` + `fsync`），修复字节数记录在 `stats.tail_repaired_bytes`。
* 默认拒绝向"末尾有不完整行"的既有文件追加（`TruncatedLedgerError`）：
  宁可让调用方显式选择修复或只读恢复，也不静默把半行变成"合法"前缀。

### 2.3 生命周期

* 上下文管理器：`with JsonlEventLedger(path) as ledger:`；`__exit__` 返回
  `False`，**不吞异常**（`test_context_manager_closes_and_propagates_exceptions`）。
* `close()` 幂等；关闭后 `append`/`append_many`/`flush`/`sync`/`verify` 全部抛
  `LedgerClosedError`。
* `append` 返回 `LedgerRecord(event, line_no, offset, byte_length, checksum)`，
  供索引溯源到权威日志的具体字节区间。

### 2.4 单写入者约束（明示不支持并发写）

同一 JSONL 文件**不支持**多进程（或同进程多次打开）并发写入：

* 跨进程：`<path>.lock` 上 `fcntl.flock(LOCK_EX|LOCK_NB)`，失败即抛
  `ConcurrentWriterError`，错误信息里带当前持有者 `pid`。
  （`test_cross_process_writer_is_rejected` 用真实子进程验证。）
* 同进程：额外的进程内路径登记，避免依赖 flock 的平台差异。
* `lock=False` 只在调用方自行保证单写入者时使用（测试/工具）。
* 读取者**不握锁**：因此可能读到写入中的半行——这会被识别为
  `TRUNCATED_TAIL`，不会被当成有效事件。

---

## 3. Crash consistency 与 fsync 取舍

### 3.1 崩溃下能保证什么

| 情形 | 结果 | 依据 |
|---|---|---|
| 进程在 `write` 到账本中途被杀 | 末尾可能出现半行 | `scan_ledger` 报 `TRUNCATED_TAIL`，**之前所有完整行仍可读** |
| 半行之后又追加了新行（外部工具绕过本模块） | 半行不再是末行 | 报 `MALFORMED_LINE`（无法与后续字节重新同步时按超长行处理） |
| 内核在 `fsync` 返回前掉电 | 依赖策略；见 §3.2 | `ALWAYS`/`BATCH` 只承诺"已 fsync 的部分" |
| 同一事件因重试被写两次 | 两行都在，第二行报 `DUPLICATE_EVENT_ID` | 回放/索引取首次出现，天然幂等 |
| 索引写失败/索引文件被删 | 权威日志不变 | 索引是可重建派生物（§4） |

关键不变式：**每一行要么是完整且校验通过的事件，要么会被扫描明确报告**。
不存在"半行被当作合法事件"的路径。

### 3.2 三档 fsync 策略

| 策略 | 行为 | 崩溃时可能丢什么 | 适用 |
|---|---|---|---|
| `ALWAYS` | 每条 `append` 后 `flush` + `os.fsync` | 不丢已返回的事件 | 审计关键路径；吞吐最低 |
| `BATCH`（默认） | 每 `fsync_every_lines` 行（默认 128）+ `flush()`/`close()` 时 fsync | 最多最后 <128 行 | 常规采集：吞吐与可容忍丢失的折中 |
| `NEVER` | 只 `flush` 到 OS，全程不 fsync | 崩溃/断电可能丢掉整段缓冲 | 测试、临时回放、可丢弃数据 |

`flush()` 默认按策略决定是否 fsync；`flush(fsync=True)` / `sync()` 可强制落盘；
`stats.fsyncs` 与 `stats.pending_lines` 暴露实际行为，避免"以为 fsync 了"。
`NEVER` 是**显式**选择，不是默认：默认策略不允许静默降低持久性保证。

### 3.3 扫描时检测的完整性问题（`IssueKind`）

| 分类 | 触发条件 | 处理 |
|---|---|---|
| `TRUNCATED_TAIL` | 末行无换行（崩溃/写入中断） | 丢弃该行，保留此前所有事件 |
| `MALFORMED_LINE` | JSON 解析失败 | 丢弃该行 |
| `OVERSIZED_LINE` | 单行 > `MAX_LINE_BYTES` | 丢弃并重新同步到下一行 |
| `CHECKSUM_MISMATCH` | `checksum` 或 `len` 与实际规范化字节不符 | 丢弃该行 |
| `ENVELOPE_INVALID` | 非对象信封 / 信封版本不支持 / 缺 `event` | 丢弃该行 |
| `SCHEMA_UNSUPPORTED` | 事件 `schema_version` 不在支持集合 | 丢弃该行 |
| `EVENT_INVALID` | 信封与校验值都对，但事件未通过字段校验 | 丢弃该行 |
| `DUPLICATE_EVENT_ID` | `event_id` 重复 | 保留首次出现，丢弃后续行 |
| `OUT_OF_ORDER` | 同一 `(run_id, source)` 内 `monotonic_ns` 回退 | **保留事件**，仅作数据质量告警 |

空行（纯空白）被跳过且不计为问题（便于日志拼接）；其余一切异常都可见。
`ScanResult.issue_counts` / `kinds_causing_skips()` 把"丢弃"与"仅告警"分开。

### 3.4 单调时间与顺序的适用边界

* `monotonic_ns` 是 `CLOCK_MONOTONIC`：只在**同一 boot**内有意义，
  跨 boot 比较无意义；重启后的时间会重新开始。
* 跨 **CPU**：现代内核的 `CLOCK_MONOTONIC` 由 clocksource 统一，
  但不同 CPU 上的读取点之间存在无界偏移，**不保证全局严格序**。
* 跨 **来源**：eBPF（内核时间戳）与用户态 uprobe 打点的时间基准、
  以及事件穿过 ring buffer 的延迟都不同，不能混成单一时间轴。
* 因此本实现只在 `(run_id, source)` 内做回退检测与序号空洞统计；
  跨来源排序只能做"近似时间窗"关联（M3 的职责）。

---

## 4. SQLite：派生的可重建索引

### 4.1 定位

* 索引**只**存派生物：`event_json`（规范化事件）+ `event_checksum` +
  为查询抽取的列（run/时间/pid/type/result/…）+ `ledger_line`/`ledger_offset`。
* 语义判定一律回到 `event_json`：查询重建 `Event` 时仍走完整校验，
  索引列不是第二套真值。
* 删除索引文件（含 `-wal`/`-shm`）后可从 JSONL 完整重建
  （`test_rebuild_from_deleted_index_file`、`test_replay_into_deleted_index_rebuilds_from_ledger`）。

### 4.2 事务与故障语义

* 写入用 `BEGIN IMMEDIATE` + 单次 `COMMIT`；任何 `sqlite3.Error` 触发
  `ROLLBACK` 并抛 `IndexWriteError("…已回滚")`，**不会留下半批数据**
  （`test_transaction_rolls_back_on_failure` 用 `RAISE(ABORT)` 触发器强制复现）。
* 索引写入**从不**回写/截断/修补 JSONL；测试对比失败前后的文件字节与
  `ledger_digest` 证明权威日志不受影响。
* **幂等键是 `(event_id, 事件校验值)`，不是单独的 `event_id`**：

  | 情形 | 行为 |
  |---|---|
  | 同 `event_id` + 同校验值（含同批内重复） | 幂等重复：只写一次，计入 `duplicates` |
  | 同 `event_id` + 不同校验值，与库内已有行冲突 | 抛 `IndexConflictError`，整批回滚，**不保留旧内容也不写入新内容** |
  | 同 `event_id` + 不同校验值，同一批内两条互相矛盾 | 同上（批内冲突也会被检测） |
  | 同 `event_id` + 不同校验值，但 `reset=True` 重建 | 允许：重建语义是"以这批输入为准" |

  `IndexConflictError` 是 `IndexWriteError` 的子类，错误信息里带上冲突的
  `event_id` 与两侧校验值。冲突检测在插入之前、同一事务内完成，因此
  同批的**其他合法新事件也不会落库**（全有或全无），索引也不会被"后写覆盖"。
  处理冲突的正确方式是检查数据来源；确实需要以新内容为准时，用
  `replay_into_index(..., reset=True)` 从权威 JSONL 整批重建。
* 重建两次得到相同行数与 `digest`（`test_rebuild_is_idempotent`）。
* 耐久性取舍：索引为 WAL + `synchronous=NORMAL`。索引可重建，
  所以宁可用"崩溃可能丢最后若干事务"换取吞吐；**权威日志的 fsync 语义不受影响**。

### 4.3 查询与一致性

* `query(run_id=…, event_types=…, source=…, pid=…, process_start_id=…,
  result=…, since_ns=…, until_ns=…, time_field=…, limit=…, offset=…)`
  以及便捷方法 `events_for_run` / `events_in_time_range` /
  `events_for_process` / `events_of_type` / `count`。
* 默认按**权威顺序**返回：`ledger_line` 优先，其次插入顺序。
  时间范围查询请显式选 `time_field`（默认 `monotonic_ns`；
  跨 boot 或需要墙钟时用 `wall_time`，但墙钟可被 NTP 调整）。
* `digest()` 基于每行 `event_json` **重新计算**校验值后再摘要，
  与 `ledger_digest(records)`（`sha256` over `event_id:checksum` 行序列）同规则比较：
  只要索引内容与权威日志一致，两者必然相等。
* `verify_integrity()` 逐行核对"存储校验值 vs 实际内容"；
  `verify_against_ledger(ledger, index)` 返回
  `ConsistencyReport(ledger_events, index_rows, ledger_digest, index_digest, matches)`。
  不一致时的正确动作是**删索引重建**，而不是修补索引。
* `read_only=True` 打开只读索引；`close()` 后所有操作抛 `IndexClosedError`。

---

## 5. 丢失与数据质量：真值边界

### 5.1 四类已知传输层丢失（`LossKind`）

| 分类 | 观测来源 |
|---|---|
| `sequence_gap` | ①逐条 `seq` 推导（本模块）②`quality.sequence_gap` 事件 |
| `ring_drop` | `quality.ring_drop` 事件 / `quality.counter_snapshot` |
| `user_queue_drop` | `quality.queue_drop` 事件 / 计数器快照 |
| `storage_drop` | `quality.storage_drop` 事件 / 计数器快照 |

生产者**二选一**：若逐条发 `seq`（且保证同一 `(run_id, source)` 只有一条连续序列），
就不要再发 `quality.sequence_gap`，否则同一段空洞会被重复计数。使用 per-CPU
序号时必须在探针内聚合，或置 `seq=None` 并改用显式 gap 事件
（gap 事件的 `stream` 字段可携带更细粒度）。序号**回退**单独计入
`sequence_regressions`，不算作空洞。

### 5.2 零丢失的含义（必须与报告一起引用）

`LossSnapshot` 携带：

```
coverage_scope            = "known_transport_layers_only"
probe_coverage_complete   = False     # 恒定，不可被计数值推翻
known_transport_lost      = Σ loss
zero_known_loss           = (known_transport_lost == 0)
```

也就是说：**"零丢失"只说明 ring buffer → 用户态队列 → 磁盘这条已知链路没有丢**。
它不说明：

* 内核挂点缺失（`mmap` 写、`io_uring`、未 hook 的库/协议）；
* 语义过滤（例如只采某 cgroup）、短命进程/极短窗口的漏采；
* 探针根本没运行、或 `result=unknown` 的比例（那是"未判定"而非"丢失"）。

报告必须同时给出：`events_observed`、`lines_total`、`issues`、四类丢失计数，
以及覆盖率声明；`LossSnapshot.to_dict()` 直接输出这些字段，避免被拆散引用。

### 5.3 快照能力

* `LossCounters` 线程安全（`observe`/`record_loss`/`record_issue`/`add_issues`/
  `snapshot`），适合采集循环与账本扫描线程共用。
* `LossSnapshot.merged(other)` 支持多来源/多段合并；`to_dict`/`from_dict`
  用于报告序列化。
* 非法输入（未知分类、负数计数、非整数）一律抛 `LossCounterError`。

---

## 6. 离线重放

* `iter_records(path)` / `iter_events(path)`：流式扫描，`issues=[...]` 可收集问题，
  大账本不必整体载入内存。
* `replay(path)`：只读分析，返回
  `ReplayResult(scan, snapshot, digest, index=None)`；`snapshot` 已并入
  扫描问题计数与逐条 `seq` 空洞。
* `replay_into_index(path, index, reset=True)`：默认先清空再写入，因此
  **重复重放幂等**；`index` 可以是已打开的 `SqliteIndex`（不会被关闭）或路径。
* 重放顺序 = 账本追加顺序（权威顺序），不是全局时间顺序；同一账本重复重放
  得到相同 `digest` 与相同记录序列。
* `verify_against_ledger(path, index)` 只报告一致性，不做修复。

---

## 7. Schema 演进

**事件 schema（`schema_version`）**

1. 兼容添加（新事件类型、新的可选 payload 字段、新的可空头字段）：
   递增到新版本号，同时把旧版本加入 `SUPPORTED_SCHEMA_VERSIONS`，
   并在本文件登记"新增了什么、默认值/缺失语义是什么"。
   读取侧用 `PRESERVE` 保留未知字段，让新写旧读不丢数据。
2. 不兼容变更（改字段语义、删必填字段、改类型、收紧枚举）：
   必须递增 `schema_version` **并新增字段**而非复用旧名；
   旧版本事件若无法忠实解释，则应保持"不支持"，扫描时报
   `SCHEMA_UNSUPPORTED`，而不是尽力猜测。
3. 事件类型与字段表是显式白名单：新增类型必须同时提供字段表、
   必填项、边界与跨字段约束，否则默认 `REJECT` 会直接拒绝生产数据。

**信封格式（`v`）** 与**索引结构（`INDEX_SCHEMA_VERSION`）** 独立演进：
索引结构变更时直接重建（索引可丢弃），不需要迁移脚本。

版本落位：`model.SCHEMA_VERSION` / `ledger.ENVELOPE_VERSION` /
`index.INDEX_SCHEMA_VERSION` 是唯一来源，改动必须同步本文件与测试。

---

## 8. M2 验收方法

### 8.1 门禁命令（离线，使用 `rtk` + 指定 Conda 环境）

```bash
rtk conda run -n ms_pointcloud_midterm python -m pytest tests/events -q   # 本任务范围
rtk conda run -n ms_pointcloud_midterm python -m pytest -q                # 全仓库回归
rtk conda run -n ms_pointcloud_midterm python -m compileall -q src/agent_probe/events
```

测试全部使用 `tmp_path`，不写仓库、不联网、不依赖已安装包（`src` 由
`pyproject.toml` 的 `pythonpath` 注入）。

### 8.2 每个测试文件证明什么

| 文件 | 覆盖的验收点 |
|---|---|
| `tests/events/test_model.py` | 头字段完整性；负数/枚举/UUID/JSON 可序列化/最大字节数/嵌套深度等边界；`result` 与 `error_code` 一致性；未知字段两种策略；Unicode（中文/emoji/星形平面）往返；全部 17 类事件的最小合法样本 |
| `tests/events/test_ledger.py` | round-trip 与信封校验值；三档 fsync；`close` 后拒写与异常不吞；同进程与**跨进程**并发写检测；尾行截断检测与显式修复；校验错/重复/不支持 schema/坏 JSON/超长行/乱序；空行；确定性字节；`verify` 只读 |
| `tests/events/test_index.py` | 事务回滚（触发器强制失败）；索引失败不触碰权威日志；**幂等（同 ID 同内容）vs 完整性冲突（同 ID 不同内容、跨批与批内）** 与全批回滚；幂等重建与删除后重建；按 run/时间/进程/类型/分页查询；只读索引；关闭行为；摘要与 `verify_against_ledger` 检出篡改 |
| `tests/events/test_quality.py` | 四类丢失分类、序号空洞推导与回退区分、计数器快照、线程安全、快照序列化/合并/不可变、零丢失覆盖范围声明 |
| `tests/events/test_replay.py` | 重放顺序与确定性；问题与丢失计数并入快照；截断尾行确定性排除；索引幂等重放；一致性报告；`PRESERVE` 离线回放 |

### 8.3 端到端手工核验（库层，不依赖 CLI）

```python
from pathlib import Path
from agent_probe.events import (
    EventType, JsonlEventLedger, LossCounters, new_event, new_run_id,
    replay_into_index, verify_against_ledger, SqliteIndex,
)

run = new_run_id()
run_dir = Path("runs") / run            # 运行产物目录（.gitignore 已忽略）
with JsonlEventLedger(run_dir / "events.jsonl") as ledger:
    ledger.append(new_event(
        run_id=run, event_type=EventType.FILE_OPEN,
        payload={"path": "/work/a.txt", "flags": 0, "fd": 3},
        pid=4242, tid=4243,
    ))

result = replay_into_index(run_dir / "events.jsonl", run_dir / "index.sqlite")
print(result.snapshot.to_dict())        # 丢失/数据质量 + 覆盖范围声明
with SqliteIndex(run_dir / "index.sqlite") as index:
    print(verify_against_ledger(run_dir / "events.jsonl", index).matches)  # True
```

判定标准：`matches is True`、`snapshot.issues` 为空、`zero_known_loss` 为真；
同时必须照抄 `probe_coverage_complete = False` 与 `coverage_scope` 一并陈述。

### 8.4 M2 计划中仍需真实探针完成的部分

本任务只交付账本**核心**。下列 M2 验收项需要 eBPF 侧配合后才能给出数字：
≥30 类操作夹具的真值比对、`strace`/`auditd` 交叉验证、30 分钟额定负载与
过载测试、第 4 周的资源预算冻结。账本已提供的接口是：
真值比对用 `scan_ledger` + `LossSnapshot`，过载指标用
`LedgerWriteStats`（写入行数/字节/fsync 次数）与四类丢失计数。

---

## 9. 不在范围

* eBPF C 探针、ring buffer、`uprobe`/`tracepoint` 挂点（M2 采集侧，未实现）。
* CLI 子命令与报告（M4）；本子包不注册任何 `probe` 命令。
* `mmap` 写、`io_uring`、静态链接 TLS、HTTP/2 等采集盲区（计划中显式列为不支持）。
* 关联引擎（M3）、策略与执行控制（M5）。
* 抵抗 root 的防篡改：本实现提供完整性**检测**（校验值、重复、截断），
  不提供密钥签名与抗篡改存储。

## 10. 已知限制

1. 单写入者：同一 JSONL 不支持并发写，已检测并文档化（§2.4）。
2. `monotonic_ns` 不是全局时间序：跨 boot/CPU/来源均不可直接比较（§3.4）。
3. `BATCH` 策略下崩溃可能丢最后 <`fsync_every_lines` 行；`NEVER` 可能丢整段缓冲——
   两者都是显式选择，默认策略不允许静默降低持久性保证。
4. 索引为派生数据：与日志不一致时一律**重建**，不提供增量修复；
   同 `event_id` 不同内容的输入会被 `IndexConflictError` 拒绝（不会被静默覆盖或忽略）。
5. `PRESERVE` 策略下未知字段不会被解释，也不会进入索引列（只在 `event_json` 内）。
6. 索引查询默认按权威顺序；跨 `wall_time` 的全局排序可能受 NTP 调整影响。
7. 根包 `agent_probe` 仍只导出 `__version__`；对外能力通过
   `agent_probe.events` 使用，CLI 集成留待后续里程碑。
