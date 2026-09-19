# 01 · M1：LLM 请求重建与计账（离线纯 Python 核心）

> 里程碑：plan.md 的 **M1**。本文只描述 `src/agent_probe/llm/` 这一个离线库：
> 从"TLS uprobe 已采集的有序明文字节片段"重建 HTTP/1.1 JSON/SSE 消息，并提取
> usage 与版本化费用估算。
>
> **不在本文范围**：eBPF 采集本身（M0）、事件账本（M2）、CLI 集成（M4）。
> 本库不打开套接字、不读磁盘、不访问网络、不依赖第三方包。

---

## 1. 范围与设计原则

| 原则 | 含义 |
|---|---|
| 增量、有界 | `feed(direction, bytes)` 接受**任意分片**（含逐字节）；所有缓冲都有上限，超限产出诊断而不是静默截断。 |
| 不伪造 | 数据不完整时产出 `complete=False` 的消息 + 类型化诊断；绝不猜测字节边界（非法 chunk / 非法头部直接进入 `FAILED`）。 |
| 事实与推断分离 | 传输层完整性（`StreamCompletion`）与提供方语义（`StopKind`）是两个独立维度。 |
| 缺失即未知 | usage 缺失记为 `None`，不填零；费用缺失记为 `cost = None`（unknown），不填 0，也不拿部分金额冒充总额。 |
| 隐私默认 | 敏感头/`target` 参数在**进入模型时**就被替换为 `<redacted>`；唯一推荐的持久化视图 `to_record()` 不含任何正文。 |
| 不推断重试 | `logical_call_id` 只能由调用方**显式**声明；本库没有"按时间/相似度推断重试"的入口。 |

---

## 2. 模块与 API

```
agent_probe.llm
├── common.py       Direction / MessageKind / BodyFraming
├── diagnostics.py  DiagnosticCode / Severity / Diagnostic
├── limits.py       ParserLimits / SseLimits
├── messages.py     HttpMessage/HttpRequest/HttpResponse + 脱敏策略
├── http1.py        Http1Parser（状态机）/ ParseBatch
├── sse.py          SseParser / SseEvent / SseFinish
├── usage.py        TokenUsage / UsageExtraction / UsageStatus
├── completion.py   PayloadAnalysis / StreamCompletion / StopKind / analyze_payload
├── pricing.py      PriceTable / ModelPrice / CostEstimate / estimate_cost
├── calls.py        CallIdentity / RetryRegistry / LlmCallRecord / AccountingLedger
└── reconstruct.py  ConnectionReconstructor / MultiConnectionReconstructor
```

### 2.1 最小用法

```python
from agent_probe.llm import (
    Direction, MultiConnectionReconstructor, AccountingLedger, DEFAULT_PRICE_TABLE,
)

reconstructor = MultiConnectionReconstructor(price_table=DEFAULT_PRICE_TABLE)
# 每次 uprobe 回调按 (连接, 方向) 喂入即可，分片边界任意：
reconstructor.feed("conn-1", Direction.CLIENT_TO_SERVER, request_bytes)
batch = reconstructor.feed("conn-1", Direction.SERVER_TO_CLIENT, response_bytes)

for record in batch.records:
    record.request_index, record.status_code      # 物理请求序号 / 状态
    record.usage.status, record.usage.usage       # usage 可得性 / 具体计数
    record.completion.completion                  # complete / truncated / unknown
    record.cost.total_cost, record.cost.complete  # Decimal 或 None（unknown）
    record.to_record()                            # 可持久化视图（无正文、无凭据）

reconstructor.close("conn-1")                     # TCP/TLS 关闭：冲刷 close-delimited 正文
ledger = AccountingLedger()
ledger.extend(reconstructor.records)
summary = ledger.summary()                        # 见 §9 指标分母
```

### 2.2 关键 API 速查

| API | 用途 |
|---|---|
| `Http1Parser.feed(bytes) -> ParseBatch` | 单方向增量解析；`ParseBatch.messages/diagnostics` |
| `Http1Parser.finish() -> ParseBatch` | 声明该方向 EOF（幂等）；产出 close-delimited 正文、提前 EOF 诊断 |
| `Http1Parser.register_request(method)` | 告知响应方向"待配对请求的方法"（HEAD/CONNECT 分帧判定） |
| `SseParser.feed(str|bytes)` / `.finish() -> SseFinish` | SSE 分帧；`finish` 给出 `saw_done`/`truncated`/残留计数 |
| `analyze_payload(message, sse_limits=...) -> PayloadAnalysis` | 一条消息的 usage + 完整性 + 模型名 + 诊断 |
| `extract_usage_from_json[_object] / _from_sse_events / _from_message` | 分层 usage 提取入口 |
| `estimate_cost(usage=, usage_status=, price_table=, model=)` | Decimal 费用估算 |
| `RetryRegistry.link_retry(...) / declare_logical_call(...)` | **显式**重试/逻辑调用登记 |
| `AccountingLedger.record/extend/summary` | 按 `physical_request_id` 去重的计账汇总 |
| `ConnectionReconstructor.feed/finish`、`MultiConnectionReconstructor.feed/close` | 连接级/多连接级门面 |

---

## 3. HTTP/1.1 状态机

```
            ┌───────────────────────────────────────────────┐
            ▼                                               │
        ┌───────┐  起始行+头部块（以空行结束）  ┌──────────────────┐
        │ START │────────────────────────────▶│ 分帧判定 _plan_body│
        └───────┘                             └──────────────────┘
            ▲                                   │      │       │
            │                        Content-Length  chunked  close/无 CL
            │                                   │      │       │
            │                          ┌────────────┐  │   ┌──────────┐
            │                          │ FIXED_BODY │  │   │ EOF_BODY │
            │                          └────────────┘  │   └──────────┘
            │                                   │      ▼
            │                                   │  ┌────────────┐
            │                                   │  │ CHUNK_SIZE │◀────────┐
            │                                   │  └────────────┘         │
            │                                   │      ▼                 │
            │                                   │  ┌────────────┐        │
            │                                   │  │ CHUNK_DATA │        │
            │                                   │  └────────────┘        │
            │                                   │      ▼                 │
            │                                   │ ┌─────────────────┐    │
            │                                   │ │ CHUNK_DATA_CRLF │────┘
            │                                   │ └─────────────────┘
            │                                   │      ▼（0 长度块）
            │                                   │ ┌───────────────┐
            │                                   │ │ CHUNK_TRAILER │
            │                                   │ └───────────────┘
            └─────────── _finalize（产出消息，回到 START）◀─────────────┘

        任何致命错误 ──▶ FAILED（丢弃后续字节；failed / failure 暴露原因）
```

要点：

* 一条消息 `_finalize` 后**立即**从同一缓冲区继续解析下一条 → 连接复用天然按消息边界连续产出。
* 消息之间的空行（CRLF/LF）按 RFC 9112 §2.2 容忍跳过。
* `HTTP/1.0` 容忍解析并标注（`http10_message`）；`HTTP/2` 连接前言、`HTTP/1.1` 之外的版本进入 `FAILED`。
* 分帧判定优先级：`chunked` > `Content-Length` > close-delimited；两者同时出现记 `conflicting_framing`（按 RFC 以 chunked 为准）。
* 响应无 `Content-Length`/`chunked` 且未捕获对应请求方法时，按连接关闭界定正文并记 `body_framing_ambiguous`。
* `1xx` 不算正文也不消耗请求配对；`HEAD` 响应无正文；`2xx CONNECT` 之后字节不再是 HTTP → 记 `connect_tunnel_unsupported` 并进入 `FAILED`。

---

## 4. 诊断码（稳定契约）

`DiagnosticCode` 是 `str` 枚举，值即下表；诊断**不含正文与凭据**，只有结构描述。
`fatal=True` 表示该方向已无法安全继续解析。

| 分组 | 诊断码 |
|---|---|
| 协议识别 | `http2_preface` · `unsupported_http_version` · `http10_message` · `malformed_start_line` · `start_line_too_large` |
| 头部 | `header_section_too_large` · `too_many_headers` · `malformed_header` · `obsolete_line_folding` · `conflicting_framing` · `malformed_content_length` · `unsupported_transfer_encoding` · `unsupported_content_encoding` |
| 正文 | `body_too_large` · `decompressed_too_large` · `gzip_decode_error` · `gzip_truncated` · `gzip_trailing_data` · `invalid_chunk_size` · `malformed_chunk` · `chunk_line_too_large` · `trailer_too_large` · `body_framing_ambiguous` · `connect_tunnel_unsupported` |
| 生命周期 | `premature_eof` · `parse_failed` · `message_after_connection_close` |
| 配对 | `response_without_request` · `request_without_response` · `duplicate_physical_request` |
| SSE | `sse_event_too_large` · `sse_truncated` · `sse_missing_done` |
| usage | `usage_absent` · `usage_unparseable` · `usage_not_captured` |
| 费用 | `model_unknown` · `model_not_priced` · `cache_price_missing` · `cache_inclusion_unknown` · `price_table_unverified` |

`Diagnostic.to_record()` → `{code, severity, detail, fatal, direction, message_index, stream_offset}`。
消息级诊断也会出现在对应 `LlmCallRecord.diagnostics` 中（同一条诊断可能同时出现在
`ParseBatch.diagnostics` 与消息的 `diagnostics` 里，这是有意为之：批次是流级日志，消息携带自身的证据子集）。

---

## 5. 上限（有界性）

| 配置项 | 默认 | 超限行为 |
|---|---:|---|
| `max_start_line_bytes` | 8 KiB | `start_line_too_large`，致命 |
| `max_header_bytes` | 64 KiB | `header_section_too_large`，致命；**未找到空行时也按此上限拒绝继续缓冲** |
| `max_headers` | 256 | `too_many_headers`，致命 |
| `max_body_bytes` | 8 MiB | `body_too_large`，**非致命**：继续消费字节保持分帧对齐，但不再缓冲（`payload_truncated=True`） |
| `max_decompressed_bytes` | 32 MiB | `decompressed_too_large`，非致命：停止解压并标记截断（zip bomb 防护） |
| `max_chunk_line_bytes` | 1 KiB | `chunk_line_too_large`，致命 |
| `max_trailer_bytes` | 8 KiB | `trailer_too_large`，致命 |
| `max_pending_requests` | 64 | 丢弃最旧请求上下文并计入 `dropped_request_contexts` |
| `SseLimits.max_event_bytes` | 1 MiB | `sse_event_too_large`，停止该流 |
| `SseLimits.max_data_lines` | 4096 | `sse_event_too_large`，停止该流 |

"分帧完整但正文被截断"是显式状态：`message.complete is True` 而
`message.payload_complete is False`。`payload_complete` 同时要求消息完整、解码成功、
未被上限丢弃——因此下游不会把截断内容当成完整 JSON 解析。

---

## 6. 隐私默认值

脱敏在消息**构造时**完成，原始值不进入数据结构：

1. **敏感头名精确匹配**：`authorization`、`proxy-authorization`、`cookie`、`set-cookie`、
   `x-api-key`、`api-key`、`x-auth-token`、`x-goog-api-key`、`x-amz-security-token` …
2. **头名子串匹配**：`authorization`、`auth`、`api-key`、`apikey`、`secret`、`password`、
   `credential`、`token`、`cookie`、`session`（宁可过度脱敏）。
3. **头值已知凭据形状**（辅助）：`sk-…`、`AIza…`、`ghp_…`、`AKIA…`、`xox…`、
   `Bearer <token>`、PEM 私钥头。这不是通用秘密探测器。

`request target` 中敏感查询参数（`key`/`token`/`secret`/`password`/`credential`/`sig` 子串）
同样替换为 `<redacted>`，被替换的参数名记录在 `redacted_query_params`。

持久化视图：

* `HttpMessage.to_record()` / `LlmCallRecord.to_record()` / `AccountingSummary.to_record()`
  **不含正文**；敏感头的值只有占位符，头名保留（便于审计"是否存在凭据"）。
* 需要正文指纹时用 `to_record(include_payload_hash=True)`，只给出 SHA-256，不给原文。
* 正文在内存中保留（解析必需），任何日志/持久化路径都由上面这些视图负责。
* 本库不写文件、不打日志。

---

## 7. SSE 语义与完整性判定

SSE 按 WHATWG 事件流规范的子集实现：

* 行终止符支持 `CRLF`/`LF`/`CR`，允许跨任意分片；流首 BOM 忽略。
* `data` 多行用 `\n` 连接；**空行**分帧；`event`/`id`/`retry` 保留；以 `:` 开头为注释。
* `data` 为 `[DONE]` 时 `is_done=True`（OpenAI 兼容哨兵）。
* EOF 时未分帧的残留**按规范丢弃**，并产出 `sse_truncated`；缺失 `[DONE]` 记
  `sse_missing_done`（警告，不是错误）。

**完整性判定（`StreamCompletion`）只看字节层证据：**

| 情况 | 判定 |
|---|---|
| 收到 `[DONE]` 或终止事件（`message_stop` / `response.completed`） | `COMPLETE` |
| 字节被截断（提前 EOF / 正文超限 / 未分帧残留），且无终止事件 | `TRUNCATED` |
| 干净结束 + 观察到 `finish_reason`（无截断） | `COMPLETE` |
| 干净结束、无任何终止证据 | `UNKNOWN`（不臆断为断流） |
| 非 SSE 的 JSON 正文分帧完整且可解析 | `COMPLETE`（`http_message_complete`） |

**`finish_reason` 语义（`StopKind`）与之正交：**

`length` → `LENGTH`、`content_filter` → `CONTENT_FILTER`、`tool_calls` → `TOOL_CALLS`、
`stop`/`end_turn`/`stop_sequence` → `STOP`、未知取值 → `OTHER`。
**任何非 `stop` 的 `finish_reason` 都不会被判成断流**；它只影响"为什么停止"的解释，
并原样保存在 `CompletionAnalysis.finish_reasons`。

---

## 8. provider-neutral usage 模型

```python
TokenUsage(
    model, input_tokens, output_tokens, total_tokens,
    cache_read_tokens, cache_write_tokens, reasoning_tokens,
    cache_read_included_in_input, cache_write_included_in_input,
    reasoning_included_in_output,   # 三态 True/False/None
    provider, fields_reported, raw,
)
```

* **缺失即 `None`**：只有提供方明确返回过的字段才有值；`fields_reported` 记录实际出现的字段。
  显式的 `0` 会保留为 `0`（与缺失区分）。
* **包含关系三态**：缓存/推理明细是否已计入对应总量。已知语义直接标注：
  `prompt_tokens_details.cached_tokens` → 已包含（`True`）；
  `cache_read_input_tokens` / `cache_creation_input_tokens` → 未包含（`False`）；
  未知来源 → `None`，计费时按"不完整"处理。

| 概念 | 字段别名 |
|---|---|
| 输入 | `prompt_tokens` · `input_tokens` |
| 输出 | `completion_tokens` · `output_tokens` |
| 总量 | `total_tokens` |
| 缓存读 | `prompt_tokens_details.cached_tokens` · `input_tokens_details.cached_tokens` · `cache_read_input_tokens` |
| 缓存写 | `cache_creation_input_tokens` · `prompt_tokens_details.cache_creation_tokens` |
| 推理 | `completion_tokens_details.reasoning_tokens` · `output_tokens_details.reasoning_tokens` |

usage 容器位置：`usage`、`message.usage`（Anthropic `message_start`）、`response.usage`
（Responses API 事件）。SSE 侧按事件顺序**浅合并**，后到的非空字段覆盖先到的：
OpenAI 兼容流只在末尾 chunk 带完整 usage；Anthropic 把输入放在 `message_start`、
输出放在 `message_delta`，两者字段不相交。

`UsageStatus` 四种状态（对应 M1"明确区分捕获失败、解析失败和提供方未返回 usage"）：

| 状态 | 含义 |
|---|---|
| `present` | 有 usage 且至少一个计数字段 |
| `absent` | 正文完整可解析，但提供方没返回 usage（如 SSE 未开 `include_usage`） |
| `unparseable` | 拿到了正文，但 JSON/结构解析失败 |
| `not_captured` | 正文缺失或被截断，**无法判断**提供方是否返回过 usage |

---

## 9. 版本化价格表与费用估算

```python
PriceTable(version, effective_date, entries, currency="USD",
           unit=PricingUnit.PER_MILLION_TOKENS, provenance=..., verified=False)
ModelPrice(model, input_per_unit, output_per_unit,
           cache_read_per_unit=None, cache_write_per_unit=None)
```

* 价格值必须是 `Decimal`/`int`/`str`；传 `float` 直接 `TypeError`（避免二进制误差）。
  估算与序列化全程 `Decimal`，`to_record()` 输出十进制字符串。
* 模型查找：先精确匹配，再**最长前缀**匹配，且前缀必须落在边界字符（`-`/`.`/`:`/`@`/`/`）上，
  因此 `gpt-4o-mini-2024-07-18 → gpt-4o-mini`，而 `gpt-4oX` 不匹配 `gpt-4o`。
* 计费分项：`input`、`output`、`cache_read`、`cache_write`。缓存命中已包含在输入总量中时
  （`cache_read_included_in_input is True`）先扣除再计价，避免重复计费。
* `CostEstimate` 记录 `currency`、`unit`、`effective_date`、`price_table_version`、
  `price_table_verified`、`matched_price_model`、`components`、`priced_subtotal`、
  `total_cost`、`complete`、`unknown_reasons`、`notes`。

`complete` 与 `total_cost` 规则：

| 条件 | 结果 |
|---|---|
| usage 为 `absent`/`unparseable`/`not_captured` | `total_cost=None`，原因 `usage_*` |
| usage 为空对象 | `total_cost=None`，原因 `usage_empty` |
| 模型名未知 / 不在表中 | `total_cost=None`，原因 `model_*` |
| 缺少输入或输出计数 | `total_cost=None`，`priced_subtotal` 给出已计价部分，原因 `*_tokens_missing` |
| 缓存明细存在但包含关系未知 / 缺缓存单价 | `total_cost=None`，原因 `cache_*` |
| 以上都不成立 | `complete=True`，`total_cost=Σ components` |

内置 `DEFAULT_PRICE_TABLE` 的 `verified=False`：数值仅用于离线夹具与格式演示，
**本里程碑未做厂商核验**，估算结果会附带"不得用于账单对照"的提示。任何真实对照都必须
换成本项目自行核验、带 `effective_date` 的价格表（`PriceTable.from_json` 可直接加载）。

---

## 10. 标识、重试与去重计账

| 概念 | 说明 |
|---|---|
| `physical_request_id` | 一次物理 HTTP 往返；`ConnectionReconstructor` 按 `f"{connection_id}:req:{request_index}"` 确定性生成（`request_index` 即该方向的物理请求序号）。 |
| `logical_call_id` | 一组重试共享的逻辑调用；**默认等于 `physical_request_id`**。 |
| `CallIdentity` | `physical_request_id`、`logical_call_id`、`attempt_index`、`retry_of`、`retry_reason`、`retry_evidence`。 |
| `RetryEvidence` | `none` / `explicit_caller` / `application_marker`（**没有**"按时间推断"这一档）。 |

显式登记方式（`RetryRegistry`）：

```python
registry.link_retry(physical_request_id="conn-1:req:2",
                    retry_of="conn-1:req:1", reason="429",
                    evidence=RetryEvidence.APPLICATION_MARKER)
registry.declare_logical_call("conn-1:req:2", "logical-42")   # 可选：自定义逻辑名
```

* 逻辑调用名取**同一重试家族内**第一个显式声明的名字，否则退化为家族根；
  因此"在某个重试节点上声明"会覆盖整个家族，不会把一个逻辑调用拆成两个。
* 分支（同一原始请求的多次重试）也支持；`attempt_index` 为到根的深度。
* 成环 → `RetryCycleError`；自环 / 空 reason / `evidence=NONE` → `ValueError`。

`AccountingLedger` 以 `physical_request_id` **去重**：同一条物理请求被重复投递时只计一次，
重复次数单列（`duplicate_physical_requests`），避免重放/重复事件导致重复计账。
重试的每一次物理请求**都**计费（token 真被消耗），但 `logical_calls` 只算一次。

---

## 11. 支持 / 不支持矩阵

| 能力 | 状态 | 说明 |
|---|---|---|
| HTTP/1.1 请求/响应重建 | ✅ 支持 | 请求行/状态行、头部、连接复用、pipelining 顺序配对 |
| `Content-Length` 正文 | ✅ 支持 | 多值不一致即致命 |
| `chunked` 正文 | ✅ 支持 | 含 chunk 扩展、trailer；chunked 非末位 → 致命 |
| gzip 正文（`Content-Encoding`） | ✅ 支持 | 增量解压，多成员/尾部垃圾记 `gzip_trailing_data`（未解析） |
| `Content-Encoding: br`/`deflate`/其他 | ⚠️ 显式不支持 | 分帧继续、`payload=None` + `unsupported_content_encoding` |
| `Transfer-Encoding` 非 chunked | ⚠️ 显式不支持 | 同上；`chunked` 非末位为致命 |
| SSE `data`/`event`/`id`/`retry`/注释/多行/BOM | ✅ 支持 | WHATWG 子集 |
| OpenAI 兼容 JSON / SSE usage | ✅ 支持 | 含 `prompt_tokens_details`/`completion_tokens_details` |
| Anthropic Messages JSON / SSE usage | ✅ 支持 | 缓存读/写明细，包含关系标为未包含 |
| Responses API 风格别名 | ✅ 支持 | `input_tokens`/`output_tokens`/`input_tokens_details` |
| Gemini `usageMetadata` 等 | ❌ 未支持 | 扩展别名表即可加入，未做则显式落在 `absent`/`unparseable` |
| HTTP/2、HTTP/3 | ❌ 不支持 | 连接前言致命；不做帧解析 |
| TLS 解密 / eBPF 采集 | ❌ 不在本库 | 本库**只消费**已采集的明文字节 |
| `100-continue`、`HEAD`、`204/304`、close-delimited | ✅ 支持 | 见 §3 分帧规则 |
| `CONNECT` 隧道 | ❌ 不支持 | 记 `connect_tunnel_unsupported` 并停止该方向 |
| 压缩正文以外的字符集转换 | ➖ 不适用 | 只按 UTF-8 解析 JSON/SSE，其他编码记 `unparseable` |

---

## 12. M1 指标分母

plan.md 的 M1 验收口径是"至少 200 个受控请求，覆盖 JSON/SSE、重试、断流、usage 缺失、
压缩和连接复用；捕获率、解析成功率与 usage 一致率分别报告"。本库提供分母与分子，
**不宣称任何指标已达成**：

| 指标 | 分子 / 分母（由 `AccountingSummary` 提供） |
|---|---|
| 请求捕获率 | 分母 = 测试服务实际接收的物理请求数（**外部真值**，本库只能提供"观察到的物理请求数" `physical_requests` 与 `requests_without_response`） |
| 解析成功率 | 分母 = `requests_with_response`；分子建议用 `responses_with_payload`（正文完整可用）；`transport_truncated`、`usage_unparseable` 单列 |
| usage 可用率 | 分母 = `physical_requests`（有响应的子集）；分子 = `usage_present`；`usage_absent`/`usage_unparseable`/`usage_not_captured` 分别单列，未知 usage 不从分母中消失 |
| usage 一致率 | 分母 = `usage_present`（且参考侧也提供 usage 的请求）；逐字段比较 `TokenUsage`，注意 `cache_*_included_in_*` 三态 |
| 费用估算误差 | 分母 = 同一请求集合 + 同一 `price_table_version`；`cost_complete=False` 的记录单列，不用 `priced_subtotal` 冒充总额 |
| 中断检测 | 分母 = 全部有响应的请求；`transport_truncated` 为"判为断流"计数；`StopKind != STOP` 的记录**不计入**断流分子（避免把 `length`/`content_filter` 当断流） |
| 重试 | `retried_physical_requests`（分子）与 `physical_requests`（分母）；重试关系来自显式登记，重试单列 |
| 重复计账 | `duplicate_physical_requests` 单列，用于证明去重生效 |

`AccountingSummary.to_record()` 同时给出 `by_model` 小计（物理请求数、token、费用、
`cost_complete`），便于按模型/提供方分组报告。

---

## 13. 已知限制与遗留风险

1. **请求/响应按序配对**：HTTP/1.1 无请求 ID，本库按每个方向的到达顺序配对（支持
   pipelining）。若某个方向的捕获丢字节导致丢消息，配对会随之错位——此时会有
   `premature_eof`/`response_without_request` 等诊断，但本库不做跨连接重排。
2. **HEAD/CONNECT 判定依赖请求方向**：响应解析器需要 `register_request(method)`。
   只捕获响应时用 close-delimited 兜底并记 `body_framing_ambiguous`。
3. **配对缺口语义**：只捕获到响应时产出 `request=None` 的记录（`physical_request_id`
   形如 `…:unmatched-response:N`），它**不计入**请求捕获率分子，只作为缺口证据。
4. **`Content-Length` 与 chunked 同时出现**按 RFC 以 chunked 为准并记诊断；观测方无法
   "拒绝"，只能标注（这是与代理实现的差异）。
5. **gzip 多成员**：只解第一个成员，剩余字节记 `gzip_trailing_data`（INFO，不致命）。
6. **usage 合并策略**：SSE 侧是"后到非空覆盖先到"的浅合并。若某提供方在流中发送**增量**
   而非累计的 usage，结果会偏小——需要在 M3/M6 用真实流量核对该提供方语义。
7. **价格表未核验**：`DEFAULT_PRICE_TABLE` 仅用于夹具/格式演示；真实账单对照必须换成
   自行核验的版本化价格表。
8. **`total_tokens` 一致性未校验**：提供方给出的 `total_tokens` 与输入+输出不一致时，
   本库原样保留（不修正），因为"谁对"无法离线判定。
9. **正文在内存中**：解析需要正文，因此内存里存在提示词原文；本库只保证**默认持久化视图**
   不含原文。调试落盘（脱敏 + 保留期限）属于后续里程碑。
10. **秘密检测是启发式**：头名规则为主，值形状规则为辅；把密钥写进无害头名且不符合已知
    形状时不会被脱敏。

---

## 14. 复现与门禁

```bash
# 仅本库测试（离线；不打网络）
rtk conda run -n ms_pointcloud_midterm python -m pytest tests/llm -q

# 全仓测试
rtk conda run -n ms_pointcloud_midterm python -m pytest -q

# 语法编译检查
rtk conda run -n ms_pointcloud_midterm python -m compileall -q src/agent_probe/llm
```

测试规模（本里程碑）：`tests/llm/` 共 **274** 个用例，全部使用内存字节夹具：

| 文件 | 用例数 | 覆盖 |
|---|---:|---|
| `test_http1_parser.py` | 64 | 任意分片（含逐字节、所有单点切分）、连接复用、chunked、gzip、各类错误与脱敏 |
| `test_sse_parser.py` | 19 | 空行分帧、多行 data、CRLF/CR/LF、`[DONE]`、截断、上限 |
| `test_usage.py` | 32 | JSON/SSE/Anthropic/别名、缺失不填零、四种状态 |
| `test_completion.py` | 34 | `StreamCompletion` × `StopKind` 分离、非 stop 不断流 |
| `test_pricing.py` | 28 | Decimal 精确性、前缀匹配、unknown 原因、float 拒绝 |
| `test_calls.py` | 22 | 标识、显式重试、成环、去重计账、按模型聚合 |
| `test_reconstruct.py` | 25 | 端到端往返、多连接隔离、配对缺口、重试分组 |
| `test_privacy.py` | 14 | 敏感头/参数脱敏、持久化视图无正文 |
| `test_limits.py` | 36 | 上限配置校验与超限诊断（含 zip bomb） |

夹具约定：gzip 使用 `mtime=0`，分片生成器（`byte_chunks` / `two_way_splits` /
`all_splits`）完全确定，因此同一份字节的任何分片方式都会得到同一结果。
