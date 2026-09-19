# M4：离线审计规则与报告

M4 从 M2 的权威事件账本**只读重放**审计结果。报告是策略、原始事件、可选
calls artifact 与账本摘要的可复算快照；它不是采集器，也不会修改账本或建立派生索引。

## 快速使用

策略是受限 YAML，当前 schema 版本为 1。例如，禁止实际修改源码并限制目标地址：

```yaml
schema_version: 1
rules:
  - id: protect-src
    kind: forbidden_write
    paths:
      - /work/src
  - id: approved-network
    kind: destination_allowlist
    allowed_destinations:
      - 10.0.0.0/8
      - api.example.test
```

从 M2 JSONL 信封账本生成报告：

```console
probe report --policy policy.yaml --ledger events.jsonl --format text
probe report --policy policy.yaml --ledger events.jsonl --format json --output audit.json
probe report --policy policy.yaml --ledger events.jsonl --format html --output audit.html
probe explain EVENT_ID --policy policy.yaml --ledger events.jsonl
```

`--ledger` 必须是 M2 `JsonlEventLedger` 生成的带版本、长度和 checksum 信封的
JSONL，不能直接写一行裸事件 JSON。账本无效、策略不合法、calls artifact 不合法、
事件 ID 不存在或输出无法写入时，`report`/`explain` 会向 stderr 报告输入错误并返回
退出码 2。

HTML 是自包含的静态时间线：每条 finding 里的证据事件链接到保持账本顺序的原始事件。
账本字段均会 HTML 转义，适合离线归档；它不加载远端脚本、样式或数据。

## 规则与结论语义

支持的规则 `kind`：

| kind | 必填字段 | 违规条件 |
| --- | --- | --- |
| `forbidden_write` | `paths` | 成功且实际发生的写入/截断/改名/删除命中路径 |
| `sensitive_read` | `paths` | 成功且实际读取字节数大于零的读取命中路径 |
| `destination_allowlist` | `allowed_destinations` | 成功连接或发送到未允许的主机/IP/CIDR |
| `cost_limit` | `max_cost`, `currency` | 完整成本数据的同币种合计超出上限 |

路径按目录边界匹配：`/work/src` 匹配 `/work/src/a.py`，不匹配
`/work/src-old/a.py`。`destination_allowlist` 支持 IP、CIDR 与精确主机名。

每条 finding 的结论只有三种：

- `violation`：有成功且实际发生的反例事件，或完整成本数据确定超过上限。
- `pass`：在提供的完整、适用证据范围内未观测到反例。
- `insufficient_evidence`：事件结果未知、所需字段/成本不完整，或成本 artifact 未提供。

未知绝不被折算为 `pass`。特别地，未提供 `--calls` 时，成本规则只能给出证据不足，
不会暗示成本为零。

## calls artifact（成本规则）

成本规则需要可选的版本化 JSON artifact：

```console
probe report --policy policy.yaml --ledger events.jsonl --calls calls.json --format json
```

顶层为 `schema_version: 1`、单一 `run_id` 和 `calls` 数组。每个 call 至少有
`physical_request_id`、`run_id`；只有 `cost_complete: true` 且同时具有 `currency`
与 `total_cost` 才是完整成本证据。金额按十进制字符串保存和聚合，避免浮点误差。

## 可解释性与复核边界

`probe explain EVENT_ID` 输出原始事件、所有关联 finding、各 finding 的原始证据事件
及缺失证据 ID。报告 JSON 同时包含策略、输入事件、calls、findings、账本摘要和数据
质量字段，复核方可使用同一版本策略重新运行。

M4 只能审计账本中已采集到的事实：采集丢失、内核 hook 覆盖不足、TLS 明文不可见等
问题不能由报告层消除，应以 `insufficient_evidence` 和上游质量事件处理，而不应宣称
策略已经被证明合规。
