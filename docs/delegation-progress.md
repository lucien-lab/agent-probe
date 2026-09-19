# Pi 委派进度

实现代理统一使用 `opencode-go/deepseek-v4.1-flash`。Pi 负责在隔离 worktree 中实现；主代理负责审查、重跑门禁、独立复现、提交与合并。

| 任务 | 状态 | 分支 | 提交 | 审查备注 |
|---|---|---|---|---|
| T00 Python 工程骨架 | reviewed+committed+merged | `main` | `76f70d9` | 12 tests passed；离线 editable install 通过。Pi 首轮违规联网安装 pytest，已披露并通过增量任务修正文档和门禁。 |
| T01 M0 doctor 与环境能力检测 | reviewed+committed+merged | `pi/m0-doctor` | `64bc06b` | 56 tests（含既有 12）。审查确认：测试未削弱、系统命令白名单、`setup-vm.sh` 仅 `--apply` 才安装/下载。**边界**：未自动创建/启动 VM，也未在 VM 内实测挂点与 LSM，因此只算 M0 的“能力检测与环境准备”子任务，M0 出口项未完成。 |
| T02 M1 HTTP/SSE 与 usage/费用解析 | reviewed+committed+merged | `pi/m1-llm` | `c081224` | 274 模块 / 286 全仓 tests 通过；无 skip/xfail；零第三方依赖、零网络。主代理独立复现：逐字节喂入 JSON/SSE(chunked)/gzip 均产出正确记录；`to_record()` 不含 `Authorization`/target 凭据/正文；usage 缺失为 `None`（非 0）；Decimal 计价且 `price_table_verified=False`。**边界**：纯库、未接入 CLI、未接触真实 TLS 字节，M1 出口指标未验证。 |
| T03 M2 事件模型与可靠账本 | reviewed+committed+merged | `pi/m2-ledger` | `04ffd76` | 216 模块 / 228 全仓 tests 通过；无 skip/xfail；仅标准库。主代理发现并退回修复 `ON CONFLICT(event_id) DO NOTHING` 的静默覆盖缺陷：现幂等键为 `(event_id, 规范化校验值)`，同 ID 不同内容抛 `IndexConflictError` 并整批回滚。独立复现（`/tmp/verify_m2_conflict.py`，不依赖 Pi 测试代码）通过 10 项检查，含批内冲突全有或全无、只读安全、账本未被索引改写。**边界**：无 eBPF 采集源，M2 出口的真值/负载验收未做；账本读路径对重复 `event_id` 采 keep-first + 显式 issue，与索引侧冲突语义互补（见 `docs/02-event-ledger.md` §4.2/§10.4）。 |
| T04 合并后一致性与文档校正 | reviewed+committed | `main` | 见下一次提交 | README 状态段改为“M0 能力检测 + M1/M2 库层已落地（未接入 CLI）”，并列出仍未完成的出口项，避免把库层进度误报为里程碑完成。 |

## 最终一致性检查

- [x] 所有分支逐项审查并提交（`64bc06b` / `c081224` / `04ffd76`）
- [x] 合并后运行完整 pytest（`main` = 546 passed）
- [x] 运行 `compileall src/agent_probe`（OK）与 `python -m agent_probe --version`（`probe 0.0.1.dev0`）
- [x] 检查 CLI、文档和公开 API 一致性（M1/M2 未注册 CLI 子命令，README 已按其库层定位描述）
- [x] 检查计划中尚未实现的功能未被误报为完成（README「仍未完成」小节逐条列出 M0/M1/M2 出口缺口）

## 合并后的已知缺口（不在本轮范围）

- M0：VM 内挂点 attach、BPF LSM 阻断验证、真实 TLS 调用点定位、无探针性能基线。
- M1：真实流量捕获率/解析成功率/usage 一致率报告；CLI 计账输出。
- M2：≥30 类操作夹具与 strace/auditd 交叉验证、30 分钟额定负载与过载丢失检测、采集源本身。
- 计划中的 M3–M6（关联、审计报告、受限执行控制、对照实验）尚未开始。
