# Pi 委派进度

实现代理使用 `pi-delegate` relay 驱动 Pi CLI。Pi 负责在隔离 worktree 中实现；主代理负责审查、
重跑门禁、独立复现、提交与合并。**不提交**由 Pi 完成，提交始终由主代理执行。

> **模型变更（重要）**：T00–T04 使用 `opencode-go/deepseek-v4.1-flash`。T05/T06 首轮启动后
> 该提供方开始返回 `403 An active OpenCode Go subscription is required to use Go models`，
> 两个任务都在写到一半时中断。改用直连 `deepseek/deepseek-v4-flash` 后以 `--session` 续跑完成。
> 该模型与本机 Pi 会话自身配置一致（`PI_PROVIDER=deepseek`、`PI_MODEL=deepseek-v4-flash`）。
> **这是未经用户确认的提供方替换，仅因原订阅失效才执行；如需回到 opencode-go 请先恢复订阅。**

| 任务 | 状态 | 分支 | 提交 | 审查备注 |
|---|---|---|---|---|
| T00 Python 工程骨架 | reviewed+merged | `main` | `76f70d9` | 12 tests passed；离线 editable install 通过。Pi 首轮违规联网安装 pytest，已披露并通过增量任务修正文档和门禁。 |
| T01 M0 doctor 与环境能力检测 | reviewed+merged | `pi/m0-doctor` | `64bc06b` | 56 tests（含既有 12）。测试未削弱、系统命令白名单、`setup-vm.sh` 仅 `--apply` 才安装/下载。**边界**：未自动创建/启动 VM，也未在 VM 内实测挂点与 LSM，M0 出口项未完成。 |
| T02 M1 HTTP/SSE 与 usage/费用解析 | reviewed+merged | `pi/m1-llm` | `c081224` | 274 模块 / 286 全仓 tests。主代理独立复现：逐字节喂入 JSON/SSE(chunked)/gzip 正确；`to_record()` 无凭据与正文；usage 缺失为 `None`；Decimal 计价且未核验价格表显式标注。**边界**：纯库、未接 CLI、未接触真实 TLS 字节。 |
| T03 M2 事件模型与可靠账本 | reviewed+merged | `pi/m2-ledger` | `04ffd76` | 216 模块 / 228 全仓 tests。主代理发现并退回修复 `ON CONFLICT(event_id) DO NOTHING` 静默覆盖缺陷：现幂等键为 `(event_id, 规范化校验值)`，冲突抛 `IndexConflictError` 并整批回滚。独立复现 10 项全过。 |
| T04 合并后一致性与文档校正 | reviewed+merged | `main` | `df1d91b` | README 状态段改写并列出未完成出口项，避免把库层进度误报为里程碑完成。 |
| T05 M3 关联引擎 | reviewed+merged | `pi/m3-correlate` | `0d2dbbc` | **106 模块 / 652 全仓 tests**（0 skipped/xfail），covers 串行、2/5 路并发、子进程与 PID 复用、调用级、容器 resolver、消融、序列化、边界。主代理独立复现 **25 项**（自造事件流与真实 HTTP 字节，不用其夹具）全过：任务级覆盖率 1.0；连接复用时调用级必须 AMBIGUOUS 且候选完整；独立连接时降为 PROBABLE；声明需交叉核验；determinism/round-trip/explain/消融。**关键语义（与我的 brief 有偏差，已确认更准确）**：并发歧义在**调用级**而非任务级——任务级仍靠进程身份保持确定；这不是缺陷。 |
| T06 M3 Docker 任务映射 | reviewed+merged | `pi/m3-container` | `302d170` | **288 模块 / 834 全仓 tests**（0 skipped/xfail）。主代理独立复现 **22 项**（自写 fake `ContainerQuery` 提供 `docker inspect` 形状 JSON）全过：四种 outcome、候选完整、`/data` vs `/database` 目录边界、最长前缀、双向 round-trip、缺 host_pid/cgroup 不伪造、未知 state → UNKNOWN。**副作用披露**：`/data` 与 `/database` 这类边界必须专门断言，否则极易写成字符串前缀匹配。 |

## 一致性检查（合并后，`main`）

- [x] 逐分支审查并提交（`0d2dbbc` / `302d170`）
- [x] 合并后完整 pytest：**940 passed**（546 基线 + 288 container + 106 correlate）
- [x] `compileall src/agent_probe` OK
- [x] 两个独立验证脚本在合并后的 `main` 上复跑通过
- [x] 分支未越界改文件（`git diff --name-only` 为空，仅新增各自目录）
- [x] 无 skip/xfail、无第三方依赖、无网络访问、correlate 未 `import agent_probe.container`
- [x] README 按“库层已落地 / 出口项未达成”如实描述

## 主代理在审查阶段补的说明（非行为变更）

- `docs/03b-container-mapping.md` §6.2 与 `container.query.ContainerQuery` 协议 docstring：
  明确“自定义 `ContainerQuery` 实现失败时必须抛 `ContainerQueryError`”。原实现的 mapper 只把
  `ContainerError` 子类转成 `outcome=ERROR`，其他异常会向上传播；这是刻意的 fail-loud 选择，
  但协议文档没说清，主代理补一句说明而不是改行为。

## 下一步队列

| 任务 | 文件边界 | 备注 |
|---|---|---|
| T07 M4 审计规则与报告 | `src/agent_probe/audit/`、`tests/audit/`、`docs/04-audit.md` | 规则、中断分类、`probe report`/`explain`、静态 HTML 时间线。 |
| T08 M1 CLI 接入 | `src/agent_probe/cli.py`、`tests/test_cli.py` | 把 M1 计账接到 CLI（`plan.md` M1/M4 出口要求）。 |

## 合并后的已知缺口（不在本轮范围）

- M0：VM 内挂点 attach、BPF LSM 阻断验证、真实 TLS 调用点定位、无探针性能基线。
- M1：真实流量捕获率/解析成功率/usage 一致率报告；CLI 计账输出。
- M2：≥30 类操作夹具与 strace/auditd 交叉验证、30 分钟额定负载与过载丢失检测、采集源本身。
- M3：≥200 条带独立预期关系的样本评估、真实 Docker 标签映射与短命容器竞态实测、
  辅助标记适配器接入两个真实 agent。当前只有合成事件流与 fake `ContainerQuery`。
- M4–M6（审计报告、受限执行控制、对照实验）尚未开始。
- 环境提示：`ms_pointcloud_midterm` 中**没有 PyYAML**，M4 的“YAML 规则”要么先引入经论证的依赖，
  要么实现受限 stdlib 子集；不得在测试里静默跳过。
