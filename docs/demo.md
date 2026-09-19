# M6 演示流程（待真实采集器与控制加载验证）

本流程是交付演示的核对表，不会把本仓库的离线库伪装成已运行的 eBPF 采集或内核阻断。
当前版本可展示账本重放、审计报告和 Python 级策略判定；只有真实采集器、BPF LSM 加载、
系统调用返回及文件快照齐备后，才可演示或声称系统级文件保护。

## 演示前准备

1. 在干净 Linux ARM64 VM 建立 `docs/00-env.md` 指定的环境，保存 `probe doctor --json` 到
   `evidence/m6/environment/doctor.json`，并记录 VM 镜像摘要、内核、包清单与仓库 revision。
2. 复制 `docs/benchmark-manifest.example.json` 到 `evidence/m6/manifest.json`。将
   `execution_status` 改为实际状态；填写固定输入摘要、策略、模型、真值和所有产物路径。
   未运行的记录保持 `outcome_recorded: false`，不得删去。
3. 为每个 agent 固定 10 个任务、每任务 3 次。运行前保存输入和允许副作用；运行后保存
   probe 账本、应用日志、测试服务记录、文件快照、费用导出/估算依据以及失败原因。

## 现场步骤

1. 选一个已完成的正常任务，展示三组对照（`application_logs`、`external_only`、
   `external_with_markers`）如何映射到同一语义事件及其独立真值。
2. 展示一次越界尝试。系统级阻断演示必须显示真实系统调用返回和保护文件内容不变；若当前
   只运行 Python 策略，则只展示其建议性决定，并明确它没有加载内核 BPF。
3. 展示 agent 收到结构化拒绝原因后改用允许路径的合规重试；保留初次失败和重试两者的证据。
4. 对生成的账本运行 `probe report` 和 `probe explain`，展示规则结论、三态证据和原始事件
   路径。报告内容与真值不一致时报告差异，不修改或过滤原始记录。
5. 单独展示异常集（子进程、容器、并发、临时替换、重试、断流、过载、越界），以及五档
   性能配置的本地与远端负载结果；缺失值仍显示为缺失。

## 发布前复核

```bash
# 检查离线评估口径和模板约束；不会运行真实 agent 或访问网络。
conda run -n ms_pointcloud_midterm python -m pytest -q tests/evaluation

# 完整回归；真实运行数据需由外部编排器生成，再按 evaluation.md 构造 ExperimentRun 校验。
conda run -n ms_pointcloud_midterm python -m pytest -q
```

确认 manifest 至少有 20 个不同的真实任务、2 个真实 agent、每 agent 10 个任务且每组合 3 次；
异常集、三组对照、消融、五档性能、许可证和全部失败证据均可定位。任何未满足项都保留在
发布说明中，不以离线测试通过替代 M6 验收。
