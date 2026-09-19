# M5：受限执行控制

本阶段的 Python 模块仅表达策略和在安装前检查能力；它**不加载 BPF**、不写入
pinned link、也不修改任何文件。只有独立的 BPF LSM 加载器在 agent 启动前通过
`validate_installation()` 后，才可以把 `enforce` 判定交给内核执行。

M0/M5 的最小实际 attach 验证见 [05-bpf-lsm-attach-probe.md](05-bpf-lsm-attach-probe.md)。
该探针始终返回允许并立即 detach，只能证明挂载能力，**不证明**任何策略已安装或操作被阻断。

## 模式

- `audit`：始终放行，同时对命中操作给出 `would_deny=true` 和结构化原因。
- `enforce`：策略语义要求拒绝；若 BPF LSM 不可用或任一必需 hook 缺失，安装必须
  失败，绝不能静默退回 audit。

## 当前支持矩阵

| 操作 | 目标 LSM hook | 命中受保护目录时 |
|---|---|---|
| 写入现有文件 (`write`) | `file_permission` | 拒绝 |
| 创建 (`create`) | `inode_create` | 拒绝 |
| 截断 (`truncate`) | `inode_setattr` | 拒绝 |
| 删除 (`unlink`) | `inode_unlink` | 拒绝 |
| 重命名 (`rename`) | `inode_rename` | 源或目标任一命中即拒绝 |
| 硬链接 (`link`) | `inode_link` | 源或目标任一命中即拒绝 |

路径比较在 Python 层是词法的，拒绝 `..` 以避免把未经解析的路径当成安全结论。
生产 BPF 程序必须按内核 dentry、挂载与命名空间进行同等检查；本模块不解决容器
挂载视图或 TOCTOU。

## 明确盲区与边界

- `mmap` 写、`io_uring`、已继承 fd、符号链接解析及跨挂载路径尚未通过真实内核
  回归验证，不能宣称被完整覆盖。
- 网络与费用策略保持审计告警，不属于执行阻断。
- 内核拒绝与日志投递必须解耦：日志不可用应告警，不能解除已安装保护；采集器退出
  也不能静默卸载 pinned link。
- 拒绝反馈应由 agent 适配器将内核 errno 和本模块的 `RefusalReason` 返回给 agent，
  以便其作出合规重试；不能仅凭告警文本判断阻断生效。
