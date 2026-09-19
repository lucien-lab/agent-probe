# M0/M5 · BPF LSM 挂载验证探针

`bpf/lsm_attach_probe/` 是一个**一次性、非持久**的能力验证工具，用来证明目标 Linux
VM 能加载并实际附着一个 BPF LSM 程序。它不是 M5 的文件保护实现，不能作为阻断效果、
策略覆盖或安全隔离的证据。

## 安全语义

- 探针只附着 `lsm/file_permission`，程序不读取参数、没有 map、始终返回 `0`；因此不会
  拒绝、修改或记录文件操作。
- loader 不创建 pinned link。成功附着后立即调用 `bpf_link__destroy()`，然后关闭 BPF
  object；SIGINT/SIGTERM 也会走同一清理路径。
- 进程被 `SIGKILL` 或主机崩溃时，未 pinned 的 link 仍随打开的 BPF fd 关闭而解除；本工具
  不应被改造成持续保护机制。M5 正式控制器须另外定义 pinned link 生命周期与故障语义。
- 加载 BPF 需要 root 或相应 BPF capability，可能被 lockdown、LSM 配置或容器 capability
  拒绝。仅在专用 Lima/Ubuntu VM 运行，**不要**在宿主机、生产机或 agent 工作负载运行期间
  运行。

## 前提

先在 VM 中运行 `probe doctor`。其中 `security.bpf_lsm` 必须通过，且 `/sys/kernel/security/lsm`
应包含 `bpf`。如果它缺失，需要按 `docs/00-env.md` 的手工引导参数流程启用并重启；本探针和
构建脚本都不会修改 GRUB、内核参数或权限。

Ubuntu 24.04/Lima VM 所需包在 `scripts/setup-vm.sh` 的 `GUEST_PACKAGES` 中：`clang-18`、
`libbpf-dev`、`libelf-dev`、`bpftool`、`pkg-config`、对应内核 headers。

## 构建与一次性验证

以下命令都在 Lima 的 Ubuntu guest 内运行；第一条仅编译，不加载 BPF：

```bash
cd /path/to/agent-probe
bash scripts/build-lsm-attach-probe.sh
```

第二条会短暂加载并附着探针，然后立即 detach。它需要特权，执行前应确认没有 agent
工作负载在运行：

```bash
cd /path/to/agent-probe/bpf/lsm_attach_probe
sudo ./lsm_attach_probe ./lsm_attach_probe.bpf.o
```

预期成功输出为：

```text
BPF LSM attach probe succeeded; detaching immediately (no policy enforced).
BPF LSM attach probe cleanup completed; no BPF link remains pinned.
```

验证后可用只读检查确认没有 pin：

```bash
sudo bpftool link show
```

该命令不应显示由本探针保留的 link。请把 loader 标准输出、`probe doctor --json` 和
`bpftool link show` 的输出保存为 M0 证据；失败时保留 stderr、内核版本与 LSM 列表，不能以
`security.bpf_lsm=pass` 替代实际 attach 成功。

## 失败解释

- `Operation not permitted`：通常是 capability、lockdown 或 `unprivileged_bpf_disabled`/容器
  限制；以 root 在 VM 中重试，并记录实际 capability。
- `Invalid argument` 或 attach 失败：常见于 `bpf` 未在活动 LSM 列表、内核未配置
  `CONFIG_BPF_LSM`，或 libbpf/内核接口不兼容。
- 缺少 `/sys/kernel/btf/vmlinux`：当前内核不能生成此 CO-RE 验证所需类型，应先修复 VM
  内核/包配置。

以上仅定位能力缺口，不授权降低主机安全配置或把 `fentry` 当成 LSM 阻断的替代品。
