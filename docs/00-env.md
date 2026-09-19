# 00 · M0 环境与能力基线

本文档定义 agent-probe 的 **M0（环境与能力验证）** 环境基线：
固定目标、`probe doctor` 的检查契约与退出码、权限影响、QEMU/VM 边界、复现步骤、
已知限制和验收证据清单。

> **重要边界**：本文档记录的是**目标与验证方法**，不是已验证结果。
> 当前开发机是 macOS 宿主，**尚未在 Linux 中验证任何 eBPF 挂点、BTF 内容或 LSM 阻断**。
> 表格中"实测值"一列在 M0 期间才由 VM 内 `probe doctor --json` 的输出回填。
> 存在 BTF、`pass` 结果都**只代表线索满足**，不代表挂点可用。

---

## 1. 目标平台与范围

- 采集目标：**Linux / ARM64**，固定 Ubuntu LTS 版本，QEMU 启动，VM 内编译。
- 宿主：macOS（开发机）或 aarch64 Linux。宿主只负责虚拟化与文件传输，不提供任何采集能力。
- 不在范围内：macOS/Windows 原生 eBPF 采集、交叉编译、自定义内核编译（除非 M0 验证需要）。

### 1.1 固定环境选择

| 项 | 固定值（声明） | 说明 |
|---|---|---|
| 发行版 | Ubuntu **24.04.4 LTS**（`noble`） | 见 `scripts/setup-vm.sh` 中的 `UBUNTU_VERSION` |
| 架构 | **arm64**（aarch64） | 与目标一致，不做 x86 交叉验证 |
| 镜像 | `ubuntu-24.04.4-server-cloudimg-arm64.img` | 需在 VM 创建后记录 `sha256sum` |
| 内核 | `linux-image-generic`（6.8 系列） | 具体 ABI 版本以 doctor 输出为准 |
| 虚拟化 | QEMU aarch64 + EDK2 ARM64 固件 | 宿主提供，VM 内不感知 |
| 包清单 | 见 `scripts/setup-vm.sh` 中 `HOST_PACKAGES` / `GUEST_PACKAGES` | 只使用发行版仓库包名 |

选择理由：noble 仓库同时提供 `clang-18`、`libbpf-dev`、`bpftool`、`dwarves`（pahole）、
`docker.io` 与较新的内核，能满足 CO-RE 编译与 tracepoint/fentry/BPF LSM 验证；
ARM64 与目标一致且云镜像可直接启动，无需自编译内核。

### 1.2 版本矩阵

| 组件 | 目标（包名 / 下限） | 实测值 | 记录方式（证据） |
|---|---|---|---|
| 内核 | `linux-image-generic` | 待回填 | E-02 |
| BTF | `/sys/kernel/btf/vmlinux` 存在且可读 | 待回填 | E-03 |
| clang / LLVM | `clang-18`、`llvm-18` | 待回填 | E-07 |
| libbpf | `libbpf-dev`（`pkg-config --modversion libbpf`） | 待回填 | E-07 |
| bpftool | `bpftool` | 待回填 | E-07 |
| pahole | `dwarves` | 待回填 | E-07 |
| Python | `python3` ≥ 3.11（noble 默认 3.12） | 待回填 | E-08 |
| OpenSSL | `openssl`（系统库 3.0.x） | 待回填 | E-08 |
| Docker | `docker.io` | 待回填 | E-09 |
| QEMU（宿主） | `qemu-system-aarch64` | 待回填 | E-01 |
| cloud image | 见 1.1 | 待回填（含 sha256） | E-01 |

回填要求：把 `probe doctor --json` 的原始输出存入 M0 证据目录，并在此表填写
"实测值 + 证据编号"，不要手抄成大概值。

---

## 2. `probe doctor` 契约

`probe doctor` 是**只读**能力检查：不创建/修改文件、不修改引导参数、不安装软件，
外部命令仅限白名单（`clang`、`bpftool`、`pkg-config`、`docker` 的版本查询）。

```bash
probe doctor            # 人类可读文本
probe doctor --json     # 稳定 JSON（schema_version = 1）
```

### 2.1 检查项

| id | 必需 | Linux 专用 | 判定依据 |
|---|:---:|:---:|---|
| `platform.os` | ✔ | | 运行平台是否为 Linux |
| `platform.arch` | | | 是否为 ARM64（x86_64 记为 `warn`） |
| `kernel.btf` | ✔ | ✔ | `/sys/kernel/btf/vmlinux` 可读且非空 |
| `kernel.tracefs` | ✔ | ✔ | `/sys/kernel/tracing` 或 `/sys/kernel/debug/tracing` 已挂载 |
| `kernel.tracepoint.sched_process_exec` | ✔ | ✔ | 事件目录下 `id` 或 `format` 可读 |
| `kernel.fentry_fexit` | ✔ | ✔ | vmlinux BTF + `available_filter_functions` + 内核配置线索 |
| `security.bpf_lsm` | ✔ | ✔ | 活动 LSM 列表含 `bpf`，并与 `CONFIG_BPF_LSM` 交叉验证 |
| `security.capabilities` | | ✔ | `CapEff` 是否含 `CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN` |
| `tools.clang` | ✔ | ✔ | `which clang` + `clang --version` |
| `tools.bpftool` | ✔ | ✔ | `which bpftool` + `bpftool version` |
| `tools.pkg_config` | ✔ | ✔ | `which pkg-config` + `--version` |
| `tools.libbpf` | | ✔ | `pkg-config --modversion libbpf` |
| `python.runtime` | ✔ | | Python ≥ 3.11 |
| `python.openssl` | ✔ | | 能取得 OpenSSL 版本（记录用） |
| `docker.engine` | ✔ | ✔ | docker CLI 是否存在 + daemon 是否可达 |

"Linux 专用" 的检查在非 Linux 主机上一律返回 `unsupported`（不抛异常）。

### 2.2 状态语义

| 状态 | 含义 |
|---|---|
| `pass` | 检查所需线索满足（**不代表**已完成实际 attach / 阻断验证） |
| `warn` | 线索不完整或工具存在但不可用；不阻塞，但必须记录 |
| `fail` | 硬性前提缺失（缺文件、命令缺失、LSM 未启用等） |
| `unsupported` | 当前主机不适用（例如 macOS 上的全部内核检查） |

**"BTF 存在" 只说明内核带类型信息**。`kernel.fentry_fexit`、`security.bpf_lsm` 等
独立检查，不会因为 `kernel.btf=pass` 而自动通过；反之亦然。

### 2.3 退出码

| 退出码 | 条件 | 处置 |
|---:|---|---|
| `0` | 所有**必需**检查为 `pass` 或 `warn` | 可以进入下一步；`warn` 必须记录 |
| `1` | 至少一个必需检查为 `fail` | 环境不满足；按报告提示修复后重跑 |
| `2` | 至少一个必需检查为 `unsupported`（且无必需 `fail`） | 当前主机不是受支持目标（macOS 宿主即为此类） |
| `3` | doctor 自身出错，未生成报告（`stderr` 有说明） | 视为工具缺陷，不应作为环境结论 |

`fail` 优先于 `unsupported`。可选检查（`required=false`）的 `fail`/`warn` 不改变退出码，
只在 `overall.status` 中降级提示，避免把 "非阻塞缺口" 误当成环境不可用。

> 注意：`argparse` 的用法错误也使用退出码 `2`，但会向 `stderr` 打印 `usage:` 且不产出报告；
> doctor 的 `2` 一定伴随合法 JSON / 完整文本报告，可用输出格式区分。

### 2.4 JSON schema（schema_version = 1）

```jsonc
{
  "schema_version": 1,
  "tool": { "name": "agent-probe", "command": "probe doctor", "version": "0.0.1.dev0" },
  "generated_at": "2026-01-01T00:00:00Z",       // 唯一非确定性字段
  "host": { "system": "Linux", "machine": "aarch64", "kernel_release": "...", "node": "..." },
  "overall": {
    "status": "pass|warn|fail|unsupported",
    "exit_code": 0,
    "counts": { "pass": 0, "warn": 0, "fail": 0, "unsupported": 0 },
    "note": "只读检查：pass 表示所需线索/文件/工具满足，不代表已完成实际验证"
  },
  "checks": [
    {
      "id": "kernel.btf",
      "title": "vmlinux BTF",
      "required": true,
      "status": "pass",
      "summary": "……",
      "evidence": { "path": "/sys/kernel/btf/vmlinux", "size_bytes": 1234 }
    }
  ]
}
```

约束（由测试保证）：`checks[].id` 与注册表顺序一致且唯一；
`evidence` 键按字典序输出；`counts` 四个键恒在且合计等于 `len(checks)`；
除 `generated_at` 外，同一能力矩阵的输出逐字节稳定。

---

## 3. 权限与系统影响

### 3.1 doctor 自身

| 项目 | 影响 |
|---|---|
| 文件系统 | 只读：`/sys/kernel/**`、`/proc/**`、`/boot/config-*`、`/var/run/docker.sock`（仅 `stat`） |
| 外部命令 | 白名单版本查询：`clang --version`、`bpftool version`、`pkg-config ...`、`docker version` |
| 需要特权 | **不需要**。无权限时降级为 `warn`/`fail` 并保留证据 |
| 网络 | 不访问网络（`docker version` 只走本地 socket） |

### 3.2 采集（M1+）所需权限 —— 与 doctor 的检查项对应

| 能力 | 需要 | 说明 |
|---|---|---|
| 加载 BPF 程序 | `CAP_BPF` + `CAP_PERFMON`，或 `CAP_SYS_ADMIN`/root | `security.capabilities` 只检查当前进程，不改变权限 |
| kprobe/uprobe/tracepoint | 同上（`unprivileged_bpf_disabled` 通常为 2） | 采集器应使用受限的受保护身份，不用 root 跑 agent |
| fentry/fexit | 同上 + 内核 `CONFIG_BPF_EVENTS`、`CONFIG_FUNCTION_TRACER` | 仅凭线索通过不算验证，需实际 attach |
| BPF LSM 阻断 | 内核 `CONFIG_BPF_LSM=y` **且** 引导参数 `lsm=` 中包含 `bpf` | 需要改引导参数并重启；**普通 fentry 不能替代 LSM 阻断** |
| tracefs / securityfs | 挂载即可，读操作无需特权 | 部分镜像默认未挂载 |
| Docker 映射（M3） | 可访问 `/var/run/docker.sock`（`docker` 组或 root） | doctor 只判断可达性 |
| 内核配置可读性 | `/boot/config-<release>` 或 `/proc/config.gz` | 两者都不可读时相关检查降级为 `warn` |

**不修改环境**：doctor 不会调整 sysctl、不会挂载 tracefs、不会修改 `docker` 组或引导参数。
以上任何变更都由人工在 VM 内执行并记录（见第 5 节步骤与第 7 节证据清单）。

---

## 4. QEMU / VM 边界

| 边界 | 说明与影响 |
|---|---|
| 无原生采集 | macOS 宿主只能运行 QEMU；macOS 上 `probe doctor` 输出 `unsupported` 是**预期正确结果**，不是缺陷 |
| 嵌套虚拟化 | ARM64 VM 内不再嵌套虚拟化；KVM 相关能力（如某些硬件 PMU 特性）不作为 M0 前提 |
| 内核不可定制 | 使用发行版内核；BPF LSM 若未在 `lsm=` 中启用，需改 guest 引导参数（`/etc/default/grub` → `grub-update` → 重启），该改动必须在文档中显式记录 |
| 性能不可外推 | QEMU 下的 CPU/内存/耗时不能代表裸机（M6 指标口径要求分别报告本地负载与真实负载） |
| 时钟与持久化 | cloud image 默认无数据盘，VM 重建后环境丢失；镜像 + 包清单 + 证据文件是唯一复现依据 |
| 网络 | VM 内需要安装包与（后续）访问本地 TLS 测试服务；M0 阶段只需包安装，不接入真实 LLM 凭据 |
| 目录共享 | 建议用 `rsync`/`scp` 或 `virtiofs`/`9p` 挂载被测仓库；挂载方式会影响文件事件路径视图（M2 需记录） |
| Docker in VM | 用发行版 `docker.io`，版本与宿主 Docker Desktop 无关联；镜像摘要必须逐次记录 |

---

## 5. 复现步骤

### 5.1 宿主（macOS 或 aarch64 Linux）

```bash
# 1) 只读检查宿主依赖与镜像（不会修改任何东西）
bash scripts/setup-vm.sh --check-only

# 2) 确认影响后执行安装/下载（本仓库自动化**不会**自动运行这一步）
bash scripts/setup-vm.sh --apply

# 3) 记录宿主侧证据
qemu-system-aarch64 --version | tee evidence/E-01-qemu.txt
shasum -a 256 "$HOME/.cache/agent-probe/vm/ubuntu-24.04.4-server-cloudimg-arm64.img" | tee evidence/E-01-image-sha256.txt
```

> `--apply` 只负责：下载固定 cloud image、安装宿主 QEMU/cloud-image-utils、
> （在 Linux 宿主上）安装 VM 内包清单。
> **cloud-init seed 生成、QEMU 启动、共享目录挂载**属于手动步骤，沿用
> `docs/` 中 M0 记录的命令，并把实际命令行粘贴进证据目录。

### 5.2 VM 内

```bash
# 4) 包清单复核（幂等；缺包时才需要 --apply）
bash scripts/setup-vm.sh --check-only

# 5) 检查内核挂点与工具链
probe doctor            # 人类可读
probe doctor --json | tee evidence/E-02-doctor.json
echo "exit=$?"          # 必须为 0；非 0 时逐项修复后重跑

# 6) 记录内核配置与 BTF 细节（补充 doctor 的证据）
grep -E 'CONFIG_(BPF|DEBUG_INFO_BTF|FUNCTION_TRACER|LSM)' /boot/config-"$(uname -r)" \
  | tee evidence/E-04-kernel-config.txt
cat /sys/kernel/security/lsm | tee evidence/E-05-active-lsm.txt
```

（M0 后续步骤——真实 TLS 调用点定位、本地 TLS 测试服务、无探针性能基线——
按 `plan.md` 另行执行，不在本文档范围内。）

---

## 6. 已知限制

1. **未验证**：本文档与 `probe doctor` 在 macOS 上只能给出 `unsupported`；Linux 侧结论必须来自 VM 实测。
2. **线索 ≠ 能力**：BTF 可读只说明类型信息存在。`kernel.fentry_fexit` 是线索检查，
   必须再由实际 `attach` 验证；该步骤属于 M0 后续工作。
3. **BPF LSM 门槛高**：需要 `CONFIG_BPF_LSM=y` 且 `lsm=` 引导参数包含 `bpf`；
   仅编译进内核不等于启用，doctor 会区分这两种情况。
4. **内核配置可能陈旧**：`/boot/config-<release>` 与运行内核不一致时会 `warn`，不会静默通过。
5. **tracefs 位置不唯一**：`/sys/kernel/tracing` 与 `/sys/kernel/debug/tracing` 都接受，报告会写出实际命中路径。
6. **capability 检查是进程级的**：只反映运行 doctor 的身份，不能代表采集器服务身份。
7. **不检查 TLS 挂点**：`SSL_read`/`SSL_write`/`_ex` 的实际调用点需要在 M0 单独用真实 agent 请求定位，
   doctor 的 `python.openssl` 只是版本记录。
8. **Docker 检查不涉及容器**：只验证 daemon 可达；任务级映射与镜像摘要属于 M3/M0 后续证据。
9. **可选检查不阻塞**：`security.capabilities`、`tools.libbpf`、`platform.arch` 的
   `warn`/`fail` 不影响退出码，但必须在证据清单中说明。
10. **生产环境不适用**：当前检查面向单机 VM，不覆盖 CI 容器、多内核版本矩阵或发行版差异。

---

## 7. M0 验收证据清单

以下为 M0 阶段**必须产出**的证据；每项都以"原始命令 + 原始输出"形式存档
（建议 `evidence/` 目录，文件名与编号对应）。

| 编号 | 证据 | 生成命令（示例） | 通过标准 |
|---|---|---|---|
| E-01 | 环境来源 | `qemu-system-aarch64 --version`；镜像 `sha256sum` | 版本与镜像是固定的，摘要已记录 |
| E-02 | doctor 原始输出 | `probe doctor --json > evidence/E-02-doctor.json` | 退出码 0；无 `fail`；`warn` 逐项有解释 |
| E-03 | BTF 可用性 | `ls -l /sys/kernel/btf/vmlinux`（含 size） | 文件存在、非空，摘要进入证据 |
| E-04 | 内核配置 | `grep -E 'CONFIG_(BPF\|DEBUG_INFO_BTF\|FUNCTION_TRACER\|LSM)' /boot/config-$(uname -r)` | 关键项值已记录（允许为 `n`，但必须如实记录） |
| E-05 | tracepoint | `probe doctor --json` 中 `kernel.tracepoint.sched_process_exec` 的 `evidence.id` | 有稳定 id |
| E-06 | fentry/fexit 实测 | 实际 attach 最小程序并读取返回值（M0 后续实现） | 至少一次成功 attach 的原始输出；不可用则记录替代方案 |
| E-07 | 工具链版本 | `clang --version`、`bpftool version`、`pkg-config --modversion libbpf`、`pahole --version` | 全部可执行且版本进入矩阵表 |
| E-08 | Python / OpenSSL | `probe doctor --json` 的 `python.*` 两个检查 | `pass`，版本回填 1.2 表 |
| E-09 | Docker | `docker version`、`docker info --format '{{.ServerVersion}}'` | daemon 可达；镜像摘要另记 |
| E-10 | 权限矩阵 | `id`、`grep CapEff /proc/self/status`、`cat /sys/kernel/security/lsm` | 记录采集所需的实际身份与 capability |
| E-11 | BPF LSM 启用方式 | `cat /proc/cmdline`、`/sys/kernel/security/lsm` | 明确回答"BPF LSM 是否在活动列表中"；若否，记录所需引导参数变更与重启结果 |
| E-12 | 复现复核 | 从全新 VM 重跑 5.1/5.2 全部命令 | 结果与 E-01~E-11 一致；差异点已说明 |

验收要求（对应 `plan.md` M0 出口）：从空白 VM 可重复搭建；有脱敏的请求/响应、
挂点与版本清单。**不可用挂点必须在本周内调整环境或给出经过验证的替代方案**，
不能把未验证的挂点写成可用；**普通 fentry 也不能替代 LSM 阻断**。

---

## 8. 变更记录

| 日期 | 变更 | 备注 |
|---|---|---|
| M0 起始 | 初版：固定 Ubuntu 24.04.4 ARM64 目标、doctor 契约、退出码与证据清单 | 所有"实测值"待 VM 内回填 |
