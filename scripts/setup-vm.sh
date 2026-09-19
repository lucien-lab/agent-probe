#!/usr/bin/env bash
#
# agent-probe · M0 固定环境准备脚本
#
# 目标：把 "Ubuntu ARM64 + eBPF 工具链" 固定成可复现的版本集合，供
# `probe doctor` 校验。脚本本身只做三件事：打印影响、检查现状、按需安装。
#
# 用法：
#   scripts/setup-vm.sh                # 只打印将要做什么（不修改任何东西），退出码 2
#   scripts/setup-vm.sh --check-only   # 只读检查当前宿主/VM 是否满足清单，退出码 0/1
#   scripts/setup-vm.sh --apply        # 执行安装（幂等；需要显式指定）
#
# 退出码：0=成功或检查全部通过；1=检查失败；2=用法错误或未指定 --apply。
#
# 环境变量：
#   AGENT_PROBE_VM_DIR       VM 镜像存放目录（默认 "$HOME/.cache/agent-probe/vm"）
#   AGENT_PROBE_IMAGE_URL    覆盖 Ubuntu cloud image 下载地址
#
# 安全边界：脚本不会修改内核引导参数、不会禁用安全特性、不会访问 agent 仓库数据。
# 本仓库的自动化验证只运行 `bash -n` 与 `--check-only`，绝不自动执行 --apply。

set -euo pipefail

readonly SCRIPT_NAME="${0##*/}"

# ---------------------------------------------------------------------------
# 固定版本矩阵（升级时必须同时更新 docs/00-env.md 与这里的常量）
# ---------------------------------------------------------------------------
readonly UBUNTU_VERSION="24.04.4"
readonly UBUNTU_CODENAME="noble"
readonly UBUNTU_ARCH="arm64"
readonly UBUNTU_CLOUD_IMAGE="ubuntu-${UBUNTU_VERSION}-server-cloudimg-${UBUNTU_ARCH}.img"
readonly UBUNTU_IMAGE_URL="${AGENT_PROBE_IMAGE_URL:-https://cloud-images.ubuntu.com/releases/${UBUNTU_VERSION}/release/${UBUNTU_CLOUD_IMAGE}}"
readonly DEFAULT_VM_DIR="${AGENT_PROBE_VM_DIR:-${HOME}/.cache/agent-probe/vm}"

# 目标内核包（noble 上为 6.8 系列；具体 ABI 版本在 VM 内由 doctor 记录实测值）
readonly GUEST_KERNEL_IMAGE="linux-image-generic"
readonly GUEST_KERNEL_HEADERS="linux-headers-generic"
readonly GUEST_KERNEL_TOOLS="linux-tools-generic"

# 宿主侧（macOS/Linux 桌面）依赖：QEMU 与 cloud-init 辅助工具
readonly -a HOST_PACKAGES=(
  qemu-system-arm
  qemu-efi-aarch64
  cloud-image-utils
  openssh-client
  curl
)

# VM 内依赖：编译/观测工具链、内核头、eBPF 工具、容器运行时、Python
readonly -a GUEST_PACKAGES=(
  build-essential
  clang-18
  llvm-18
  libbpf-dev
  libelf-dev
  zlib1g-dev
  libssl-dev
  bpftool
  dwarves
  pkg-config
  "${GUEST_KERNEL_IMAGE}"
  "${GUEST_KERNEL_HEADERS}"
  "${GUEST_KERNEL_TOOLS}"
  docker.io
  python3
  python3-venv
  python3-dev
  git
  jq
  openssl
  ca-certificates
  trace-cmd
)

MODE="plan"

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
log() { printf '[setup-vm] %s\n' "$*"; }
warn() { printf '[setup-vm][warn] %s\n' "$*" >&2; }
die() {
  printf '[setup-vm][error] %s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<EOF
${SCRIPT_NAME} — 准备 agent-probe 的固定 Ubuntu ARM64 环境

用法：
  ${SCRIPT_NAME}               打印计划与影响，不修改任何东西（退出码 2）
  ${SCRIPT_NAME} --check-only  只读检查清单是否满足（退出码 0=通过, 1=有缺失）
  ${SCRIPT_NAME} --apply       执行安装/下载（幂等，需显式指定）
  ${SCRIPT_NAME} --help        显示本帮助

目标版本矩阵：
  Ubuntu ${UBUNTU_VERSION} LTS (${UBUNTU_CODENAME}) · ${UBUNTU_ARCH} · kernel=${GUEST_KERNEL_IMAGE}

VM 目录（--apply 时使用）：${DEFAULT_VM_DIR}
镜像地址：${UBUNTU_IMAGE_URL}
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apply)
        [[ "${MODE}" == "check-only" ]] && die "--apply 与 --check-only 不能同时使用"
        MODE="apply"
        ;;
      --check-only)
        [[ "${MODE}" == "apply" ]] && die "--apply 与 --check-only 不能同时使用"
        MODE="check-only"
        ;;
      --help | -h)
        usage
        exit 0
        ;;
      *)
        usage >&2
        die "未知参数：$1"
        ;;
    esac
    shift
  done
}

# ---------------------------------------------------------------------------
# 平台识别
# ---------------------------------------------------------------------------
host_kernel() { uname -s; }
host_machine() { uname -m; }

is_macos_host() { [[ "$(host_kernel)" == "Darwin" ]]; }
is_linux_host() { [[ "$(host_kernel)" == "Linux" ]]; }

have() { command -v "$1" >/dev/null 2>&1; }

host_package_installed() {
  # macOS 用 brew，Linux 用 dpkg；找不到包管理器时保守返回 "未知"
  local pkg="$1"
  if is_macos_host; then
    have brew || return 1
    brew list --versions "${pkg}" >/dev/null 2>&1
    return $?
  fi
  if have dpkg-query; then
    dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"
    return $?
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 影响说明
# ---------------------------------------------------------------------------
print_plan() {
  log "模式：${MODE}"
  log "宿主：$(host_kernel) $(host_machine)"
  log "目标：Ubuntu ${UBUNTU_VERSION} LTS (${UBUNTU_CODENAME}) ${UBUNTU_ARCH}，内核 ${GUEST_KERNEL_IMAGE}"
  cat <<EOF

将要执行的操作（--apply 时）：
  1. 下载 Ubuntu cloud image 到 ${DEFAULT_VM_DIR}/${UBUNTU_CLOUD_IMAGE}
     （约 600 MB，网络访问仅限 cloud-images.ubuntu.com）
  2. 在 VM 内安装以下包（幂等，已安装则跳过）：
$(printf '       - %s\n' "${GUEST_PACKAGES[@]}")

不在本脚本范围内的步骤（由 docs/00-env.md 的手动步骤完成）：
  - 生成 cloud-init seed、启动 QEMU 虚拟机、挂载共享目录。
  - 修改内核引导参数（lsm= 等）：必须显式记录并单独确认。

影响与边界：
  - 不在宿主上安装 eBPF 采集能力：macOS 宿主只能运行 QEMU，不能加载 eBPF 程序。
  - 不修改内核引导参数（lsm= / bpf LSM 需要在 VM 内单独确认，见 docs/00-env.md）。
  - 不写入被测 agent 的仓库、不读取 agent 凭据。
  - 只安装发行版仓库中的固定包名，不追加第三方源、不使用 curl | bash。
  - 仓库自动化只运行 --check-only，不会自动 --apply。
EOF
}

# ---------------------------------------------------------------------------
# 检查
# ---------------------------------------------------------------------------
CHECK_FAILURES=0

record() {
  # record <ok|missing|n/a> <描述>
  local state="$1"
  shift
  case "${state}" in
    ok) log "  [ok]      $*" ;;
    missing)
      warn "  [missing] $*"
      CHECK_FAILURES=$((CHECK_FAILURES + 1))
      ;;
    *) log "  [n/a]     $*" ;;
  esac
}

check_host_tools() {
  log "宿主依赖："
  if is_linux_host && [[ "$(host_machine)" == "aarch64" ]]; then
    log "  检测到 aarch64 Linux 宿主，可直接在宿主机执行 VM 内步骤（跳过 QEMU 检查）"
    return 0
  fi

  local missing_host_tools=()
  local host_tools=(qemu-system-aarch64 cloud-localds ssh curl)
  local tool
  for tool in "${host_tools[@]}"; do
    if have "${tool}"; then
      record ok "命令 ${tool}: $(command -v "${tool}")"
    else
      record missing "命令 ${tool} 不存在（宿主要求）"
      missing_host_tools+=("${tool}")
    fi
  done
  if ((${#missing_host_tools[@]} > 0)); then
    log "  建议（macOS/Homebrew）：brew install qemu cloud-image-utils"
    log "  建议（Debian/Ubuntu）：sudo apt-get install ${HOST_PACKAGES[*]}"
  fi
}

check_image() {
  log "VM 镜像："
  local image_path="${DEFAULT_VM_DIR}/${UBUNTU_CLOUD_IMAGE}"
  if [[ -f "${image_path}" ]]; then
    record ok "已存在 ${image_path}（$(du -h "${image_path}" | cut -f1)）"
  else
    record missing "缺少 ${image_path}（--apply 会从 ${UBUNTU_IMAGE_URL} 下载）"
  fi
}

check_guest_packages() {
  log "VM 内软件包："
  if ! (is_linux_host && have dpkg-query); then
    record "n/a" "当前不是 Linux/dpkg 环境，跳过包检查（请在 VM 内运行 ${SCRIPT_NAME} --check-only）"
    return 0
  fi
  local pkg
  for pkg in "${GUEST_PACKAGES[@]}"; do
    if host_package_installed "${pkg}"; then
      record ok "包 ${pkg}"
    else
      record missing "包 ${pkg} 未安装"
    fi
  done
}

check_kernel_bits() {
  log "内核观测前提（只读）："
  if ! is_linux_host; then
    record "n/a" "非 Linux 宿主，BTF/tracefs/LSM 检查请使用 VM 内的 probe doctor"
    return 0
  fi
  local path
  for path in /sys/kernel/btf/vmlinux /sys/kernel/tracing/trace /sys/kernel/security/lsm; do
    if [[ -r "${path}" ]]; then
      record ok "${path} 可读"
    else
      record missing "${path} 不可读"
    fi
  done
}

run_checks() {
  CHECK_FAILURES=0
  log "只读检查（不修改任何内容）："
  check_host_tools
  check_image
  check_guest_packages
  check_kernel_bits
  if ((CHECK_FAILURES > 0)); then
    warn "检查完成：${CHECK_FAILURES} 项缺失；运行 ${SCRIPT_NAME} --apply 修复，或查看 docs/00-env.md"
    return 1
  fi
  log "检查完成：全部满足"
  return 0
}

# ---------------------------------------------------------------------------
# 应用（幂等）
# ---------------------------------------------------------------------------
ensure_dir() {
  local dir="$1"
  if [[ -d "${dir}" ]]; then
    log "已存在目录 ${dir}，跳过"
  else
    log "创建目录 ${dir}"
    mkdir -p "${dir}"
  fi
}

fetch_image() {
  local image_path="${DEFAULT_VM_DIR}/${UBUNTU_CLOUD_IMAGE}"
  if [[ -f "${image_path}" ]]; then
    log "镜像已存在 ${image_path}，跳过下载"
    return 0
  fi
  log "下载 ${UBUNTU_IMAGE_URL} -> ${image_path}"
  curl --fail --location --continue-at - --output "${image_path}.part" "${UBUNTU_IMAGE_URL}"
  mv "${image_path}.part" "${image_path}"
}

install_host_packages() {
  if is_linux_host && [[ "$(host_machine)" == "aarch64" ]]; then
    log "aarch64 Linux 宿主：跳过宿主 QEMU 包安装（可直接在宿主运行采集）"
    return 0
  fi
  if is_macos_host && have brew; then
    log "Homebrew：安装 qemu cloud-image-utils（幂等，已安装则跳过）"
    brew list --versions qemu >/dev/null 2>&1 || brew install qemu
    brew list --versions cloud-image-utils >/dev/null 2>&1 || brew install cloud-image-utils
    return 0
  fi
  if have apt-get; then
    log "apt-get：安装宿主包 ${HOST_PACKAGES[*]}"
    sudo -- apt-get update
    sudo -- apt-get install -y --no-install-recommends "${HOST_PACKAGES[@]}"
    return 0
  fi
  warn "未识别的宿主包管理器：请手动安装 ${HOST_PACKAGES[*]}"
}

install_guest_packages() {
  if ! is_linux_host; then
    log "非 Linux 宿主：跳过 VM 内包安装（请在 VM 内再次运行 ${SCRIPT_NAME} --apply）"
    return 0
  fi
  have apt-get || die "Linux 但不是 apt 系统：请手动安装 ${GUEST_PACKAGES[*]}"

  local missing=()
  local pkg
  for pkg in "${GUEST_PACKAGES[@]}"; do
    if ! host_package_installed "${pkg}"; then
      missing+=("${pkg}")
    fi
  done
  if ((${#missing[@]} == 0)); then
    log "VM 内包清单已全部满足，跳过 apt"
    return 0
  fi
  log "apt-get：安装缺失包（${#missing[@]} 个）：${missing[*]}"
  sudo -- apt-get update
  sudo -- apt-get install -y --no-install-recommends "${missing[@]}"
}

apply_changes() {
  log "开始执行（幂等）："
  ensure_dir "${DEFAULT_VM_DIR}"
  install_host_packages
  fetch_image
  install_guest_packages
  log "完成。下一步：在 VM 内运行 scripts/setup-vm.sh --check-only，然后运行 probe doctor --json"
}

main() {
  parse_args "$@"
  case "${MODE}" in
    plan)
      print_plan
      warn "未指定 --apply：本次未做任何修改。确认影响后再运行 ${SCRIPT_NAME} --apply"
      exit 2
      ;;
    check-only)
      run_checks
      ;;
    apply)
      print_plan
      apply_changes
      run_checks
      ;;
    *)
      die "未知模式：${MODE}"
      ;;
  esac
}

main "$@"
