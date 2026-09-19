#!/usr/bin/env bash
# Build the M0/M5 BPF LSM attach probe in the current Linux VM.
# This script never loads a BPF program; executing the resulting loader is a
# separate, explicitly documented administrator action.
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly PROBE_DIR="${REPO_ROOT}/bpf/lsm_attach_probe"

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'error: build this probe inside the target Linux VM, not on the host.\n' >&2
  exit 2
fi

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  printf 'error: /sys/kernel/btf/vmlinux is unavailable; cannot generate CO-RE types.\n' >&2
  exit 1
fi

exec make -C "${PROBE_DIR}" all
