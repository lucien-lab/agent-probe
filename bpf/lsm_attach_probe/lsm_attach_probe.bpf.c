// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal BPF LSM attach probe for M0/M5 capability verification.
 *
 * This is deliberately not an enforcement program: every invocation returns
 * zero.  It has no maps and no pinned state, and is safe only as a short-lived
 * attach/detach capability check run by an administrator in the target VM.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/file_permission")
int BPF_PROG(agent_probe_lsm_attach_probe, struct file *file, int mask)
{
	/* Do not inspect arguments or alter the security decision. */
	return 0;
}
