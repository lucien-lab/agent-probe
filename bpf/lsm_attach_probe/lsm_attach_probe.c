// SPDX-License-Identifier: GPL-2.0-only
/* A short-lived, non-persistent loader for lsm_attach_probe.bpf.o. */
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t stop_requested;

static void request_stop(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static void usage(const char *program)
{
	fprintf(stderr, "Usage: %s <lsm_attach_probe.bpf.o>\\n", program);
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_object *object = NULL;
	struct bpf_program *program;
	int err = 1;

	if (argc != 2) {
		usage(argv[0]);
		return 2;
	}

	/* Signal handling ensures an interactive interruption still reaches cleanup. */
	signal(SIGINT, request_stop);
	signal(SIGTERM, request_stop);

	object = bpf_object__open_file(argv[1], NULL);
	if (libbpf_get_error(object)) {
		fprintf(stderr, "open BPF object failed: %s\\n", strerror(errno));
		object = NULL;
		goto cleanup;
	}

	err = bpf_object__load(object);
	if (err) {
		fprintf(stderr, "load BPF LSM program failed: %s (%d)\\n", strerror(-err), err);
		goto cleanup;
	}

	program = bpf_object__next_program(object, NULL);
	if (program == NULL || bpf_object__next_program(object, program) != NULL) {
		fprintf(stderr, "expected exactly one LSM program in object\\n");
		goto cleanup;
	}

	link = bpf_program__attach_lsm(program);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "attach BPF LSM hook failed: %s\\n", strerror(errno));
		link = NULL;
		goto cleanup;
	}

	if (!stop_requested) {
		puts("BPF LSM attach probe succeeded; detaching immediately (no policy enforced).");
	}
	err = 0;

cleanup:
	/* No pinning: explicit destruction detaches the LSM link before exit. */
	if (link != NULL)
		bpf_link__destroy(link);
	if (object != NULL)
		bpf_object__close(object);
	if (err == 0)
		puts("BPF LSM attach probe cleanup completed; no BPF link remains pinned.");
	return err == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
