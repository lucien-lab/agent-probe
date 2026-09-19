# Build only inside the target Linux VM.  Nothing in this Makefile loads BPF.
# 发行版默认 clang 名称不同；调用方可用 CLANG=clang-18 固定 M0 基线。
CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
ARCH ?= arm64
CFLAGS ?= -O2 -g -Wall -Wextra -Werror

.PHONY: all clean

all: lsm_attach_probe.bpf.o lsm_attach_probe

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

lsm_attach_probe.bpf.o: lsm_attach_probe.bpf.c vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -g -Wall -Werror -Wno-missing-declarations -I. -c $< -o $@

lsm_attach_probe: lsm_attach_probe.c
	$(CC) $(CFLAGS) $< $$(pkg-config --cflags --libs libbpf) -o $@

clean:
	rm -f lsm_attach_probe.bpf.o lsm_attach_probe vmlinux.h
