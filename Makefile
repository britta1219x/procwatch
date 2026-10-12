CC = gcc
CLANG = clang
BPFTOOL = bpftool
BPF_ARCH ?= x86

CFLAGS = -g -O2
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH)
INCLUDES = -I./include -I/usr/include
LIBS = -lbpf -lelf -lz

ALL_TARGETS = procwatch_execve procwatch_openat

.PHONY: all check-env clean test

all: check-env $(ALL_TARGETS)

check-env:
	@command -v $(CC) >/dev/null || (echo "error: $(CC) is required"; exit 1)
	@command -v $(CLANG) >/dev/null || (echo "error: $(CLANG) is required"; exit 1)
	@command -v $(BPFTOOL) >/dev/null || (echo "error: $(BPFTOOL) is required"; exit 1)
	@test -r /sys/kernel/btf/vmlinux || (echo "error: kernel BTF is unavailable at /sys/kernel/btf/vmlinux"; exit 1)

include/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

include/%.skel.h: src/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

src/%.bpf.o: src/%.bpf.c include/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

src/openat_monitor.bpf.o: src/path_rules.h src/monitor_stats.h
src/execve_monitor.bpf.o: src/monitor_stats.h

procwatch_execve: src/execve_monitor.c src/monitor_stats.h include/execve_monitor.skel.h
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES) $(LIBS)

procwatch_openat: src/openat_monitor.c src/path_rules.h src/monitor_stats.h include/openat_monitor.skel.h
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES) $(LIBS)

test: tests/path_rules_test.c src/path_rules.h
	$(CC) -std=c11 -Wall -Wextra -Werror -o tests/path_rules_test tests/path_rules_test.c
	./tests/path_rules_test

clean:
	rm -f src/*.bpf.o include/*.skel.h include/vmlinux.h tests/path_rules_test $(ALL_TARGETS)

