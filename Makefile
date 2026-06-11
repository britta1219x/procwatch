CC = gcc
CLANG = clang
BPFTOOL = bpftool

CFLAGS = -g -O2
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86
INCLUDES = -I./include -I/usr/include
LIBS = -lbpf -lelf -lz

KERNEL_INC = /usr/src/kernels/$(shell ls /usr/src/kernels/ | tail -1)/tools/lib

ALL_TARGETS = procwatch_execve procwatch_openat

.PHONY: all clean

all: $(ALL_TARGETS)

include/%.skel.h: src/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

src/%.bpf.o: src/%.bpf.c
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -I$(KERNEL_INC) -c $< -o $@

procwatch_execve: src/execve_monitor.c include/execve_monitor.skel.h
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES) $(LIBS)

procwatch_openat: src/openat_monitor.c include/openat_monitor.skel.h
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES) $(LIBS)

clean:
	rm -f src/*.bpf.o include/*.skel.h $(ALL_TARGETS)
