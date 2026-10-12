#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "path_rules.h"
#include "monitor_stats.h"

#define TASK_COMM_LEN 16

struct open_event {
    u32 pid;
    u32 uid;
    u8  alert_type;
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_COUNT);
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");

static __always_inline void count_stat(u32 key)
{
    u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct open_event *e;
    const char *filename = (const char *)ctx->args[1];
    char path[MAX_PATH_LEN] = {};
    unsigned char alert;

    if (bpf_probe_read_user_str(path, sizeof(path), filename) < 0) {
        count_stat(STAT_PATH_READ_FAILED);
        return 0;
    }

    alert = classify_path(path);
    if (alert == ALERT_NONE)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        count_stat(STAT_RINGBUF_RESERVE_FAILED);
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->alert_type = alert;
    __builtin_memcpy(e->path, path, sizeof(e->path));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

