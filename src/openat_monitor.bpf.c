#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN  256

#define ALERT_PASSWD   1
#define ALERT_SHADOW   2
#define ALERT_SSHKEY   3
#define ALERT_SUDOERS  4

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

static __always_inline int check_path(const char *path, struct open_event *e)
{
    char buf[MAX_PATH_LEN];
    bpf_probe_read_user_str(buf, sizeof(buf), path);

    /* /etc/passwd */
    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' &&
        buf[4]=='/' && buf[5]=='p' && buf[6]=='a' && buf[7]=='s' &&
        buf[8]=='s' && buf[9]=='w' && buf[10]=='d' && buf[11]=='\0') {
        e->alert_type = ALERT_PASSWD;
        bpf_probe_read_user_str(e->path, sizeof(e->path), path);
        return 1;
    }
    /* /etc/shadow */
    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' &&
        buf[4]=='/' && buf[5]=='s' && buf[6]=='h' && buf[7]=='a' &&
        buf[8]=='d' && buf[9]=='o' && buf[10]=='w' && buf[11]=='\0') {
        e->alert_type = ALERT_SHADOW;
        bpf_probe_read_user_str(e->path, sizeof(e->path), path);
        return 1;
    }
    /* /etc/sudoers */
    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' &&
        buf[4]=='/' && buf[5]=='s' && buf[6]=='u' && buf[7]=='d' &&
        buf[8]=='o' && buf[9]=='e' && buf[10]=='r' && buf[11]=='s') {
        e->alert_type = ALERT_SUDOERS;
        bpf_probe_read_user_str(e->path, sizeof(e->path), path);
        return 1;
    }
    /* /.ssh/ anywhere in path */
    {
        int i;
        #pragma unroll
        for (i = 0; i < MAX_PATH_LEN - 6; i++) {
            if (buf[i]   == '/' && buf[i+1] == '.' &&
                buf[i+2] == 's' && buf[i+3] == 's' &&
                buf[i+4] == 'h' && buf[i+5] == '/') {
                e->alert_type = ALERT_SSHKEY;
                bpf_probe_read_user_str(e->path, sizeof(e->path), path);
                return 1;
            }
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct open_event *e;
    const char *filename = (const char *)ctx->args[1];

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (!check_path(filename, e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
