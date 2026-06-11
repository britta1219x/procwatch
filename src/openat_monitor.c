#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "openat_monitor.skel.h"

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN  256

#define ALERT_PASSWD   1
#define ALERT_SHADOW   2
#define ALERT_SSHKEY   3
#define ALERT_SUDOERS  4

struct open_event {
    unsigned int pid;
    unsigned int uid;
    unsigned char alert_type;
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];
};

static volatile int exiting = 0;

static void sig_handler(int sig) { exiting = 1; }

static const char *alert_str(unsigned char t)
{
    switch (t) {
    case ALERT_PASSWD:  return "\033[33m[PASSWD ]\033[0m";
    case ALERT_SHADOW:  return "\033[31m[SHADOW ]\033[0m";
    case ALERT_SSHKEY:  return "\033[35m[SSHKEY ]\033[0m";
    case ALERT_SUDOERS: return "\033[31m[SUDOERS]\033[0m";
    default:            return "[UNKNOWN]";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct open_event *e = data;
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char ts[16];
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%s %-8s %-7d %-5d %-16s %s\n",
           alert_str(e->alert_type), ts,
           e->pid, e->uid, e->comm, e->path);
    return 0;
}

int main(void)
{
    struct openat_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = openat_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = openat_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Watching sensitive file access... (Ctrl+C to stop)\n\n");
    printf("%-9s %-8s %-7s %-5s %-16s %s\n",
           "ALERT", "TIME", "PID", "UID", "COMM", "PATH");
    printf("%-9s %-8s %-7s %-5s %-16s %s\n",
           "---------", "--------", "-------", "-----",
           "----------------", "--------------------");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -4) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    openat_monitor_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
