#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "execve_monitor.skel.h"
#include "monitor_stats.h"

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

struct event {
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char ts[16];
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%-8s %-7d %-7d %-5d %-16s %s\n",
           ts, e->pid, e->ppid, e->uid, e->comm, e->filename);
    return 0;
}

static void print_stats(int map_fd)
{
    const char *labels[STAT_COUNT] = {
        "path read failures", "ring buffer reserve failures"
    };

    for (unsigned int key = 0; key < STAT_COUNT; key++) {
        __u64 value = 0;
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0)
            fprintf(stderr, "%s: %llu\n", labels[key],
                    (unsigned long long)value);
        else
            perror("Failed to read monitor stats");
    }
}

int main(void)
{
    struct execve_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = execve_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = execve_monitor_bpf__attach(skel);
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

    printf("%-8s %-7s %-7s %-5s %-16s %s\n",
           "TIME", "PID", "PPID", "UID", "COMM", "FILENAME");
    printf("%-8s %-7s %-7s %-5s %-16s %s\n",
           "--------", "-------", "-------", "-----", "----------------", "--------------------");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    print_stats(bpf_map__fd(skel->maps.stats));

cleanup:
    ring_buffer__free(rb);
    execve_monitor_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}

