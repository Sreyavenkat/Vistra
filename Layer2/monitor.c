#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "eBPFAgent.skel.h"

#define MAX_PATH 256

static volatile sig_atomic_t exiting = 0;

/*------------ IGNORE COMM ------------------*/
const char *ignore_procs[] = {
    // Layer-2 monitor itself
    "monitor",

    // IDEs / dev tools
    "code",
    "cpptools",
    "vscode",

    // System daemons
    "systemd-udevd",
    "(udev-worker)",
    "upowerd",
    "gdbus",
    "pulseaudio",
    "pipewire",
    "NetworkManager",
    "udisksd",
    "dbus-daemon",

    // Desktop / graphics
    "gnome-shell",
    "KMS thread",
    "VizCompositorTh",

    // Short-lived utilities
    "lsblk",
    "df",
    "top",
    "htop",
    "journalctl",

    NULL
};
int should_ignore(const char *comm)
{
    for (int i = 0; ignore_procs[i] != NULL; i++) {
        if (strncmp(comm, ignore_procs[i], 16) == 0)
            return 1; // ignore
    }
    return 0;
}

/* -------- MUST MATCH eBPF STRUCT -------- */
struct event {
    unsigned int pid;
    unsigned int ppid;
    unsigned long long ts;
    char comm[16];
    char syscall[16];

    int fd;
    size_t count;

    char path[MAX_PATH];
    char new_path[MAX_PATH];
};

/* -------- SIGNAL -------- */
void sig_handler(int sig)
{
    exiting = 1;
}

/* -------- RINGBUF CALLBACK -------- */
int handle_event(void *ctx, void *data, size_t size)
{
    struct event *e = data;

    // Ignore events from our own monitor process
    if (should_ignore(e->comm))
        return 0;


    FILE *f = fopen("syscall_queue.log", "a");
    if (!f)
        return 0;

    time_t now = time(NULL);
    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "%s | PID=%u | PPID=%u | COMM=%s | SYSCALL=%s",
            tbuf, e->pid, e->ppid, e->comm, e->syscall);

    if (!strcmp(e->syscall, "read") || !strcmp(e->syscall, "write")) {
        fprintf(f, " | FD=%d | COUNT=%zu",
                e->fd, e->count);
    }

    if (e->path[0]) {
        fprintf(f, " | PATH=%s", e->path);
    }

    if (!strcmp(e->syscall, "renameat")) {
        fprintf(f, " | NEW_PATH=%s", e->new_path);
    }

    fprintf(f, "\n");
    fclose(f);
    return 0;
}

/* -------- MAIN -------- */
int main()
{
    struct ring_buffer *rb = NULL;
    struct eBPFAgent_bpf *skel = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = eBPFAgent_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = eBPFAgent_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("[+] Layer-2 syscall monitor running...\n");

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

cleanup:
    ring_buffer__free(rb);
    eBPFAgent_bpf__destroy(skel);
    return 0;
}
