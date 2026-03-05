#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_PATH 256

struct event {
    u32 pid;
    u32 ppid;
    u64 ts;
    char comm[16];
    char syscall[16];

    int fd;
    size_t count;

    char path[MAX_PATH];
    char new_path[MAX_PATH];
    char arg1[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");


/* ---------------- HELPER ---------------- */

static __always_inline int submit_event(const char *name)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));   // 🔥 CRITICAL FIX

    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(e->syscall, name, sizeof(e->syscall) - 1);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


/* ---------------- SYSCALL HOOKS ---------------- */

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));   // 🔥 CRITICAL FIX

    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "openat", 6);

    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (void *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_read")
int tp_read(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "read", 4);

    e->fd = (int)ctx->args[0];
    e->count = (size_t)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_write")
int tp_write(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "write", 5);

    e->fd = (int)ctx->args[0];
    e->count = (size_t)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_renameat")
int tp_rename(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "renameat", 8);

    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (void *)ctx->args[1]);
    bpf_probe_read_user_str(e->new_path, sizeof(e->new_path),
                            (void *)ctx->args[3]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "unlinkat", 8);

    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (void *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 🔥 Normalize name
    __builtin_memcpy(e->syscall, "execve", 6);

    // filename (args[0])
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (void *)ctx->args[0]);

    // argv pointer
    const char **argv = (const char **)ctx->args[1];

    if (argv) {
        const char *arg1_ptr = NULL;

        if (bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr),
                                &argv[1]) == 0 && arg1_ptr) {

            bpf_probe_read_user_str(e->arg1, sizeof(e->arg1),
                                    arg1_ptr);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_execveat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 🔥 Normalize name (important)
    __builtin_memcpy(e->syscall, "execve", 6);

    // pathname is args[1]
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (void *)ctx->args[1]);

    // argv pointer is args[2]
    const char **argv = (const char **)ctx->args[2];

    if (argv) {
        const char *arg1_ptr = NULL;

        if (bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr),
                                &argv[1]) == 0 && arg1_ptr) {

            bpf_probe_read_user_str(e->arg1, sizeof(e->arg1),
                                    arg1_ptr);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tp_exit(void *ctx)
{
    return submit_event("exit");
}