#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* ---------------- DUMMY STRUCT TO TRICK __INTELLISENSE__ ---------------- */
#ifdef __INTELLISENSE__
struct task_struct {
    struct task_struct *real_parent;
    __u32 tgid;
};
#endif
#ifdef __INTELLISENSE__
#define BPF_CORE_READ_TASK(task_ptr, field, subfield) ((__u32)0)
#endif


/* ---------------- EVENT STRUCT ---------------- */
#define MAX_PATH 256

struct event {
    u32 pid;
    u32 ppid;
    u64 ts;
    char comm[16];
    char syscall[16];

    // generic
    int fd;
    size_t count;

    // paths
    char path[MAX_PATH];
    char new_path[MAX_PATH];
};



/* ---------------- RING BUFFER ---------------- */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB buffer
} events SEC(".maps");

/* ---------------- HELPER ---------------- */
static __always_inline int submit_event(const char *name)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    // CO-RE safe read of parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid;
    BPF_CORE_READ_INTO(&ppid, task, real_parent, tgid);
    e->ppid = ppid;

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, name, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}



/* ---------------- SYSCALL HOOKS ---------------- */

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "openat", 7);

    // filename is arg[1]
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

    e->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "read", 5);

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

    e->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "write", 6);

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

    e->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "renameat", 9);

    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (void *)ctx->args[1]);   // old path
    bpf_probe_read_user_str(e->new_path, sizeof(e->new_path),
                            (void *)ctx->args[3]);   // new path

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "unlinkat", 9);

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

    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->syscall, "execve", 7);

    // filename = args[0]
    bpf_probe_read_user_str(
        e->path,
        sizeof(e->path),
        (void *)ctx->args[0]
    );

    bpf_ringbuf_submit(e, 0);
    return 0;
}



SEC("tracepoint/sched/sched_process_exit")
int tp_exit(void *ctx)
{
    return submit_event("exit");
}
