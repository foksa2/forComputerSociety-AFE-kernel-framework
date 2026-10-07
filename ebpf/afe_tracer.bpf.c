#include "afe_maps.h"

char LICENSE[] SEC("license") = "GPL";

/* Static Lineage Classification Helper */
static __always_inline float evaluate_lineage_gamma(const char *comm) {
    // Check web-server context
    if (comm[0] == 'w' && comm[1] == 'w' && comm[2] == 'w') return 0.40f; // www-data
    if (comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i') return 0.40f; // nginx
    if (comm[0] == 'a' && comm[1] == 'p' && comm[2] == 'a') return 0.40f; // apache
    if (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h') return -0.25f; // admin ssh
    return 0.00f; // Standard user context
}

/* Hook 1: Trace Process Executions (sys_enter_execve) */
SEC("tp/sys_calls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 zero = 0;
    struct afe_event_t *event = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!event) return 0;

    u64 id = bpf_get_current_pid_tgid();
    event->pid = id >> 32;
    event->tgid = id;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = 1; // EXECVE

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->uid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read canonicalized binary path from sys_enter_execve args
    const char **args = (const char **)ctx->args[0];
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), args);

    // Maintenance of Lineage Map
    struct lineage_info_t lin = {};
    lin.ppid = event->ppid;
    lin.static_gamma_offset = evaluate_lineage_gamma(event->comm);
    bpf_map_update_elem(&lineage_map, &event->pid, &lin, BPF_ANY);

    // Reserve and submit to Ring Buffer
    struct afe_event_t *ring_evt = bpf_ringbuf_reserve(&afe_events, sizeof(*ring_evt), 0);
    if (ring_evt) {
        __builtin_memcpy(ring_evt, event, sizeof(*event));
        bpf_ringbuf_submit(ring_evt, 0);
    }
    return 0;
}

/* Hook 2: Pre-TLS VFS Layer Data Interception (vfs_write) */
SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_entry, struct file *file, const char *buf, size_t count) {
    if (count == 0 || buf == NULL) return 0;

    u32 zero = 0;
    struct afe_event_t *event = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!event) return 0;

    u64 id = bpf_get_current_pid_tgid();
    event->pid = id >> 32;
    event->event_type = 2; // VFS_WRITE
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read sample buffer for Pre-TLS Shannon Entropy calculation
    u32 sample_size = count < MAX_ENTROPY_BUF ? count : MAX_ENTROPY_BUF;
    event->buffer_len = sample_size;
    bpf_probe_read_user(&event->buffer_sample, sample_size, buf);

    struct afe_event_t *ring_evt = bpf_ringbuf_reserve(&afe_events, sizeof(*ring_evt), 0);
    if (ring_evt) {
        __builtin_memcpy(ring_evt, event, sizeof(*event));
        bpf_ringbuf_submit(ring_evt, 0);
    }
    return 0;
}

/* Hook 3: Anti-Evasion Process Reparenting Protection (setsid) */
SEC("tp/sys_calls/sys_enter_setsid")
int handle_setsid(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // Retrieve existing lineage; preserve gamma offset despite session decoupling
    struct lineage_info_t *lin = bpf_map_lookup_elem(&lineage_map, &pid);
    if (lin) {
        lin->is_web_spawned = 1; // Freeze web ancestry flag
    }
    return 0;
}
