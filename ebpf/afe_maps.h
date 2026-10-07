#ifndef __AFE_MAPS_H
#define __AFE_MAPS_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_SESSIONS 10240
#define MAX_ENTROPY_BUF 256

/* Event Data Structure Emitted to User Space */
struct afe_event_t {
    u32 pid;
    u32 tgid;
    u32 ppid;
    u32 uid;
    u32 event_type; // 1 = EXECVE, 2 = VFS_WRITE, 3 = SETSID, 4 = PTRACE
    u64 timestamp_ns;
    char comm[16];
    char filename[64];
    u32 buffer_len;
    u8 buffer_sample[MAX_ENTROPY_BUF];
};

/* In-Kernel Lineage & Process Context Map */
struct lineage_info_t {
    u32 ppid;
    u32 ancestor_uid;
    float static_gamma_offset;
    u8 is_web_spawned;
};

/* BPF Ring Buffer for Zero-Copy Event Streaming */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} afe_events SEC(".maps");

/* Process Lineage Ancestry Cache (Survives setsid() and reparenting) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, u32); // PID
    __type(value, struct lineage_info_t);
} lineage_map SEC(".maps");

/* Per-CPU Scratch Buffer for Verifier Compliance */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct afe_event_t);
} scratch_map SEC(".maps");

#endif /* __AFE_MAPS_H */
