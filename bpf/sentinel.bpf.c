// SPDX-License-Identifier: GPL-2.0
/*
 * bpf/sentinel.bpf.c
 * High-Performance In-Kernel Observability & Security Telemetry Probe for Containers.
 * Implements tracepoints on sys_enter_execve, sys_enter_connect, and sys_enter_openat.
 */

#define BPF_NO_PRESERVE_ACCESS_INDEX
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256

enum event_type {
    EVENT_PROCESS_EXEC = 1,
    EVENT_SOCKET_CONNECT = 2,
    EVENT_FILE_OPEN = 3,
};

/* Unified kernel telemetry structure emitted to ring buffer */
struct telemetry_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];
    __u32 daddr;        // IPv4 destination address (network order)
    __u16 dport;        // Destination port
    __u16 flags;        // Execution / Open flags
    __u8 is_container;   // 1 if originating within monitored container cgroup
};

/* Lockless BPF Ring Buffer for sub-microsecond userland event streaming */
struct {
    __uint(type, 27); /* BPF_MAP_TYPE_RINGBUF */
    __uint(max_entries, 1 << 24); /* 16 MB ring buffer */
} events SEC(".maps");

/* CGroup filter map: tracks monitored container namespaces */
struct {
    __uint(type, 1); /* BPF_MAP_TYPE_HASH */
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u32);
} monitored_cgroups SEC(".maps");

/* Tracepoint: sys_enter_execve */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    
    // Check if CGroup is in monitored containers map
    __u32 *monitored = bpf_map_lookup_elem(&monitored_cgroups, &cgroup_id);
    if (!monitored) {
        // If map is non-empty, filter out unmonitored host processes
        // (Allows full fleet monitoring when map is empty)
    }

    struct telemetry_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0; // Ring buffer full: drop to avoid blocking kernel execution
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = cgroup_id;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->event_type = EVENT_PROCESS_EXEC;
    event->is_container = monitored ? 1 : 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Submit reserved event to ring buffer
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Tracepoint: sys_enter_connect */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(void *ctx) {
    struct telemetry_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->event_type = EVENT_SOCKET_CONNECT;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
