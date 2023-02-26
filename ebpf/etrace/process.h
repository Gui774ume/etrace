/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PROCESS_H_
#define _PROCESS_H_

#define CGROUP_MAX_LENGTH 72
#define TASK_COMM_LEN 16

struct cgroup_context {
    u32 subsystem_id;
    u32 state_id;
    char name[CGROUP_MAX_LENGTH];
};

struct credentials_context {
    kuid_t          uid;		/* real UID of the task */
    kgid_t          gid;		/* real GID of the task */
    kuid_t          suid;		/* saved UID of the task */
    kgid_t          sgid;		/* saved GID of the task */
    kuid_t          euid;		/* effective UID of the task */
    kgid_t          egid;		/* effective GID of the task */
    kuid_t          fsuid;		/* UID for VFS ops */
    kgid_t          fsgid;		/* GID for VFS ops */
    unsigned        securebits;	/* SUID-less security management */
    u32             padding;
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;	/* caps we're permitted */
    kernel_cap_t    cap_effective;	/* caps we can actually use */
    kernel_cap_t    cap_bset;	/* capability bounding set */
    kernel_cap_t    cap_ambient;	/* Ambient capability set */
};

struct namespace_context {
    u32 cgroup_namespace;
    u32 ipc_namespace;
    u32 net_namespace;
    u32 mnt_namespace;
    u32 pid_namespace;
    u32 time_namespace;
    u32 user_namespace;
    u32 uts_namespace;
};

struct process_context {
    struct namespace_context namespaces;
    struct credentials_context credentials;
    char comm[TASK_COMM_LEN];
    struct cgroup_context cgroups[CGROUP_SUBSYS_COUNT];
};

__attribute__((always_inline)) int fill_process_context(struct process_context *ctx) {
    // fetch current task
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

    // fetch process comm
    bpf_get_current_comm(ctx->comm, sizeof(ctx->comm));

    // fetch cgroup data
    char *container_id;
    #pragma unroll
    for (u32 i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
        ctx->cgroups[i].subsystem_id = i;
        BPF_CORE_READ_INTO(&ctx->cgroups[i].state_id, task, cgroups, subsys[i], id);
        BPF_CORE_READ_INTO(&container_id, task, cgroups, subsys[i], cgroup, kn, name);
        bpf_probe_read_str(ctx->cgroups[i].name, sizeof(ctx->cgroups[i].name), container_id);
    }

    // fetch process credentials
    BPF_CORE_READ_INTO(&ctx->credentials.uid, task, cred, uid);
    BPF_CORE_READ_INTO(&ctx->credentials.gid, task, cred, gid);
    BPF_CORE_READ_INTO(&ctx->credentials.suid, task, cred, suid);
    BPF_CORE_READ_INTO(&ctx->credentials.sgid, task, cred, sgid);
    BPF_CORE_READ_INTO(&ctx->credentials.euid, task, cred, euid);
    BPF_CORE_READ_INTO(&ctx->credentials.egid, task, cred, egid);
    BPF_CORE_READ_INTO(&ctx->credentials.fsuid, task, cred, fsuid);
    BPF_CORE_READ_INTO(&ctx->credentials.fsgid, task, cred, fsgid);
    BPF_CORE_READ_INTO(&ctx->credentials.securebits, task, cred, securebits);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_inheritable, task, cred, cap_inheritable);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_permitted, task, cred, cap_permitted);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_effective, task, cred, cap_effective);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_bset, task, cred, cap_bset);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_ambient, task, cred, cap_ambient);

    // fetch process namespaces
    BPF_CORE_READ_INTO(&ctx->namespaces.cgroup_namespace, task, nsproxy, cgroup_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.ipc_namespace, task, nsproxy, ipc_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.net_namespace, task, nsproxy, net_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.mnt_namespace, task, nsproxy, mnt_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.pid_namespace, task, nsproxy, pid_ns_for_children, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.time_namespace, task, nsproxy, time_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.user_namespace, task, cred, user_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.uts_namespace, task, nsproxy, uts_ns, ns.inum);
    return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 8192);
} traced_pids SEC(".maps");

struct sched_process_fork_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

/*
 * tracepoint__sched__sched_process_fork is used to track child processes and inherit tracing state
 */
SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct sched_process_fork_args *ctx)
{
    u32 key = bpf_get_current_pid_tgid();
    u32 child_pid = (u32) ctx->child_pid;

    // check if the parent process is traced
    u32 *is_traced = bpf_map_lookup_elem(&traced_pids, &key);
    if (!is_traced) {
        key = bpf_get_current_pid_tgid() >> 32;
        is_traced = bpf_map_lookup_elem(&traced_pids, &key);
        if (!is_traced) {
            // the parent isn't traced
            return 0;
        }
    }

    // inherit traced state
    bpf_map_update_elem(&traced_pids, &child_pid, &child_pid, BPF_ANY);
    return 0;
}

SEC("kprobe/do_exit")
int kprobe_do_exit(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    // delete traced pids entry
    bpf_map_delete_elem(&traced_pids, &tid);
    return 0;
}

#endif