/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _SYSCALL_CACHE_H_
#define _SYSCALL_CACHE_H_

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 600);
} syscall_filters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[TASK_COMM_LEN]);
	__type(value, u32);
	__uint(max_entries, 512);
} comm_filters SEC(".maps");

__attribute__((always_inline)) int is_syscall_ignored(u32 nr) {
    // check if syscalls are filtered
    if (load_syscall_filter() == 1) {
        u32 *filter = bpf_map_lookup_elem(&syscall_filters, &nr);
        if (filter == 0 || (filter != 0 && *filter != 1)) {
            // filter out syscall
            return 1;
        }
    }

    // check if comms are filtered
    if (load_comm_filter() == 1) {
        char comm[TASK_COMM_LEN] = {};
        bpf_get_current_comm(&comm[0], TASK_COMM_LEN);
        u32 *filter = bpf_map_lookup_elem(&comm_filters, comm);
        if (filter == 0 || (filter != 0 && *filter != 1)) {
            // filter out syscall
            return 1;
        }
    }
    return 0;
}

struct syscall_cache {
    struct process_context entry_process_context;
    u64 args[6];
    u32 nr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, struct syscall_cache);
	__uint(max_entries, 4096);
} syscall_cache SEC(".maps");

struct syscall_cache syscall_cache_zero = {};

__attribute__((always_inline)) struct syscall_cache *reset_syscall_cache(u64 id, u32 nr) {
    if (is_syscall_ignored(nr)) {
        return 0;
    }

    int ret = bpf_map_update_elem(&syscall_cache, &id, &syscall_cache_zero, BPF_ANY);
    if (ret < 0) {
        // should never happen
        return 0;
    }
    return bpf_map_lookup_elem(&syscall_cache, &id);
}

__attribute__((always_inline)) struct syscall_cache *get_syscall_cache(u64 id) {
    return bpf_map_lookup_elem(&syscall_cache, &id);
}

__attribute__((always_inline)) int delete_syscall_cache(u64 id) {
    return bpf_map_delete_elem(&syscall_cache, &id);
}

#endif
