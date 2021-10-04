/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _EVENT_H_
#define _EVENT_H_

#define MAX_DATA_PER_SYSCALL 4608
#define MAX_DATA_PER_ARG 1024

struct syscall_event {
    u32 nr;
    u32 tgid;
    u32 pid;
    u32 padding;
    u64 ret;
    u64 ts;
    struct process_context entry_process_context;
    struct process_context exit_process_context;
};

struct syscall_buffer {
    struct syscall_event evt;
    char args[MAX_DATA_PER_SYSCALL];
    u16 cursor;
};

struct syscall_buffer syscall_buffer_zero = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct syscall_buffer);
	__uint(max_entries, 512);
} syscall_buffer_cache SEC(".maps");

__attribute__((always_inline)) struct syscall_buffer *reset_syscall_buffer_cache(u64 id) {
    int ret = bpf_map_update_elem(&syscall_buffer_cache, &id, &syscall_cache_zero, BPF_ANY);
    if (ret < 0) {
        // should never happen
        return 0;
    }
    return bpf_map_lookup_elem(&syscall_buffer_cache, &id);
}

__attribute__((always_inline)) struct syscall_buffer *get_syscall_buffer_cache(u64 id) {
    return bpf_map_lookup_elem(&syscall_buffer_cache, &id);
}

__attribute__((always_inline)) int delete_syscall_buffer_cache(u64 id) {
    return bpf_map_delete_elem(&syscall_buffer_cache, &id);
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct syscall_buffer);
	__uint(max_entries, 1);
} syscall_buffer_gen SEC(".maps");

__attribute__((always_inline)) struct syscall_buffer *new_syscall_buffer() {
    u32 key = 0;
    int ret = bpf_map_update_elem(&syscall_buffer_gen, &key, &syscall_buffer_zero, BPF_ANY);
    if (ret < 0) {
        // should never happen
        return 0;
    }
    return bpf_map_lookup_elem(&syscall_buffer_gen, &key);
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16384 * 1024 /* 16 MB */);
} events SEC(".maps");

struct events_stats_counter {
    u64 lost;
    u64 sent;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct events_stats_counter);
	__uint(max_entries, 600);
} events_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} events_sync SEC(".maps");

__attribute__((always_inline)) int send_syscall_buffer(struct syscall_buffer *buf) {
    u32 sync_key = 0;
    u32 *sync_value = bpf_map_lookup_elem(&events_sync, &sync_key);
    if (sync_value == 0 || (sync_value != 0 && *sync_value == 1)) {
        return 0;
    }
    int ret = 0;
    if (*sync_value == 0) {
        ret = bpf_ringbuf_output(&events, buf, sizeof(buf->evt) + (buf->cursor & (MAX_DATA_PER_SYSCALL - MAX_DATA_PER_ARG - 1)), BPF_RB_FORCE_WAKEUP);
    }

    // record statistics
    struct events_stats_counter *stats = bpf_map_lookup_elem(&events_stats, &buf->evt.nr);
    if (stats != 0) {
        if (ret < 0) {
            __sync_fetch_and_add(&stats->lost, 1);
        } else {
            __sync_fetch_and_add(&stats->sent, 1);
        }
    }
    return ret;
}

#endif