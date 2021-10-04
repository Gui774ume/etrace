/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _ETRACE_H_
#define _ETRACE_H_

struct tracepoint_raw_syscalls_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct tracepoint_raw_syscalls_sys_enter *args) {
    // ignore syscalls from etrace
    u64 id = bpf_get_current_pid_tgid();
    if ((id >> 32) == load_etrace_tgid()) {
        return 0;
    }

    // create new syscall cache entry
    u32 nr = 0;
    bpf_probe_read(&nr, sizeof(nr), &args->id);

    // filter all events except the execve one
    if (nr != SYSCALL_EXECVE) {
        if (is_syscall_ignored(nr)) {
            return 0;
        }
    }

    struct syscall_cache *cache = reset_syscall_cache(id);
    if (cache == 0) {
        // this syscall is ignored
        return 0;
    }

    // save syscall nr and input registers
    bpf_probe_read(&cache->nr, sizeof(cache->nr), &args->id);
    bpf_probe_read(&cache->args[0], sizeof(cache->args), &args->args[0]);

    // save entry process context
    fill_process_context(&cache->entry_process_context);
    return 0;
}

SEC("kprobe/security_bprm_check")
int kprobe_security_bprm_check(struct pt_regs *ctx) {
    // ignore syscalls from etrace
    u64 id = bpf_get_current_pid_tgid();
    if ((id >> 32) == load_etrace_tgid()) {
        return 0;
    }

    // fetch syscall cache
    struct syscall_cache *cache = get_syscall_cache(id);
    if (cache == 0) {
        return 0;
    }

    // lookup syscall definition
    struct syscall_definition *def = lookup_definition(cache->nr);
    if (def == 0) {
        return 0;
    }

    struct syscall_buffer *buf = reset_syscall_buffer_cache(id);
    if (buf == 0) {
        // should never happen
        return 0;
    }

    // resolve arguments
    int ret = resolve_args(cache, def, buf);
    if (ret < 0) {
        // couldn't resolve arguments, exit now and do not send event
        delete_syscall_buffer_cache(id);
    }
    return 0;
}

struct tracepoint_raw_syscalls_sys_exit {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    long ret;
};

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct tracepoint_raw_syscalls_sys_exit *args) {
    // ignore syscalls from etrace
    u64 id = bpf_get_current_pid_tgid();
    if ((id >> 32) == load_etrace_tgid()) {
        return 0;
    }

    // fetch syscall cache
    struct syscall_cache *cache = get_syscall_cache(id);
    if (cache == 0) {
        return 0;
    }

    // prepare event
    struct syscall_buffer *buf = new_syscall_buffer();
    if (buf == 0) {
        // should never happen
        goto exit;
    }
    bpf_probe_read(&buf->evt.entry_process_context, sizeof(buf->evt.entry_process_context), &cache->entry_process_context);
    bpf_probe_read(&buf->evt.ret, sizeof(buf->evt.ret), &args->ret);
    fill_process_context(&buf->evt.exit_process_context);
    buf->evt.nr = cache->nr;
    buf->evt.ts = bpf_ktime_get_ns();
    buf->evt.tgid = id >> 32;
    buf->evt.pid = id;

    // filter execve events
    if (cache->nr == SYSCALL_EXECVE) {
        if (is_syscall_ignored(cache->nr)) {
            goto exit;
        }

        // copy argument from cache
        struct syscall_buffer *cached_buf = get_syscall_buffer_cache(id);
        if (cached_buf == 0) {
            // shouldn't happen
            goto exit;
        }
        bpf_probe_read(buf->args, MAX_DATA_PER_SYSCALL, cached_buf->args);
        buf->cursor = cached_buf->cursor;

    } else {

        // lookup syscall definition
        struct syscall_definition *def = lookup_definition(cache->nr);
        if (def == 0) {
            goto exit;
        }

        // resolve arguments
        int ret = resolve_args(cache, def, buf);
        if (ret < 0) {
            // couldn't resolve arguments, exit now and do not send event
            goto exit;
        }
    }

    // send event
    send_syscall_buffer(buf);

exit:
    delete_syscall_cache(id);
    delete_syscall_buffer_cache(id);
    return 0;
}

#endif
