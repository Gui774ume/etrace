/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _SYSCALL_ARGS_H_
#define _SYSCALL_ARGS_H_

#define DYNAMIC_SIZE_RESOLUTION_TYPE_UNKNOWN       0
#define DYNAMIC_SIZE_RESOLUTION_TYPE_ARG0          1 << 0
#define DYNAMIC_SIZE_RESOLUTION_TYPE_ARG1          1 << 1
#define DYNAMIC_SIZE_RESOLUTION_TYPE_ARG2          1 << 2
#define DYNAMIC_SIZE_RESOLUTION_TYPE_ARG3          1 << 3
#define DYNAMIC_SIZE_RESOLUTION_TYPE_ARG4          1 << 4
#define DYNAMIC_SIZE_RESOLUTION_TYPE_ARG5          1 << 5
#define DYNAMIC_SIZE_RESOLUTION_TYPE_RETURN_VALUE  1 << 6
#define DYNAMIC_SIZE_RESOLUTION_TYPE_TRAILING_ZERO 1 << 7

struct syscall_argument {
    u32 dereference_count;
    u32 size;
    u32 size_multiplier;
    u32 dynamic_size_resolution_type;
};

struct syscall_definition {
    struct syscall_argument args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct syscall_definition);
	__uint(max_entries, 600);
} syscall_definitions SEC(".maps");

__attribute__((always_inline)) struct syscall_definition *lookup_definition(u32 syscall_nr) {
    return bpf_map_lookup_elem(&syscall_definitions, &syscall_nr);
}

__attribute__((always_inline)) int resolve_args(struct syscall_cache *cache, struct syscall_definition *def, struct syscall_buffer *buf) {
    u64 *arg_tmp = 0;
    u64 arg = 0;
    u64 size = 0;
    int copy_ret = 0;

    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (def->args[i].size == 0 && def->args[i].dynamic_size_resolution_type == DYNAMIC_SIZE_RESOLUTION_TYPE_UNKNOWN) {
            goto exit;
        }

        arg = (u64) cache->args[i];

        // handle dereferences
        if (def->args[i].dereference_count == 2) {
            if (arg == 0) {
                // null pointer can't be dereferenced, move on
                goto exit;
            }
            arg_tmp = (u64 *)arg;
            bpf_probe_read_user(&arg, sizeof(arg), arg_tmp);
        }
        // arg is now either a pointer to a value, or the value itself

        // resolve value size
        size = def->args[i].size;
        if (size == 0) {
            // the size is determined at runtime
            switch (def->args[i].dynamic_size_resolution_type) {
                case DYNAMIC_SIZE_RESOLUTION_TYPE_ARG0:
                    size = cache->args[0];
                    break;
                case DYNAMIC_SIZE_RESOLUTION_TYPE_ARG1:
                    size = cache->args[1];
                    break;
                case DYNAMIC_SIZE_RESOLUTION_TYPE_ARG2:
                    size = cache->args[2];
                    break;
                case DYNAMIC_SIZE_RESOLUTION_TYPE_ARG3:
                    size = cache->args[3];
                    break;
                case DYNAMIC_SIZE_RESOLUTION_TYPE_ARG4:
                    size = cache->args[4];
                    break;
                case DYNAMIC_SIZE_RESOLUTION_TYPE_ARG5:
                    size = cache->args[5];
                    break;
                case DYNAMIC_SIZE_RESOLUTION_TYPE_RETURN_VALUE:
                    size = buf->evt.ret;
                    break;
            }

            // use multiplier if applicable
            if (def->args[i].size_multiplier > 0) {
                size = size * def->args[i].size_multiplier;
            }
        }
        if (size > MAX_DATA_PER_ARG) {
            size = MAX_DATA_PER_ARG;
        }

        // copy value
        if (def->args[i].dereference_count == 1 || def->args[i].dereference_count == 2) {
            // arg is a pointer to the value
            if (def->args[i].dynamic_size_resolution_type == DYNAMIC_SIZE_RESOLUTION_TYPE_TRAILING_ZERO) {
                copy_ret = bpf_probe_read_user_str(&buf->args[(buf->cursor + 4) & (MAX_DATA_PER_SYSCALL - MAX_DATA_PER_ARG - 1)], MAX_DATA_PER_ARG, (void *)arg);
            } else {
                copy_ret = bpf_probe_read_user(&buf->args[(buf->cursor + 4) & (MAX_DATA_PER_SYSCALL - MAX_DATA_PER_ARG - 1)], size, (void *)arg);
                if (copy_ret == 0) {
                    copy_ret = size;
                }
            }
        } else {
            // arg is the value itself
            copy_ret = bpf_probe_read_kernel(&buf->args[(buf->cursor + 4) & (MAX_DATA_PER_SYSCALL - MAX_DATA_PER_ARG - 1)], size, &arg);
            if (copy_ret == 0) {
                copy_ret = size;
            }
        }

        bpf_probe_read(&buf->args[buf->cursor & (MAX_DATA_PER_SYSCALL - MAX_DATA_PER_ARG - 1)], sizeof(int), &copy_ret);
        if (copy_ret > 0) {
            buf->cursor += copy_ret + 4;
        } else {
            buf->cursor += 4;
        }
    }

exit:
    return 0;
}

#endif