/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CONST_H_
#define _CONST_H_

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

__attribute__((always_inline)) static u64 load_etrace_tgid() {
    u64 etrace_tgid = 0;
    LOAD_CONSTANT("etrace_tgid", etrace_tgid);
    return etrace_tgid;
}

__attribute__((always_inline)) static u64 load_syscall_filter() {
    u64 syscall_filter = 0;
    LOAD_CONSTANT("syscall_filter", syscall_filter);
    return syscall_filter;
}

__attribute__((always_inline)) static u64 load_comm_filter() {
    u64 comm_filter = 0;
    LOAD_CONSTANT("comm_filter", comm_filter);
    return comm_filter;
}

#endif
