/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

// Custom eBPF helpers
#include "include/all.h"

// etrace probes
#include "etrace/const.h"
#include "etrace/process.h"
#include "etrace/syscall_cache.h"
#include "etrace/event.h"
#include "etrace/syscall_args.h"
#include "etrace/etrace.h"

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
