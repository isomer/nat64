/* SPDX-License-Identifier: GPL-2.0
 *
 *  Test wrappers for bpf functions
 *  Copyright (C) 2025  Perry Lorier
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef TEST_BPF_H
#define TEST_BPF_H
#include <sys/types.h>
#include <stdint.h>

#define __arg_ctx
#define __arg_nullable
#define __arg_nonnull

#define SEC(section)

struct xdp_md {
    uintptr_t data;
    uintptr_t data_end;
    uintptr_t data_meta;
    uint32_t ingress_ifindex;
    uint32_t rx_queue_index;
};

long bpf_trace_printk(const char *restrict fmt, size_t fmt_size, ...);
long bpf_xdp_adjust_head(struct xdp_md *ctx, int delta);
void *bpf_map_lookup_elem(void *map, void *key);

enum {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]
#define __ulong(name, val) enum { ___bpf_concat(__unique_value, __COUNTER__) = val } name


#endif
