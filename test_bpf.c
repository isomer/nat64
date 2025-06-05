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

#include "test_bpf.h"
#include <net/ethernet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

long bpf_trace_printk(const char *restrict fmt, size_t fmt_size, ...) {
    assert(fmt[fmt_size-1] == '\0');
    long ret;

    va_list ap;
    va_start(ap, fmt_size);
    ret = vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    return ret;
}


long bpf_xdp_adjust_head(struct xdp_md *ctx, int delta) {
    if (ctx->data + delta + ETH_HLEN > ctx->data_end) {
        printf("Requested: %d (%" PRIdPTR " remaining)", delta, ctx->data_end - ctx->data);
        return -EINVAL;
    }
    ctx->data += delta;
    return 0;
}

void *bpf_map_lookup_elem(void *map, void *key) {
    (void) map;
    (void) key;
    abort(); // TODO
}

void *nat64_4to6;
void *nat64_6to4;
void *nat64_scratch;
