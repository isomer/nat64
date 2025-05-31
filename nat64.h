/* SPDX-License-Identifier: GPL-2.0
 *
 *  Shared definitions between userspace and ebpf program for nat64
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
#ifndef NAT64_H
#define NAT64_h
#include <stdint.h>
#include <net/ethernet.h>

typedef enum {
    COUNTER_INVALID_IPVER,
    COUNTER_NEST_ICMP_ERR,
    COUNTER_OBSOLETE_ICMP,
    COUNTER_SUCCESS,
    COUNTER_TRUNCATED,
    COUNTER_UNKNOWN_ETHERTYPE,
    COUNTER_UNKNOWN_ICMPV4,
    COUNTER_UNKNOWN_ICMPV6,
    COUNTER_UNKNOWN_IPV4,
    COUNTER_UNKNOWN_IPV6,
    COUNTER_WRONG_MAC,
    COUNTER_MAX,
} counter_t;

enum { VERSION = 1 };

typedef struct configmap_t {
    int version;
    int success_action;
    int ignore_action;
    uint8_t v6_prefix[16];
    uint8_t magic_mac[ETH_ALEN];
    uint8_t gateway_mac[ETH_ALEN];
    uint8_t ipv4_addr[4];
} configmap_t;

#endif
