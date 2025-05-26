/* SPDX-License-Identifier: GPL-2.0
 *
 *  NAT64 EBPF module for Linux
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

// rfc7915
#ifndef TEST
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#else
#include "test_bpf.h"
#endif
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <stdbool.h>
#include <stdint.h>

static const uint8_t magic_ether[ETH_ALEN] = { 02, 00, 00, 00, 00, 0x64 };
static const uint8_t v6_prefix[] = { 0x00, 0x64, 0xFF, 0x9B, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t ipv4_addr[4] = { 192, 168, 4, 4 };

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memcmp
#define memcmp(s1, s2, n) __builtin_memcmp((s1), (s2), (n))
#endif

#ifndef memset
#define memset(s1, c, n) __builtin_memset((s1), (c), (n))
#endif

#ifndef memzero
#define memzero(s1, n) memset((s1), 0, (n))
#endif

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#define LOG(msg, ...) { static const char fmt[] = (msg); bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__); }
#define LOG_IF(cond, msg, ...) do { if (UNLIKELY(cond)) LOG(msg, ##__VA_ARGS__); } while(0)

#define MAX(a,b) ({ typeof(a) maxtmp_a = (a); typeof(b) maxtmp_b = (b); maxtmp_a > maxtmp_b ? maxtmp_a : maxtmp_b; })

typedef enum status_t {
    STATUS_SUCCESS, /* Successfully transformed */
    STATUS_INVALID, /* Invalid input frame - drop with diagnostic */
    STATUS_PASS, /* Ignore frame */
    STATUS_DROP, /* Silently drop frame */
} status_t;

static const char *status_names[] = {
    [STATUS_SUCCESS] = "SUCCESS",
    [STATUS_INVALID] = "INVALID",
    [STATUS_PASS] = "PASS",
    [STATUS_DROP] = "DROP",
};

#define RETURN_IF_ERR(x) do { status_t err = (x); if (err == STATUS_INVALID) LOG("invalid at %d", __LINE__); if (UNLIKELY(err != STATUS_SUCCESS)) return err; } while(0)
#define RETURN_IF_NULL(x) do { if (UNLIKELY((x) == NULL)) return STATUS_INVALID; } while(0)


static __always_inline uint16_t u8_combine(uint8_t hi, uint8_t lo) {
    return ((uint16_t)hi << 8) | lo;
}


static __always_inline uint16_t u32_combine(uint32_t value) {
    return ((value >> 16) & 0xFFFF) | (value & 0xFFFF);
}


static __always_inline uint32_t partial_netsum(__arg_nonnull void *data, size_t len) {
    uint32_t netsum = 0;
    uint8_t *data8 = data;

    for(size_t i = 0; i < len; i += 2) {
        netsum += u8_combine(data8[i], data8[i+1]);
    }

    return netsum;
}


static __always_inline uint16_t finalise_netsum(uint32_t netsum) {
    netsum = (netsum >> 16) + (netsum & 0xFFFF);
    netsum = (netsum >> 16) + (netsum & 0xFFFF);
    return htons((uint16_t)~netsum);
}


static __always_inline status_t err_to_status(int err) {
    if (err < 0) {
        return STATUS_INVALID;
    }
    return STATUS_SUCCESS;
}


static __always_inline size_t packet_len(__arg_ctx struct xdp_md *ctx) {
    return ctx->data_end - ctx->data;
}


static __always_inline void *get_header_at(__arg_ctx struct xdp_md *ctx, size_t offset, size_t hdr_size) {
    if (UNLIKELY(ctx->data + offset + hdr_size > ctx->data_end)) {
        LOG("Wanted header of %d bytes, only %d remaining",
                hdr_size,
                (int)(ctx->data_end - ctx->data - offset));
        return NULL;
    }
    return (void *)(unsigned long)(ctx->data + offset);
}


static __always_inline void *get_header(__arg_ctx struct xdp_md *ctx, size_t hdr_size) {
    return get_header_at(ctx, 0, hdr_size);
}


static __always_inline status_t pop_header(__arg_ctx struct xdp_md *ctx, size_t hdr_size, __arg_nullable uint32_t *old_parent_netsum) {
    if (old_parent_netsum) {
        if (LIKELY(ctx->data + hdr_size <= ctx->data_end)) {
            *old_parent_netsum += partial_netsum((void *)(unsigned long)ctx->data, hdr_size);
        } else {
            LOG("pop_header can't netsum");
        }
    }

    return err_to_status(bpf_xdp_adjust_head(ctx, hdr_size));
}


static __always_inline status_t push_header(__arg_ctx struct xdp_md *ctx, __arg_nonnull void *hdr, size_t hdr_size, __arg_nullable uint32_t *new_parent_netsum) {
    RETURN_IF_ERR(err_to_status(bpf_xdp_adjust_head(ctx, -hdr_size)));

    if (UNLIKELY(ctx->data + hdr_size > ctx->data_end))
        return STATUS_INVALID;

    memcpy((void *)(unsigned long)ctx->data, hdr, hdr_size);

    if (new_parent_netsum)
        *new_parent_netsum += partial_netsum(hdr, hdr_size);

    return STATUS_SUCCESS;
}


static __always_inline status_t replace_header(__arg_ctx struct xdp_md *ctx,
        size_t old_hdr_size,
        __arg_nullable uint32_t *old_parent_netsum,
        __arg_nonnull void *new_hdr,
        size_t new_hdr_size,
        __arg_nullable uint32_t *new_parent_netsum) {
    ssize_t delta = new_hdr_size - old_hdr_size;

    if (old_parent_netsum) {
        void *old_hdr;
        RETURN_IF_NULL((old_hdr = get_header_at(ctx, 0, old_hdr_size)));
        *old_parent_netsum += partial_netsum(old_hdr, old_hdr_size);
    }

    RETURN_IF_ERR(err_to_status(bpf_xdp_adjust_head(ctx, -delta)));

    void *data;
    RETURN_IF_NULL((data = get_header_at(ctx, 0, new_hdr_size)));

    memcpy(data, new_hdr, new_hdr_size);

    if (new_parent_netsum)
        *new_parent_netsum += partial_netsum(data, new_hdr_size);

    return STATUS_SUCCESS;
}


static __always_inline uint32_t pseudo_netsum_from_ipv4(__arg_nonnull const struct ip *ip) {
    uint32_t netsum = 0;
    netsum += ntohs(ip->ip_src.s_addr >> 16);
    netsum += ntohs(ip->ip_src.s_addr & 0xFFFF);
    netsum += ntohs(ip->ip_dst.s_addr >> 16);
    netsum += ntohs(ip->ip_dst.s_addr & 0xFFFF);

    netsum += u8_combine(0, ip->ip_p);
    netsum += ntohs(ip->ip_len) - ip->ip_hl * 4; // ip payload length
    return netsum;
}


static __always_inline uint32_t pseudo_netsum_from_ipv6(__arg_nonnull const struct ip6_hdr *ip6) {
    uint32_t netsum = 0;
    for (size_t i = 0; i < 8; ++i) {
        netsum += ntohs(ip6->ip6_src.s6_addr16[i]);
        netsum += ntohs(ip6->ip6_dst.s6_addr16[i]);
    }

    /* payload length */
    netsum += ntohs(ip6->ip6_plen) >> 16; // This will always be zero, because v4 doesn't support jumbo frames
    netsum += ntohs(ip6->ip6_plen) & 0xFFFF;

    netsum += u8_combine(0, 0); // zeros
    netsum += u8_combine(0, ip6->ip6_nxt);

    netsum = (netsum >> 16) + (netsum & 0xFFFF);

    return netsum;
}


/* This function applies the incremental checksum fixup to an existing checksum.
 * old is the value that should be removed from the checksum.
 * new is the value that should be added to the checksum.
 * If changing this checksum also changes a checksum elsewhere (eg updating the
 * UDP checksum inside IPv4 | ICMPv4 | IPv4 | UDP, where the ICMPv4 checksum
 * also needs to be updated), then that is the parent_old and parent_new and
 * they will be updated.  If parent_old and parent_new are NULL, then they will
 * be ignored and no further update will be applied.
 */
static __always_inline void apply_checksum_fixup(__arg_nonnull uint16_t *checksum,
        uint32_t old,
        uint32_t new,
        __arg_nullable uint32_t *restrict parent_old,
        __arg_nullable uint32_t *restrict parent_new) {
    new = (new & 0xFFFF) + (new >> 16);
    new = (new & 0xFFFF) + (new >> 16);

    LOG_IF(new > 0xFFFF, "new not fully wrapped: %04x", new);

    /* Because of 1s compliment math, -x is the same as ~x.
     * Checksums are stored as the bitwise complement (~) of the 16 bit 1bit sums.
     * so checksum = ~(total)
     *             = ~(~orig - old + new)
     *             = ~(~orig + ~old + new)
     *             = ~~orig + ~~old + ~new
     *             = orig + old + ~new
     */
    uint32_t update = ntohs(*checksum) + old + (uint16_t)~new;
    update = (update & 0xFFFF) + (update >> 16);
    update = (update & 0xFFFF) + (update >> 16);
    LOG_IF(update > 0xFFFF, "update not fully wrapped: %04x", update);

    if (parent_old)
        *parent_old += ntohs(*checksum);
    *checksum = htons(update);
    if (parent_new)
        *parent_new += ntohs(*checksum);
}


static __always_inline struct in6_addr remap_v4_to_v6(struct in_addr addr) {
    struct in6_addr ret;
    memcpy(ret.s6_addr, v6_prefix, sizeof(v6_prefix));
    ret.s6_addr32[3] = addr.s_addr;
    return ret;
}


static __always_inline struct in_addr remap_v6_to_v4(struct in6_addr addr) {
    if (memcmp(addr.s6_addr, v6_prefix, sizeof(v6_prefix)) == 0) {
        /* This is an IPv4 embedded in a v6 address, unpack it. */
        return (struct in_addr) {
            .s_addr = addr.s6_addr32[3],
        };
    }

    /* Lets use a dummy address for now*/
    return (struct in_addr) {
        .s_addr = *(uint32_t*)&ipv4_addr[0],
    };
}


static __always_inline struct ip construct_v4_from_v6(__arg_nonnull const struct ip6_hdr *ip6) {
    struct ip ip;
    ip.ip_v = 0x4;
    ip.ip_hl = 20/4;
    ip.ip_tos = (ntohl(ip6->ip6_flow) >> 20) & 0xFF;
    ip.ip_len = htons(ntohs(ip6->ip6_plen) + ip.ip_hl * 4);
    ip.ip_id = 0x00; /* TODO: Handle fragmentation */
    ip.ip_off = 0x00; // TODO: Handle fragmentation
    ip.ip_ttl = ip6->ip6_hlim;
    ip.ip_p = (ip6->ip6_nxt == IPPROTO_ICMPV6) ? IPPROTO_ICMP : ip6->ip6_nxt;
    ip.ip_sum = 0x0000;
    ip.ip_src = remap_v6_to_v4(ip6->ip6_src);
    ip.ip_dst = remap_v6_to_v4(ip6->ip6_dst);
    ip.ip_sum = finalise_netsum(partial_netsum(&ip, sizeof(ip)));

    return ip;
}


static __always_inline struct ip6_hdr construct_v6_from_v4(struct ip *iphdr) {
    struct ip6_hdr ip6hdr;
    ip6hdr.ip6_flow = htonl(6 << 28 | iphdr->ip_tos << 20);
    ip6hdr.ip6_plen = htons(ntohs(iphdr->ip_len) - iphdr->ip_hl * 4);
    ip6hdr.ip6_hlim = iphdr->ip_ttl;
    ip6hdr.ip6_nxt = (iphdr->ip_p == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : iphdr->ip_p;
    ip6hdr.ip6_src = remap_v4_to_v6(iphdr->ip_src);
    ip6hdr.ip6_dst = remap_v4_to_v6(iphdr->ip_dst);

    return ip6hdr;
}


// Ethernet | IPv4 | ICMPv4 | IPv4 | UDP
// Ethernet | IPv6 | ICMPv6 | IPv6 | UDP
static __always_inline status_t process_udp(__arg_ctx struct xdp_md *ctx,
        size_t offset,
        uint32_t old_netsum,
        uint32_t new_netsum,
        __arg_nullable uint32_t *restrict old_parent_netsum,
        __arg_nullable uint32_t *restrict new_parent_netsum) {

    struct udphdr *udp = NULL;
    RETURN_IF_NULL((udp = get_header_at(ctx, offset, sizeof(struct udphdr))));

    apply_checksum_fixup(&udp->check, old_netsum, new_netsum, old_parent_netsum, new_parent_netsum);

    return STATUS_SUCCESS;
}


// Ethernet | IPv4 | ICMPv4 | IPv4 | TCP  =>  Ethernet | IPv6 | ICMPv6 | IPv6 | TCP
// Ethernet | IPv6 | ICMPv6 | IPv6 | TCP  =>  Ethernet | IPv4 | ICMPv4 | IPv4 | TCP
static __always_inline status_t process_tcp(__arg_ctx struct xdp_md *ctx,
        size_t offset,
        uint32_t old_netsum,
        uint32_t new_netsum,
        __arg_nullable uint32_t *restrict old_parent_netsum,
        __arg_nullable uint32_t *restrict new_parent_netsum) {
    struct tcphdr *tcp = NULL;
    RETURN_IF_NULL((tcp = get_header_at(ctx, offset, sizeof(struct tcphdr))));

    apply_checksum_fixup(&tcp->check, old_netsum, new_netsum, old_parent_netsum, new_parent_netsum);

    return STATUS_SUCCESS;
}


// Ethernet | IPv4 | ICMPv4 | IPv4 | ICMPv4  =>  Ethernet | IPv6 | ICMPv6 | IPv6 | ICMPv6
static __always_inline status_t process_quoted_icmp4(__arg_ctx struct xdp_md *ctx,
        size_t offset,
        uint32_t old_netsum,
        uint32_t new_netsum,
        __arg_nonnull uint32_t *restrict old_parent_netsum,
        __arg_nonnull uint32_t *restrict new_parent_netsum) {
    /* There are no more headers after the ICMP header, and the kernel won't
     * let us shrink the packet too small, so we can't do the general approach
     * of popping it and pushing on the replacement, so we want to do it in
     * place.
     */
    struct icmphdr *icmp = NULL;
    RETURN_IF_NULL((icmp = get_header_at(ctx, offset, sizeof(struct icmphdr))));

    old_netsum += u8_combine(icmp->type, icmp->code);
    *old_parent_netsum += u8_combine(icmp->type, icmp->code);

    status_t ret = STATUS_INVALID;

    switch (icmp->type) {
        case ICMP_ECHOREPLY:
            icmp->type = ICMP6_ECHO_REPLY;
            ret = STATUS_SUCCESS;
            break;
        /* ICMP Errors should never be quoted, so drop them */
        case ICMP_DEST_UNREACH:
        case ICMP_TIME_EXCEEDED:
            return STATUS_INVALID;
        case ICMP_ECHO:
            icmp->type = ICMP6_ECHO_REQUEST;
            ret = STATUS_SUCCESS;
            break;
        /* Single hop messages, not routed */
        case 9: /* Router Advertisement */
        case 10: /* Router solicitation */
            return STATUS_DROP;
        /* Obsolete messages */
        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
        case ICMP_ADDRESS:
        case ICMP_ADDRESSREPLY:
            LOG("Obsolete icmp v4 type %d dropped", icmp->type);
            return STATUS_DROP;
        default: /* Unknown */
            LOG("Unknown icmp v4 type %d dropped", icmp->type);
            return STATUS_INVALID;
    }

    new_netsum += u8_combine(icmp->type, icmp->code);
    *new_parent_netsum += u8_combine(icmp->type, icmp->code);

    apply_checksum_fixup(&icmp->checksum, old_netsum, new_netsum, old_parent_netsum, new_parent_netsum);

    return ret;
}


// Ethernet | IPv6 | ICMPv6 | IPv6 | ICMPv6
static __always_inline status_t process_quoted_icmp6(__arg_ctx struct xdp_md *ctx,
        size_t offset,
        uint32_t old_netsum,
        uint32_t new_netsum,
        __arg_nullable uint32_t *restrict old_parent_netsum,
        __arg_nullable uint32_t *restrict new_parent_netsum) {
    struct icmp6_hdr *icmp6 = NULL;
    RETURN_IF_NULL((icmp6 = get_header_at(ctx, offset, sizeof(struct icmp6_hdr))));

    old_netsum += u8_combine(icmp6->icmp6_type, icmp6->icmp6_code);

    int ret = STATUS_INVALID;

    switch (icmp6->icmp6_type) {
        case ICMP6_ECHO_REPLY:
            icmp6->icmp6_type = ICMP_ECHO;
            ret = STATUS_SUCCESS;
            break;
        /* ICMP Errors should not contain an ICMP Error, drop */
        case ICMP6_DST_UNREACH:
        case ICMP6_TIME_EXCEEDED:
            LOG("nested error %d", icmp6->icmp6_type);
            ret = STATUS_INVALID;
            break;
        case ICMP6_ECHO_REQUEST:
            LOG("Got nested icmp6 echo request");
            icmp6->icmp6_type = ICMP_ECHO;
            ret = STATUS_SUCCESS;
            break;
        /* Single hop messages, not routed */
        /* Obsolete messages */
        default: /* Unknown */
            LOG("Unknown icmp v6 type %d", icmp6->icmp6_type);
            break;
    }

    new_netsum += u8_combine(icmp6->icmp6_type, icmp6->icmp6_code);

    apply_checksum_fixup(&icmp6->icmp6_cksum, old_netsum, new_netsum, old_parent_netsum, new_parent_netsum);

    return ret;
}

// Ethernet | IPv4 | ICMPv4 | IPv4 | ...
static __always_inline status_t process_quoted_ipv4(__arg_ctx struct xdp_md *ctx,
        __arg_nullable uint32_t *restrict old_parent_netsum,
        __arg_nullable uint32_t *restrict new_parent_netsum) {
    struct ip *iphdr = NULL;

    RETURN_IF_NULL((iphdr = get_header(ctx, sizeof(struct ip))));

    uint8_t protocol = iphdr->ip_p;

    struct ip6_hdr ip6hdr = construct_v6_from_v4(iphdr);

    /* TODO: Handle fragmented IPv4 packet */

    uint32_t old_netsum = pseudo_netsum_from_ipv4(iphdr);
    uint32_t new_netsum = pseudo_netsum_from_ipv6(&ip6hdr);

    if (UNLIKELY(iphdr->ip_v != 0x04)) {
        LOG("not ipv4: %d", iphdr->ip_v);
        return STATUS_INVALID;
    }

    /* Due to limits on minimum packet sizes imposed by the kernel, we cannot
     * do the usual pop / push for this, but instead need to do it all in place.
     */
    RETURN_IF_ERR(replace_header(ctx, sizeof(struct ip), old_parent_netsum, &ip6hdr, sizeof(ip6hdr), new_parent_netsum));
    size_t offset = sizeof(ip6hdr);

    /* Handle any inner protocols that need handling */
    switch (protocol) {
        case IPPROTO_ICMP:
            return process_quoted_icmp4(ctx, offset, 0 /* icmp4 has no pseudo header */, new_netsum, old_parent_netsum, new_parent_netsum);
        case IPPROTO_TCP:
            return process_tcp(ctx, offset, old_netsum, new_netsum, old_parent_netsum, new_parent_netsum);
        case IPPROTO_UDP:
            return process_udp(ctx, offset, old_netsum, new_netsum, old_parent_netsum, new_parent_netsum);

        /* These don't need fixups */
        case IPPROTO_AH:
        case IPPROTO_ESP:
        case IPPROTO_SCTP:
            break;
    }

    /* Send the packet out the incoming interface */
    return STATUS_SUCCESS;
}


// Ethernet | IPv6 | ICMPv6 | IPv6 | ...
static __always_inline status_t process_quoted_ipv6(__arg_ctx struct xdp_md *ctx,
        __arg_nullable uint32_t *restrict old_parent_netsum,
        __arg_nullable uint32_t *restrict new_parent_netsum) {
    struct ip6_hdr *ip6 = NULL;

    RETURN_IF_NULL((ip6 = get_header(ctx, sizeof(struct ip6_hdr))));

    if (UNLIKELY((ip6->ip6_vfc & 0xF0) != 0x60)) {
        LOG("ip6 version: %d", ip6->ip6_vfc);
        return STATUS_INVALID;
    }

    uint8_t protocol = ip6->ip6_nxt;

    struct ip ip = construct_v4_from_v6(ip6);

    uint32_t old_netsum = pseudo_netsum_from_ipv6(ip6);
    uint32_t new_netsum = pseudo_netsum_from_ipv4(&ip);

    /* TODO: Handle fragmented IPv4 packet */

    RETURN_IF_ERR(replace_header(ctx, sizeof(struct ip6_hdr), old_parent_netsum, &ip, sizeof(ip), new_parent_netsum));
    size_t offset = sizeof(ip);

    /* Handle any inner protocols that need handling */
    switch (protocol) {
        case IPPROTO_ICMPV6:
            RETURN_IF_ERR(process_quoted_icmp6(ctx, offset, old_netsum, 0 /* icmp4 doesn't have a pseudo header */, old_parent_netsum, new_parent_netsum));
            break;
        case IPPROTO_TCP:
            RETURN_IF_ERR(process_tcp(ctx, offset, old_netsum, new_netsum, old_parent_netsum, new_parent_netsum));
            break;
        case IPPROTO_UDP:
            RETURN_IF_ERR(process_udp(ctx, offset, old_netsum, new_netsum, old_parent_netsum, new_parent_netsum));
            break;

        /* These don't need fixups */
        case IPPROTO_AH:
        case IPPROTO_ESP:
        case IPPROTO_SCTP:
            break;
    }

    /* Push on the new IPv6 header */
    RETURN_IF_ERR(push_header(ctx, &ip, sizeof(ip), new_parent_netsum));

    /* Send the packet out the incoming interface */
    return STATUS_SUCCESS;
}


// Ethernet | IPv4 | ICMPv4... => Ethernet | IPv6 | ICMPv6...
static __always_inline status_t process_icmp4(__arg_ctx struct xdp_md *ctx, uint32_t old_netsum, uint32_t new_netsum) {
    struct icmphdr *icmp = NULL;
    RETURN_IF_NULL((icmp = get_header(ctx, sizeof(struct icmphdr))));

    struct icmp6_hdr icmp6;
    memcpy(&icmp6, icmp, sizeof(icmp6));

    RETURN_IF_ERR(pop_header(ctx, sizeof(struct icmphdr), NULL));

    /* The packet length can change when we replace the IP header,
     * so remove the old packet length from the checksum here.
     */
    uint16_t old_packet_len = packet_len(ctx) + sizeof(struct icmphdr);
    old_netsum += old_packet_len;

    /* Also remove the old type and code, because it's going to be remapped */
    old_netsum += u8_combine(icmp6.icmp6_type, icmp6.icmp6_code);

    status_t ret = STATUS_INVALID;

    switch (icmp6.icmp6_type) {
        case ICMP_ECHOREPLY:
            icmp6.icmp6_type = ICMP6_ECHO_REPLY;
            ret = STATUS_SUCCESS;
            break;
        case ICMP_DEST_UNREACH:
            icmp6.icmp6_type = ICMP6_DST_UNREACH;
            switch (icmp6.icmp6_code) {
                case ICMP_NET_UNREACH: icmp6.icmp6_code = ICMP6_DST_UNREACH_NOROUTE; break;
                case ICMP_HOST_UNREACH: icmp6.icmp6_code = ICMP6_DST_UNREACH_NOROUTE; break;
                case ICMP_PROT_UNREACH: LOG("Not Implemented"); /* TODO */ break;
                case ICMP_PORT_UNREACH: icmp6.icmp6_code = ICMP6_DST_UNREACH_NOPORT; break;
                case ICMP_FRAG_NEEDED:
                          icmp6.icmp6_code = ICMP6_PACKET_TOO_BIG;
                          icmp6.icmp6_type = 0;
                          icmp6.icmp6_mtu = htonl(icmp6.icmp6_mtu != 0 ? icmp6.icmp6_mtu - sizeof(struct ip) : 1280);
                          break;
                case ICMP_SR_FAILED: icmp6.icmp6_code = ICMP6_DST_UNREACH_NOROUTE; break;
                case ICMP_NET_UNKNOWN: icmp6.icmp6_code = ICMP6_DST_UNREACH_NOROUTE; break;
                case ICMP_HOST_UNKNOWN: icmp6.icmp6_code = ICMP6_DST_UNREACH_NOROUTE; break;
                case ICMP_HOST_ISOLATED: icmp6.icmp6_code = ICMP6_DST_UNREACH_NOROUTE; break;
                case ICMP_NET_ANO: icmp6.icmp6_code = ICMP6_DST_UNREACH_ADMIN; break;
                case ICMP_HOST_ANO: icmp6.icmp6_code = ICMP6_DST_UNREACH_ADMIN; break;
                case ICMP_NET_UNR_TOS: icmp6.icmp6_code = ICMP6_DST_UNREACH_NOROUTE; break;
                case ICMP_HOST_UNR_TOS: icmp6.icmp6_code = ICMP6_DST_UNREACH_NOROUTE; break;
                case ICMP_PKT_FILTERED: icmp6.icmp6_code = ICMP6_DST_UNREACH_ADMIN; break;
                case ICMP_PREC_VIOLATION: return STATUS_DROP; break;
                default:
                  return STATUS_DROP;
            }
            ret = process_quoted_ipv4(ctx, &old_netsum, &new_netsum);
            break;
        case ICMP_TIME_EXCEEDED:
            icmp6.icmp6_type = ICMP6_TIME_EXCEEDED;
            ret = process_quoted_ipv4(ctx, &old_netsum, &new_netsum);
            break;
        case ICMP_ECHO:
            icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
            ret = STATUS_SUCCESS;
            break;
        /* Single hop messages, not routed */
        case 9: /* Router Advertisement */
        case 10: /* Router solicitation */
            LOG("unroutable single hop message");
            return STATUS_DROP;
        /* Obsolete messages */
        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
        case ICMP_ADDRESS:
        case ICMP_ADDRESSREPLY:
            LOG("Obsolete icmp v4 type %d dropped", icmp6.icmp6_type);
            return STATUS_DROP;
        default: /* Unknown */
            LOG("Unknown icmp v4 type %d dropped", icmp6.icmp6_type);
            return STATUS_DROP;
    }

    /* ... Add back the packet length to the checksum */
    uint16_t new_packet_len = packet_len(ctx) + sizeof(icmp6);
    new_netsum += new_packet_len;
    new_netsum += u8_combine(icmp6.icmp6_type, icmp6.icmp6_code);

    /* Modifying the checksum between pop and push header is okay here, because
     * there's no parent to be modified twice */
    apply_checksum_fixup(&icmp6.icmp6_cksum, old_netsum, new_netsum, NULL, NULL);

    RETURN_IF_ERR(push_header(ctx, &icmp6, sizeof(icmp6), NULL));

    return ret;
}


// Ethernet | IPv6 | ICMPv6... => Ethernet | IPv4 | ICMPv4...
static __always_inline status_t process_icmp6(__arg_ctx struct xdp_md *ctx, uint32_t old_netsum, uint32_t new_netsum) {
    struct icmp6_hdr *icmp6 = NULL;
    RETURN_IF_NULL((icmp6 = get_header(ctx, sizeof(struct icmp6_hdr))));

    struct icmphdr icmp4;
    icmp4.type = icmp6->icmp6_type;
    icmp4.code = icmp6->icmp6_code;
    icmp4.checksum = icmp6->icmp6_cksum;

    old_netsum += u8_combine(icmp6->icmp6_type, icmp6->icmp6_code);

    RETURN_IF_ERR(pop_header(ctx, sizeof(struct icmp6_hdr), NULL));

    status_t ret = STATUS_DROP;

    switch (icmp4.type) {
        case ICMP6_DST_UNREACH:
            icmp4.type = ICMP_DEST_UNREACH;
            switch (icmp4.code) {
                case ICMP6_DST_UNREACH_NOROUTE: icmp4.code = ICMP_NET_UNREACH; break;
                case ICMP6_DST_UNREACH_ADMIN: icmp4.code = ICMP_HOST_ANO; break;
                case ICMP6_DST_UNREACH_BEYONDSCOPE: icmp4.code = ICMP_HOST_UNREACH ; break;
                case ICMP6_DST_UNREACH_ADDR: icmp4.code = ICMP_HOST_UNKNOWN; break;
                case ICMP6_DST_UNREACH_NOPORT: icmp4.code = ICMP_PORT_UNREACH; break;
                default:
                  return STATUS_DROP;
            }
            ret = process_quoted_ipv6(ctx, &old_netsum, &new_netsum);
            break;
        case ICMP6_PACKET_TOO_BIG:
            icmp4.type = ICMP_DEST_UNREACH;
            icmp4.code = ICMP_FRAG_NEEDED;
            icmp4.un.frag.mtu -= 20;
            ret = process_quoted_ipv6(ctx, &old_netsum, &new_netsum);
            break;
        case ICMP6_TIME_EXCEEDED:
            icmp4.type = ICMP_TIME_EXCEEDED;
            ret = process_quoted_ipv6(ctx, &old_netsum, &new_netsum);
            break;
        case ICMP6_PARAM_PROB: /* TODO */ break;
        case ICMP6_ECHO_REPLY:
            icmp4.type = ICMP_ECHO;
            ret = STATUS_SUCCESS;
            break;
        case ICMP6_ECHO_REQUEST:
            LOG("Got icmp6 echo request");
            icmp4.type = ICMP_ECHO;
            ret = STATUS_SUCCESS;
            break;
        /* Single hop messages, not routed */
        /* Obsolete messages */
        default: /* Unknown */
            LOG("Unknown icmp v6 type %d", icmp4.type);
            break;
    }

    new_netsum += u8_combine(icmp4.type, icmp4.code);

    apply_checksum_fixup(&icmp4.checksum, old_netsum, new_netsum, NULL, NULL);

    RETURN_IF_ERR(push_header(ctx, &icmp4, sizeof(icmp4), NULL));

    return ret;
}


// Ethernet | IPv4... => Ethernet | IPv6...
static __always_inline status_t process_ipv4(__arg_ctx struct xdp_md *ctx) {
    struct ip *iphdr = NULL;

    RETURN_IF_NULL((iphdr = get_header(ctx, sizeof(struct ip))));

    uint8_t protocol = iphdr->ip_p;

    struct ip6_hdr ip6hdr = construct_v6_from_v4(iphdr);

    /* TODO: Handle fragmented IPv4 packet */

    uint32_t old_netsum = pseudo_netsum_from_ipv4(iphdr);
    uint32_t new_netsum = pseudo_netsum_from_ipv6(&ip6hdr);

    /* Strip off the old IPv4 header */
    RETURN_IF_ERR(pop_header(ctx, sizeof(struct ip), NULL));

    /* Handle any inner protocols that need handling */
    switch (protocol) {
        case IPPROTO_ICMP:
            RETURN_IF_ERR(process_icmp4(ctx, 0 /* icmp4 has no pseudo header */, new_netsum));
            break;
        case IPPROTO_TCP:
            RETURN_IF_ERR(process_tcp(ctx, 0, old_netsum, new_netsum, NULL, NULL));
            break;
        case IPPROTO_UDP:
            RETURN_IF_ERR(process_udp(ctx, 0, old_netsum, new_netsum, NULL, NULL));
            break;

        /* These don't need fixups */
        case IPPROTO_AH:
        case IPPROTO_ESP:
        case IPPROTO_SCTP:
            break;
    }

    ip6hdr.ip6_plen = htons(packet_len(ctx));

    /* Push on the new IPv6 header */
    RETURN_IF_ERR(push_header(ctx, &ip6hdr, sizeof(ip6hdr), NULL));

    /* Send the packet out the incoming interface */
    return STATUS_SUCCESS;
}


// Ethernet | IPv6... => Ethernet | IPv4...
static __always_inline status_t process_ipv6(__arg_ctx struct xdp_md *ctx) {
    struct ip6_hdr *ip6 = NULL;

    RETURN_IF_NULL((ip6 = get_header(ctx, sizeof(struct ip6_hdr))));

    uint8_t protocol = ip6->ip6_nxt;

    struct ip ip = construct_v4_from_v6(ip6);

    uint32_t old_netsum = pseudo_netsum_from_ipv6(ip6);
    uint32_t new_netsum = pseudo_netsum_from_ipv4(&ip);

    /* TODO: Handle fragmented IPv4 packet */

    /* Strip off the old IPv6 header */
    RETURN_IF_ERR(pop_header(ctx, sizeof(struct ip6_hdr), NULL));

    /* Handle any inner protocols that need handling */
    switch (protocol) {
        case IPPROTO_ICMPV6:
            RETURN_IF_ERR(process_icmp6(ctx, old_netsum, 0 /* icmp4 doesn't have a pseudo header */));
            break;
        case IPPROTO_TCP:
            RETURN_IF_ERR(process_tcp(ctx, 0, old_netsum, new_netsum, NULL, NULL));
            break;
        case IPPROTO_UDP:
            RETURN_IF_ERR(process_udp(ctx, 0, old_netsum, new_netsum, NULL, NULL));
            break;

        /* These don't need fixups */
        case IPPROTO_AH:
        case IPPROTO_ESP:
        case IPPROTO_SCTP:
            break;
    }

    uint16_t old = ntohs(ip.ip_len);
    /* Fixup packet length */
    ip.ip_len = htons(packet_len(ctx) + sizeof(ip));
    apply_checksum_fixup(&ip.ip_sum, old, ntohs(ip.ip_len), NULL, NULL);

    /* Push on the new IPv6 header */
    RETURN_IF_ERR(push_header(ctx, &ip, sizeof(ip), NULL));

    /* Send the packet out the incoming interface */
    return STATUS_SUCCESS;
}

// Ethernet | IPv4... => Ethernet | IPv6...
// Ethernet | IPv6... => Ethernet | IPv4...
static __always_inline status_t process_ethernet(__arg_ctx struct xdp_md *ctx) {
    struct ether_header *ethhdr = NULL;

    RETURN_IF_NULL(ethhdr = get_header(ctx, sizeof(struct ether_header)));

    /* Is this to the magic ethernet address? */
    if (memcmp(magic_ether, ethhdr->ether_dhost, sizeof(magic_ether)) == 0) {
        struct ether_header newhdr;
        /* Build a new header */
        memcpy(newhdr.ether_dhost, ethhdr->ether_shost, ETH_ALEN);
        memcpy(newhdr.ether_shost, ethhdr->ether_dhost, ETH_ALEN);
        newhdr.ether_type = ethhdr->ether_type;

        /* Discard the old header */
        RETURN_IF_ERR(pop_header(ctx, sizeof(newhdr), NULL));

        status_t ret;

        switch (ntohs(newhdr.ether_type)) {
            case ETHERTYPE_IP:
                newhdr.ether_type = htons(ETHERTYPE_IPV6);
                ret = process_ipv4(ctx);
                break;

            case ETHERTYPE_IPV6:
                newhdr.ether_type = htons(ETHERTYPE_IP);
                ret = process_ipv6(ctx);
                break;

            default:
                LOG("Unknown ethertype %04x", ntohs(newhdr.ether_type));
                return STATUS_DROP;
        }

        /* Now push our new ethernet header back on the front */
        RETURN_IF_ERR(push_header(ctx, &newhdr, sizeof(newhdr), NULL));
        LOG("Done with status %d", ret);
        return ret;
    } else {
        //LOG("Packet not to magic ethernet address, ignoring.");
        //TODO: We should increment a counter here
        return STATUS_PASS;
    }
}

extern int xdp_nat64(__arg_ctx struct xdp_md *ctx);

SEC("xdp")
int xdp_nat64(__arg_ctx struct xdp_md *ctx) {
    switch (process_ethernet(ctx)) {
        case STATUS_PASS: return XDP_PASS;
        case STATUS_INVALID: return XDP_DROP;
        case STATUS_SUCCESS: return XDP_TX;
        case STATUS_DROP: return XDP_DROP;
    }
}

char _license[] SEC("license") = "GPL";
