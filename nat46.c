/* SPDX-License-Identifier: GPL-2.0 */
// rfc7915
#include <linux/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <stdbool.h>
#include <stdint.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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

#define LOG(msg, ...) { static const char fmt[] = (msg); bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__); }
#define LOG_IF(cond, msg, ...) do { if (cond) LOG(msg, ##__VA_ARGS__); } while(0)

static __always_inline int pop_header(struct xdp_md *ctx, size_t hdr_size) {
    return bpf_xdp_adjust_head(ctx, hdr_size);
}


static __always_inline int push_header(struct xdp_md *ctx, void *hdr, size_t hdr_size) {
    int ret = bpf_xdp_adjust_head(ctx, -hdr_size);
    if (ret < 0)
        return ret;

    if (ctx->data + hdr_size > ctx->data_end)
        return -1;

    memcpy((void *)(unsigned long)ctx->data, hdr, hdr_size);
    return 0;
}


static __always_inline void *get_header(struct xdp_md *ctx, size_t hdr_size) {
    if (ctx->data + hdr_size > ctx->data_end)
        return NULL;
    return (void *)(unsigned long)ctx->data;
}


static __always_inline uint16_t u16_combine(uint8_t hi, uint8_t lo) {
    return ntohs(((uint16_t)hi << 8) | lo);
}


static __always_inline uint32_t pseudo_netsum_from_ipv4(struct ip *ip) {
    uint32_t netsum = 0;
    netsum += ntohs(ip->ip_src.s_addr >> 16);
    netsum += ntohs(ip->ip_src.s_addr & 0xFFFF);
    netsum += ntohs(ip->ip_dst.s_addr >> 16);
    netsum += ntohs(ip->ip_dst.s_addr & 0xFFFF);

    netsum += u16_combine(0, ip->ip_p);
    netsum += ntohs(ip->ip_len) - ip->ip_hl * 4; // ip payload length

    return netsum;
}


static __always_inline uint32_t pseudo_netsum_from_ipv6(struct ip6_hdr *ip6) {
    uint32_t netsum = 0;
    for (size_t i = 0; i < 8; ++i) {
        netsum += ntohs(ip6->ip6_src.s6_addr16[i]);
        netsum += ntohs(ip6->ip6_dst.s6_addr16[i]);
    }

    /* payload length */
    netsum += ntohl(ip6->ip6_plen) >> 16;
    netsum += ntohl(ip6->ip6_plen) & 0xFFFF;

    netsum += u16_combine(0, 0); // zeros
    netsum += u16_combine(0, ip6->ip6_nxt);

    return netsum;
}


static __always_inline void apply_checksum_fixup(uint16_t *checksum, uint32_t old, uint32_t new) {
    LOG("prev=%04x", ntohs(*checksum));
    LOG("%04x -> %04x", old, new);
    old = (old & 0xFFFF) + (old >> 16);
    old = (old & 0xFFFF) + (old >> 16);
    new = (new & 0xFFFF) + (new >> 16);
    new = (new & 0xFFFF) + (new >> 16);
    LOG("%04x -w> %04x", old, new);
    LOG("%04x => %04x", (uint16_t)~new, old + (uint16_t)~new);

    LOG_IF(old > 0xFFFF, "old not fully wrapped: %04x", old);
    LOG_IF(new > 0xFFFF, "new not fully wrapped: %04x", new);

    uint32_t update = ntohs(*checksum) + old + (uint16_t)~new;
    update = (update & 0xFFFF) + (update >> 16);
    update = (update & 0xFFFF) + (update >> 16);
    LOG_IF(update > 0xFFFF, "update not fully wrapped: %04x", update);

    *checksum = htons(update);
}


static __always_inline int process_icmp(struct xdp_md *ctx, uint32_t old_netsum, uint32_t new_netsum) {
    struct icmphdr *icmp = NULL;
    if (!(icmp = get_header(ctx, sizeof(struct icmphdr)))) {
        LOG("unable to get icmp header");
        return XDP_PASS;
    }

    old_netsum += u16_combine(icmp->type, icmp->code);

    switch (icmp->type) {
        case ICMP_ECHOREPLY:
            //icmp->type = ICMP6_ECHO_REPLY;
            break;
        case ICMP_DEST_UNREACH: /* TODO */
        case ICMP_TIME_EXCEEDED: /* TODO */
            return XDP_DROP;
        case ICMP_ECHO:
            //icmp->type = ICMP6_ECHO_REQUEST;
            break;
        /* Single hop messages, not routed */
        case 9: /* Router Advertisement - Single hop */
        case 10: /* Router solicitation - Single hop */
            return XDP_DROP;
        /* Obsolete messages */
        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
        case ICMP_ADDRESS:
        case ICMP_ADDRESSREPLY:
            LOG("Obsolete icmp v4 type %d dropped", icmp->type);
            return XDP_DROP;
        default: /* Unknown */
            LOG("Unknown icmp v4 type %d dropped", icmp->type);
            return XDP_DROP;
    }

    new_netsum += u16_combine(icmp->type, icmp->code);

    apply_checksum_fixup(&icmp->checksum, old_netsum, new_netsum);

    return XDP_TX;
}


static __always_inline int process_tcp(struct xdp_md *ctx, uint32_t old_netsum, uint32_t new_netsum) {
    struct tcphdr *tcp = NULL;
    if (!(tcp = get_header(ctx, sizeof(struct tcphdr)))) {
        return XDP_PASS;
    }

    apply_checksum_fixup(&tcp->check, old_netsum, new_netsum);

    return XDP_TX;
}


static __always_inline int process_udp(struct xdp_md *ctx, uint32_t old_netsum, uint32_t new_netsum) {
    struct udphdr *udp = NULL;
    if (!(udp = get_header(ctx, sizeof(struct udphdr)))) {
        return XDP_PASS;
    }

    apply_checksum_fixup(&udp->check, old_netsum, new_netsum);

    return XDP_TX;
}


static __always_inline int process_ipv4(struct xdp_md *ctx) {
    struct ip *iphdr = NULL;

    if (!(iphdr = get_header(ctx, sizeof(struct ip))))
        return XDP_PASS;

    uint8_t protocol = iphdr->ip_p;

    /* Construct a new IPv6 header based on the existing ipv4 header */
    struct ip6_hdr ip6hdr;
    ip6hdr.ip6_flow = 0x0; /* TODO: Copy traffic control bits */
    ip6hdr.ip6_vfc = 0x60; /* TODO: Copy traffic control bits */
    LOG("ip_len=%04x", ntohs(iphdr->ip_len));
    ip6hdr.ip6_plen = htons(ntohs(iphdr->ip_len) - iphdr->ip_hl * 4);
    ip6hdr.ip6_hlim = iphdr->ip_ttl;
    ip6hdr.ip6_nxt = (protocol == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : protocol;

    uint32_t v4_src = ntohl(iphdr->ip_src.s_addr);
    uint32_t v4_dst = ntohl(iphdr->ip_dst.s_addr);
    /* TODO: These arrays should probably be uint16_t's rather than uint8_ts */
    uint8_t v6_src[16] = {
        0x00,0x64, 0xff, 0x9b, 0x00, 0x01, 0x00, 0x00,
        0x00,0x00, 0x00, 0x00, (v4_src >> 24) & 0xFF, (v4_src >> 16) & 0xFF, (v4_src >> 8) & 0xFF, (v4_src & 0xFF)
    };
    uint8_t v6_dst[16] = {
        0x00,0x64, 0xff, 0x9b, 0x00, 0x01, 0x00, 0x00,
        0x00,0x00, 0x00, 0x00, (v4_dst >> 24) & 0xFF, (v4_dst >> 16) & 0xFF, (v4_dst >> 8) & 0xFF, (v4_dst & 0xFF)
    };

    memcpy(&ip6hdr.ip6_dst, v6_dst, sizeof(ip6hdr.ip6_dst));
    memcpy(&ip6hdr.ip6_src, v6_src, sizeof(ip6hdr.ip6_src));

    uint32_t old_netsum = pseudo_netsum_from_ipv4(iphdr);
    uint32_t new_netsum = pseudo_netsum_from_ipv6(&ip6hdr);

    /* TODO: Handle fragmented IPv4 packet */

    /* Strip off the old IPv4 header */
    if (pop_header(ctx, sizeof(struct ip)) < 0) {
        LOG("failed to pop v4 header");
        return XDP_PASS;
    }

    /* Handle any inner protocols that need handling */
    switch (protocol) {
        int ret;
        case IPPROTO_ICMP:
            if ((ret = process_icmp(ctx, 0 /* icmp4 has no pseudo header */, new_netsum)) != XDP_TX)
                return ret;
            break;
        case IPPROTO_TCP:
            if ((ret = process_tcp(ctx, old_netsum, new_netsum)) != XDP_TX)
                return ret;
            break;
        case IPPROTO_UDP:
            if ((ret = process_udp(ctx, old_netsum, new_netsum)) != XDP_TX)
                return ret;
            break;

        /* These don't need fixups */
        case IPPROTO_AH:
        case IPPROTO_ESP:
        case IPPROTO_SCTP:
            break;
    }

    /* Push on the new IPv6 header */
    if (push_header(ctx, &ip6hdr, sizeof(ip6hdr)) < 0) {
        LOG("failed to push v6 header");
        return XDP_DROP;
    }

    /* Send the packet out the incoming interface */
    LOG("rewrite done");
    return XDP_TX;
}


static __always_inline int process_ethernet(struct xdp_md *ctx) {
    static const uint8_t magic_ether[ETH_ALEN] = { 02, 00, 00, 00, 00, 0x46 };
    struct ether_header *ethhdr = NULL;
    struct ether_header newhdr;

    if (!(ethhdr = get_header(ctx, sizeof(struct ether_header)))) {
        LOG("packet missing ethernet header");
        return XDP_PASS;
    }

    if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP
            && memcmp(magic_ether, ethhdr->ether_dhost, sizeof(magic_ether)) == 0) {

        /* Build a new header based on the old header */
        memcpy(newhdr.ether_dhost, ethhdr->ether_shost, ETH_ALEN);
        memcpy(newhdr.ether_shost, ethhdr->ether_dhost, ETH_ALEN);
        newhdr.ether_type = htons(ETHERTYPE_IPV6);

        /* Discard the old header */
        if (pop_header(ctx, sizeof(newhdr)) < 0) {
            LOG("couldn't pop ethernet header ");
            return XDP_PASS;
        }

        /* Process the remaining */
        int ret = process_ipv4(ctx);

        /* Now push our new ethernet header back on the front */
        if (push_header(ctx, &newhdr, sizeof(newhdr)) < 0) {
                LOG("couldn't push ethernet header");
                return XDP_DROP;
        }

        return ret;
    } else {
        return XDP_PASS;
    }
}


SEC("xdp")
int xdp_4to6(struct xdp_md *ctx) {
    return process_ethernet(ctx);
}

char _license[] SEC("license") = "GPL";
