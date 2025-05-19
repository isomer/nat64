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
    return ((uint16_t)hi << 8) | lo;
}


static __always_inline uint32_t partial_netsum(uint8_t *data, size_t len) {
    uint32_t netsum = 0;

    for(size_t i = 0; i < len; i += 2) {
        netsum += u16_combine(data[i], data[i+1]);
    }

    return netsum;
}


static __always_inline uint16_t finalise_netsum(uint32_t netsum) {
    netsum = (netsum >> 16) + (netsum & 0xFFFF);
    netsum = (netsum >> 16) + (netsum & 0xFFFF);
    return htons((uint16_t)~netsum);
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
    netsum += ntohs(ip6->ip6_plen) >> 16; // This will always be zero, because v4 doesn't support jumbo frames
    netsum += ntohs(ip6->ip6_plen) & 0xFFFF;

    netsum += u16_combine(0, 0); // zeros
    netsum += u16_combine(0, ip6->ip6_nxt);

    netsum = (netsum >> 16) + (netsum & 0xFFFF);

    return netsum;
}


static __always_inline void apply_checksum_fixup(uint16_t *checksum, uint32_t old, uint32_t new) {
    new = (new & 0xFFFF) + (new >> 16);
    new = (new & 0xFFFF) + (new >> 16);

    LOG_IF(new > 0xFFFF, "new not fully wrapped: %04x", new);

    uint32_t update = ntohs(*checksum) + old + (uint16_t)~new;
    update = (update & 0xFFFF) + (update >> 16);
    update = (update & 0xFFFF) + (update >> 16);
    LOG_IF(update > 0xFFFF, "update not fully wrapped: %04x", update);

    *checksum = htons(update);
}


static __always_inline int process_icmp4(struct xdp_md *ctx, uint32_t old_netsum, uint32_t new_netsum) {
    struct icmphdr *icmp = NULL;
    if (!(icmp = get_header(ctx, sizeof(struct icmphdr)))) {
        LOG("unable to get icmp header");
        return XDP_PASS;
    }

    old_netsum += u16_combine(icmp->type, icmp->code);

    switch (icmp->type) {
        case ICMP_ECHOREPLY:
            icmp->type = ICMP6_ECHO_REPLY;
            break;
        case ICMP_DEST_UNREACH: /* TODO */
        case ICMP_TIME_EXCEEDED: /* TODO */
            return XDP_DROP;
        case ICMP_ECHO:
            icmp->type = ICMP6_ECHO_REQUEST;
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


static __always_inline int process_icmp6(struct xdp_md *ctx, uint32_t old_netsum, uint32_t new_netsum) {
    struct icmp6_hdr *icmp6 = NULL;
    if (!(icmp6 = get_header(ctx, sizeof(struct icmp6_hdr)))) {
        LOG("unable to get icmp header");
        return XDP_PASS;
    }

    LOG("Got icmp6 type %d", icmp6->icmp6_type);

    old_netsum += u16_combine(icmp6->icmp6_type, icmp6->icmp6_code);

    switch (icmp6->icmp6_type) {
        case ICMP6_ECHO_REPLY:
            icmp6->icmp6_type = ICMP_ECHO;
            break;
        case ICMP6_DST_UNREACH: /* TODO */
        case ICMP6_TIME_EXCEEDED: /* TODO */
            return XDP_DROP;
        case ICMP6_ECHO_REQUEST:
            LOG("Got icmp6 echo request");
            icmp6->icmp6_type = ICMP_ECHO;
            break;
        /* Single hop messages, not routed */
        /* Obsolete messages */
        default: /* Unknown */
            LOG("Unknown icmp v6 type %d dropped", icmp6->icmp6_type);
            return XDP_DROP;
    }

    new_netsum += u16_combine(icmp6->icmp6_type, icmp6->icmp6_code);

    apply_checksum_fixup(&icmp6->icmp6_cksum, old_netsum, new_netsum);

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


static __always_inline struct in6_addr remap_v4_to_v6(struct in_addr addr) {
    struct in6_addr ret;
    memcpy(ret.s6_addr, v6_prefix, sizeof(v6_prefix));
    ret.s6_addr32[3] = addr.s_addr;
    return ret;
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
    ip6hdr.ip6_plen = htons(ntohs(iphdr->ip_len) - iphdr->ip_hl * 4);
    ip6hdr.ip6_hlim = iphdr->ip_ttl;
    ip6hdr.ip6_nxt = (protocol == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : protocol;
    ip6hdr.ip6_src = remap_v4_to_v6(iphdr->ip_src);
    ip6hdr.ip6_dst = remap_v4_to_v6(iphdr->ip_dst);

    /* TODO: Handle fragmented IPv4 packet */

    uint32_t old_netsum = pseudo_netsum_from_ipv4(iphdr);
    uint32_t new_netsum = pseudo_netsum_from_ipv6(&ip6hdr);

    /* Strip off the old IPv4 header */
    if (pop_header(ctx, sizeof(struct ip)) < 0) {
        LOG("failed to pop v4 header");
        return XDP_PASS;
    }

    /* Handle any inner protocols that need handling */
    switch (protocol) {
        int ret;
        case IPPROTO_ICMP:
            if ((ret = process_icmp4(ctx, 0 /* icmp4 has no pseudo header */, new_netsum)) != XDP_TX)
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
    return XDP_TX;
}


static __always_inline int process_ipv6(struct xdp_md *ctx) {
    struct ip6_hdr *ip6 = NULL;

    if (!(ip6 = get_header(ctx, sizeof(struct ip6_hdr))))
        return XDP_PASS;

    /* Construct a new IPv4 header based on the existing IPv6 header */
    uint8_t protocol = ip6->ip6_nxt;
    struct ip ip;

    ip.ip_v = 0x4;
    ip.ip_hl = 20/4;
    ip.ip_tos = 0x00; /* TODO: Copy traffic control bits */
    ip.ip_len = htons(ntohs(ip6->ip6_plen) + ip.ip_hl * 4);
    ip.ip_id = 0x00; /* TODO: Handle fragmentation */
    ip.ip_off = 0x00; // TODO: Handle fragmentation
    ip.ip_ttl = ip6->ip6_hlim;
    ip.ip_p = (protocol == IPPROTO_ICMPV6) ? IPPROTO_ICMP : protocol;
    ip.ip_sum = 0x0000;
    ip.ip_src = remap_v6_to_v4(ip6->ip6_src);
    ip.ip_dst = remap_v6_to_v4(ip6->ip6_dst);
    ip.ip_sum = finalise_netsum(partial_netsum((void*)&ip, sizeof(ip)));

    uint32_t old_netsum = pseudo_netsum_from_ipv6(ip6);
    uint32_t new_netsum = pseudo_netsum_from_ipv4(&ip);

    /* TODO: Handle fragmented IPv4 packet */

    /* Strip off the old IPv4 header */
    if (pop_header(ctx, sizeof(struct ip6_hdr)) < 0) {
        LOG("failed to pop v6 header");
        return XDP_PASS;
    }

    /* Handle any inner protocols that need handling */
    switch (protocol) {
        int ret;
        case IPPROTO_ICMPV6:
            if ((ret = process_icmp6(ctx, old_netsum, 0 /* icmp4 doesn't have a pseudo header */)) != XDP_TX)
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
    if (push_header(ctx, &ip, sizeof(ip)) < 0) {
        LOG("failed to push v6 header");
        return XDP_DROP;
    }

    /* Send the packet out the incoming interface */
    return XDP_TX;
}


static __always_inline int process_ethernet(struct xdp_md *ctx) {
    struct ether_header *ethhdr = NULL;

    if (!(ethhdr = get_header(ctx, sizeof(struct ether_header)))) {
        LOG("packet missing ethernet header");
        return XDP_PASS;
    }

    /* Is this to the magic ethernet address? */
    if (memcmp(magic_ether, ethhdr->ether_dhost, sizeof(magic_ether)) == 0) {
        struct ether_header newhdr;
        /* Build a new header */
        memcpy(newhdr.ether_dhost, ethhdr->ether_shost, ETH_ALEN);
        memcpy(newhdr.ether_shost, ethhdr->ether_dhost, ETH_ALEN);
        newhdr.ether_type = ethhdr->ether_type;

        /* Discard the old header */
        if (pop_header(ctx, sizeof(newhdr)) < 0) {
            LOG("couldn't pop ethernet header ");
            return XDP_PASS;
        }

        int ret = XDP_DROP;

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
                return XDP_DROP;
        }

        /* Now push our new ethernet header back on the front */
        if (push_header(ctx, &newhdr, sizeof(newhdr)) < 0) {
            LOG("couldn't push ethernet header");
            return XDP_DROP;
        }
        LOG("Done with status %d", ret);
        return ret;
    } else {
        //LOG("Packet not to magic ethernet address, ignoring.");
        //TODO: We should increment a counter here
        return XDP_PASS;
    }
}

extern int xdp_nat64(struct xdp_md *ctx);

SEC("xdp")
int xdp_nat64(struct xdp_md *ctx) {
    return process_ethernet(ctx);
}

char _license[] SEC("license") = "GPL";
