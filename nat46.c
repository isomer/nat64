/* SPDX-License-Identifier: GPL-2.0 */
// rfc7915
#include <linux/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
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

// ipv4 pseudo header (all values in network byte order)
struct pseudo4 {
    uint8_t source[4];
    uint8_t dest[4];
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
};

// ipv6 pseudo header (all values in network byte order)
struct pseudo6 {
    uint8_t source[16];
    uint8_t dest[16];
    uint32_t length;
    uint8_t zero[3];
    uint8_t nxthdr;
};

static __always_inline uint64_t combine_ipv4(uint8_t addr[static 4]) {
    uint64_t netsum = 0;
    //netsum += ntohs(((uint16_t)addr[0] << 8) | addr[1]);
    //netsum += ntohs(((uint16_t)addr[2] << 8) | addr[3]);
    /* Note: returned in host byte order */
    return netsum;
}

static __always_inline uint64_t combine_ipv6(uint8_t addr[static 16]) {
    uint64_t netsum = 0;
    netsum += ntohs(((uint16_t)addr[0] << 8) | addr[1]);
    netsum += ntohs(((uint16_t)addr[2] << 8) | addr[3]);
    netsum += (((uint16_t)addr[4] << 8) | addr[5]);
    netsum += ntohs(((uint16_t)addr[6] << 8) | addr[7]);
    netsum += ntohs(((uint16_t)addr[8] << 8) | addr[9]);
    netsum += ntohs(((uint16_t)addr[10] << 8) | addr[11]);
    //netsum += ntohs(((uint16_t)addr[12] << 8) | addr[13]);
    //netsum += ntohs(((uint16_t)addr[14] << 8) | addr[15]);
    LOG("v6 addr netsum=%04llx", netsum);
    /* Note: returned in host byte order */
    return netsum;
}

static __always_inline uint16_t pseudo4_netsum(struct pseudo4 pseudo4) {
    uint64_t netsum = 0;
    netsum += combine_ipv4(pseudo4.source);
    netsum += combine_ipv4(pseudo4.dest);
    //netsum += ntohs((pseudo4.zero << 8) | pseudo4.protocol);
    //netsum += ntohs(pseudo4.length);

    netsum = (netsum & 0xFFFF) + (netsum >> 16);
    netsum = (netsum & 0xFFFF) + (netsum >> 16);

    if (netsum > 0xFFFF)
        LOG("ipv4 netsum not fully wrapped: %lld", netsum);

    /* note: returned in host byte order not network byte order */
    return netsum;
}

static __always_inline uint16_t pseudo6_netsum(struct pseudo6 pseudo6) {
    uint64_t netsum = 0;
    netsum += combine_ipv6(pseudo6.source);
    netsum += combine_ipv6(pseudo6.dest);
    //netsum += ntohs((uint16_t)(pseudo6.length >> 16));
    //netsum += ntohs((uint16_t)(pseudo6.length & 0xFFFF));
    //netsum += ntohs((pseudo6.zero[2] << 8) | pseudo6.nxthdr);

    LOG("unfolded netsum=%04lld", netsum);
    netsum = (netsum & 0xFFFF) + (netsum >> 16);
    netsum = (netsum & 0xFFFF) + (netsum >> 16);
    LOG("folded netsum=%04lld", netsum);

    if (netsum > 0xFFFF)
        LOG("netsum checksum not fully wrapped: %lld", netsum);

    /* note: returned in host byte order not network byte order */
    return netsum;
}

static __always_inline uint16_t incremental_update(uint16_t orig_checksum, struct pseudo4 pseudo4, struct pseudo6 pseudo6) {

    uint64_t old = pseudo4_netsum(pseudo4);
    uint64_t new = pseudo6_netsum(pseudo6);

    LOG("old=%04llx new=%04llx ~new=%04x", old, new, (uint16_t)~new);

    uint64_t checksum = ntohs(orig_checksum) + (uint16_t)old + (uint16_t)~new;
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);

    if (checksum > 0xFFFF) {
        LOG("Final checksum not wrapped");
    }

    return htons(checksum);
}

static __always_inline struct pseudo4 pseudo_from_ipv4(struct ip *ip) {
    struct pseudo4 ret = (struct pseudo4) {
            .zero = 0,
            .protocol = ip->ip_p,
            .length = htons(ntohs(ip->ip_len) - ip->ip_hl * 4),
    };

    memcpy(&ret.source, &ip->ip_src.s_addr, sizeof(ret.source));
    memcpy(&ret.dest, &ip->ip_dst.s_addr, sizeof(ret.dest));

    return ret;
}

static __always_inline struct pseudo6 pseudo_from_ipv6(struct ip6_hdr *ip6) {
    struct pseudo6 pseudo6;
    pseudo6.length = ip6->ip6_plen;
    memzero(&pseudo6.zero, sizeof(pseudo6.zero));
    pseudo6.nxthdr = ip6->ip6_nxt;
    memcpy(&pseudo6.source, &ip6->ip6_src, sizeof(pseudo6.source));
    memcpy(&pseudo6.dest, &ip6->ip6_dst, sizeof(pseudo6.dest));

    return pseudo6;
}

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

static __always_inline int process_udp(struct xdp_md *ctx, struct pseudo4 *pseudo4, struct pseudo6 *pseudo6) {
    struct udphdr *udp = NULL;
    if (!(udp = get_header(ctx, sizeof(struct udphdr)))) {
        return XDP_PASS;
    }

    LOG("Old checksum=%04x", ntohs(udp->check));
    udp->check = incremental_update(udp->check, *pseudo4, *pseudo6);
    LOG("New checksum=%04x", ntohs(udp->check));

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
    ip6hdr.ip6_plen = htons(ntohs(iphdr->ip_len) - iphdr->ip_hl * 4);
    ip6hdr.ip6_hlim = iphdr->ip_ttl;
    ip6hdr.ip6_nxt = protocol;

    uint32_t v4_src = ntohl(iphdr->ip_src.s_addr);
    uint32_t v4_dst = ntohl(iphdr->ip_dst.s_addr);
    uint8_t v6_dst[16] = {
        0x00,0x64, 0xff, 0x9b, 0x00, 0x01, 0x00, 0x00,
        0x00,0x00, 0x00, 0x00, (v4_dst >> 24) & 0xFF, (v4_dst >> 16) & 0xFF, (v4_dst >> 8) & 0xFF, (v4_dst & 0xFF)
    };
    uint8_t v6_src[16] = {
        0x00,0x64, 0xff, 0x9b, 0x00, 0x01, 0x00, 0x00,
        0x00,0x00, 0x00, 0x00, (v4_src >> 24) & 0xFF, (v4_src >> 16) & 0xFF, (v4_src >> 8) & 0xFF, (v4_src & 0xFF)
    };

    memcpy(&ip6hdr.ip6_dst, v6_dst, sizeof(ip6hdr.ip6_dst));
    memcpy(&ip6hdr.ip6_src, v6_src, sizeof(ip6hdr.ip6_src));

    /* pseudo header */
    struct pseudo4 pseudo4 = pseudo_from_ipv4(iphdr);
    struct pseudo6 pseudo6 = pseudo_from_ipv6(&ip6hdr);

    /* TODO: Handle fragmented IPv4 packet */

    /* Strip off the old IPv4 header */
    if (pop_header(ctx, sizeof(struct ip)) < 0)
        return XDP_PASS;

    /* Handle any inner protocols that need handling */
    switch (protocol) {
        int ret;
        case IPPROTO_ICMP:
            /* TODO */
            break;
        case IPPROTO_UDP:
            if ((ret = process_udp(ctx, &pseudo4, &pseudo6)) != XDP_TX)
                return ret;
            break;
    }

    /* Push on the new IPv6 header */
    if (push_header(ctx, &ip6hdr, sizeof(ip6hdr)) < 0)
        return XDP_DROP;

    /* Send the packet out the incoming interface */
    LOG("rewrite done");
    return XDP_TX; // bpf_redirect(ctx->ingress_ifindex, 0);
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
