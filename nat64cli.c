/* SPDX-License-Identifier: GPL-2.0
 *
 *  CLI tool for managing nat64 ebpf program
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
#include <xdp/libxdp.h>

#include "nat64.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct metric_t {
    const char *name;
    const char *help_text;
} metric_t;

static metric_t metrics[] = {
    [COUNTER_INVALID_IPVER] = { .name = "invalid_ipver", .help_text = "IP version number is incorrect" },
    [COUNTER_NEST_ICMP_ERR] = { .name = "nested_icmp_error", .help_text = "Number of invalid nested ICMP Errors" },
    [COUNTER_OBSOLETE_ICMP] = { .name = "obsolete_icmp", .help_text = "Count of obsolete icmp message types", },
    [COUNTER_SUCCESS] = { .name = "nat_success", .help_text = "Count of successfully translated packets", },
    [COUNTER_TRUNCATED] = { .name = "nat_truncated", .help_text = "Count of truncated packets", },
    [COUNTER_UNKNOWN_ETHERTYPE] = { .name = "unknown_ethertype", .help_text = "Count of ignored due to unknown ethernet type", },
    [COUNTER_UNKNOWN_ICMPV4] = { .name = "unknown_icmpv4", .help_text = "Count of ignored due to unknown icmp v4 type/code", },
    [COUNTER_UNKNOWN_ICMPV6] = { .name = "unknown_icmpv6", .help_text = "Count of ignored due to unknown icmp v6 type/code", },
    [COUNTER_UNKNOWN_IPV4] = { .name = "unknown_ipv4", .help_text = "Count of unknown IPv4 protocol", },
    [COUNTER_UNKNOWN_IPV6] = { .name = "unknown_ipv6", .help_text = "Count of unknown IPv6 protocol", },
    [COUNTER_WRONG_MAC] = { .name = "wrong_mac", .help_text = "Count of ignored due to destination mac mismatch", },
};

static const char *pin_path = "/proc/sys/fs/nat64/";

enum {
    EXIT_FAIL_BPF = 1,
};

int prog_fd = -1;


typedef bool (*predicate_t)(struct xdp_program *prog, const void *userdata);


static bool predicate_by_name(struct xdp_program *prog, const void *preddata) {
    const char *name = preddata;
    assert(prog);
    return strcmp(xdp_program__name(prog), name) == 0;
}


static bool predicate_by_id(struct xdp_program *prog, const void *preddata) {
    const uint32_t *id = preddata;
    return xdp_program__id(prog) == *id;
}


static bool find_subprogram_by_predicate(struct xdp_multiprog *mp, predicate_t pred, void *preddata, struct xdp_program **prog, int *mode) {
    /* Is this one of the multiprog subprograms? */
    while ((*prog = xdp_multiprog__next_prog(*prog, mp))) {
        if (pred(*prog, preddata)) {
            *mode = xdp_multiprog__attach_mode(mp);
            return true;
        }
    }

    /* Is it a legacy program? */
    if (xdp_multiprog__is_legacy(mp)) {
        printf("Legacy multiprogram\n");
        *prog = xdp_multiprog__main_prog(mp);
        if (*prog && pred(*prog, preddata)) {
            *mode = xdp_multiprog__attach_mode(mp);
            return true;
        }
    }

    /* Is it a hardware program? */
    *prog = xdp_multiprog__hw_prog(mp);
    if (*prog && pred(*prog, preddata)) {
        *mode = XDP_MODE_HW;
        return true;
    }

    fprintf(stderr, "Program not found\n");
    return false;
}


static bool find_program_by_predicate(int ifindex, predicate_t predicate, void *preddata, struct xdp_program **prog, int *mode) {
    struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(ifindex);

    if (!mp) {
        /* TODO: Library functions should not do I/O */
        fprintf(stderr, "No multiprog loaded on if#%d", ifindex);
        return false;
    }

    bool ret;
    if (!libxdp_get_error(mp)) {
        ret = find_subprogram_by_predicate(mp, predicate, preddata, prog, mode);
    } else {
		fprintf(stderr, "Unable to get xdp_dispatcher program: %s\n",
			strerror(errno));
        ret = false;
    }

    xdp_multiprog__close(mp);

    return ret;
}


static bool get_mac_address(const char *ifname, uint8_t mac_address[static ETH_ALEN]) {
    struct ifreq ifr;

    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        fprintf(stderr, "unable to get mac address\n");
    }

    strcpy(ifr.ifr_name, ifname);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        return false;
    }

    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    return true;
}

static bool load_program(struct bpf_object **prog) {
    char errmsg[1024];
    int err = 0;

    *prog = bpf_object__open_file("nat64.bpf.o", NULL);
    if (!prog) {
        fprintf(stderr, "failed to open bpf program: %s", strerror(errno));
        return false;
    }

    if ((err = bpf_object__load(*prog)) != 0) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "warning: Load failed: %s\n", errmsg);
        return false;
    }

	return true;
}


static bool attach_program(int ifindex, struct xdp_program *prog) {
    char errmsg[1024];
    int err = 0;

    printf("starting attachment\n");
    if ((err = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0)) != 0) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: attaching program: %s\n", errmsg);
        return false;
    }

	return true;
}


static const char *pop_arg(size_t argc, const char *argv[], size_t *idx) {
    if (*idx < argc) {
        return argv[(*idx)++];
    }
    else
        return NULL;
}


static void usage(const char *argv0) {
    fprintf(stderr, "%s <ifname> unload\n", argv0);
    fprintf(stderr, "%s <ifname> [reload] {OPTIONS...}\n", argv0);
    fprintf(stderr, "  OPTIONS := gateway (<gatewaymac>|reflect)\n");
    fprintf(stderr, "           | mac <gatewaymac>\n");
    fprintf(stderr, "           | success (pass|drop|tx)\n");
    fprintf(stderr, "           | ignore (pass|drop|tx)\n");
    fprintf(stderr, "           | map <fromprefix> <toprefix>\n");
    fprintf(stderr, "           | dynamic <v4prefix>\n");
}


static int parse_action(const char *st, int *action) {
    if (strcmp(st, "pass") == 0) {
        *action = XDP_PASS;
        return true;
    } else if (strcmp(st, "drop") == 0) {
        *action = XDP_DROP;
        return true;
    } else if (strcmp(st, "tx") == 0) {
        *action = XDP_TX;
        return true;
    } else {
        return false;
    }
}


static bool parse_mac(const char *st, uint8_t mac[static ETH_ALEN]) {
    return ether_hostton(st, (struct ether_addr *)mac) == 0
        || ether_aton_r(st, (struct ether_addr *)mac) != NULL;
}


static bool parse_prefix(const char *st, struct sockaddr_storage *addr) {
    const char *slash_pos = strchr(st, '/');
    if (!slash_pos) {
        fprintf(stderr, "Missing / in %s\n", st);
        return false;
    }

    char *network = strndup(st, slash_pos - st);
    if (!network)
        return false;

    if (inet_pton(AF_INET, network, &((struct sockaddr_in *)addr)->sin_addr) == 1) {
        struct sockaddr_in *sin4 = (struct sockaddr_in *)addr;
        sin4->sin_family = AF_INET;
        sin4->sin_port = atoi(slash_pos + 1);
        free(network);
        return sin4->sin_port <= 32;
    }

    if (inet_pton(AF_INET6, network, &((struct sockaddr_in6 *)addr)->sin6_addr) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = atoi(slash_pos + 1);
        free(network);
        return sin6->sin6_port <= 128;
    }

    free(network);
    return false;
}


static bool add_dynamic(int fd, uint32_t ipv4) {
    return bpf_map_update_elem(fd, NULL, &ipv4, BPF_ANY) == 0;
}


int main(int argc, const char *argv[]) {
    unsigned int ifindex = 0;
    struct bpf_object *prog = NULL;
    struct xdp_program *xdpprog = NULL;
    int mode = 0;
    size_t idx = 1;
    const char *ifname = pop_arg(argc, argv, &idx);
    int err;
    char errmsg[1024];
    bool do_attach = false;

    if (!ifname) {
        fprintf(stderr, "Missing ifname\n");
        usage(argv[0]);
        return 1;
    }

    if ((ifindex = if_nametoindex(ifname)) == 0) {
        fprintf(stderr, "Unknown interface %s\n", ifname);
        return 1;
    }

    find_program_by_predicate(ifindex, predicate_by_name, "xdp_nat64", &xdpprog, &mode);
    prog = xdp_program__bpf_obj(xdpprog);

    const char *arg = pop_arg(argc, argv, &idx);
    if (arg && strcmp(arg, "unload") == 0) {
        if (xdpprog) {
            fprintf(stderr, "Detatching old program\n");
            xdp_program__detach(xdpprog, ifindex, mode, 0);
            bpf_object__unpin(xdp_program__bpf_obj(xdpprog), pin_path);
            prog = NULL;
            xdpprog = NULL;
        }
        return 0;
    }

    if (arg && strcmp(arg, "reload") == 0) {
        if (xdpprog) {
            fprintf(stderr, "Detatching old program\n");
            xdp_program__detach(xdpprog, ifindex, mode, 0);
            bpf_object__unpin(xdp_program__bpf_obj(xdpprog), pin_path);
            prog = NULL;
            xdpprog = NULL;
        }
    }

    if (!prog) {
        printf("Beginning program load\n");
        if (!load_program(&prog)) {
            fprintf(stderr, "Failed to load ebpf program\n");
            return 1;
        }

        do_attach = true;
    }

    if ((err = bpf_object__pin(prog, pin_path)) != 0) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Pinning failed: %s\n", errmsg);
    }

    /* Get references to all the interesting maps */
    struct bpf_map *configmap = bpf_object__find_map_by_name(prog, "nat64_configmap");
    if (!configmap) {
        fprintf(stderr, "Failed to find config map\n");
        return false;
    }

    struct bpf_map *counters_map = bpf_object__find_map_by_name(prog, "nat64_counters");
    if (!counters_map) {
        fprintf(stderr, "Failed to find config map\n");
        return false;
    }

    struct bpf_map *nat64_6to4 = bpf_object__find_map_by_name(prog, "nat64_6to4");
    if (!nat64_6to4) {
        fprintf(stderr, "Couldn't find nat64_6to4 map\n");
        return false;
    }

    struct bpf_map *nat64_4to6 = bpf_object__find_map_by_name(prog, "nat64_4to6");
    if (!nat64_4to6) {
        fprintf(stderr, "Couldn't find nat64_4to6 map\n");
        return false;
    }

    struct bpf_map *nat64_dyn4 = bpf_object__find_map_by_name(prog, "nat64_dyn4");
    if (!nat64_dyn4) {
        fprintf(stderr, "Couldn't find nat64_dyn4 map\n");
        return false;
    }


    int configmap_fd = -1;
    int counters_fd = -1;
    int nat64_6to4_fd = -1;
    int nat64_4to6_fd = -1;
    int nat64_dyn4_fd = -1;

    if ((configmap_fd = bpf_map__fd(configmap)) == -1) {
        fprintf(stderr, "Failed to get configmap fd\n");
        return 1;
    }

    if ((counters_fd = bpf_map__fd(counters_map)) == -1) {
        fprintf(stderr, "Failed to get counters fd\n");
        return 1;
    }

    if ((nat64_6to4_fd = bpf_map__fd(nat64_6to4)) == -1) {
        fprintf(stderr, "Failed to get nat64_6to4 fd\n");
        return 1;
    }

    if ((nat64_4to6_fd = bpf_map__fd(nat64_4to6)) == -1) {
        fprintf(stderr, "Failed to get nat64_4to6 fd\n");
        return 1;
    }

    if ((nat64_4to6_fd = bpf_map__fd(nat64_dyn4)) == -1) {
        fprintf(stderr, "Failed to get nat64_dyn4 fd\n");
        return 1;
    }

    configmap_t config = { .version = 0 };
    int zero = 0;
    err = bpf_map_lookup_elem(configmap_fd, &zero, &config);
    if (err != 0) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Failed to read configmap, loading defaults: %s\n", errmsg);
    }

    /* Default config.  TODO: Read from running program */
    if (config.version == 0 || config.dst_mac_mode == 0) {
        /* No config, load defaults. */
        config = (configmap_t) {
            .version = VERSION,
            .success_action = XDP_TX,
            .ignore_action = XDP_DROP,
            .dst_mac_mode = DST_MAC_REFLECT,
            .magic_mac = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x64 },
        };

        if (!get_mac_address(ifname, config.gateway_mac)) {
            fprintf(stderr, "Failed to get mac address\n");
            return false;
        }
    } else if (config.version != VERSION) {
        fprintf(stderr, "Wrong version of ebpf program loaded, expected %d, got %d\n", VERSION, config.version);
        return 1;
    }

    while(arg) {
        if (strcmp(arg, "gateway") == 0) {
            const char *gw = pop_arg(argc, argv, &idx);
            if (!gw) {
                fprintf(stderr, "expected mac address or 'relect' after 'gateway'\n");
                usage(argv[0]);
                return 1;
            }
            if (strcmp(gw, "reflect") == 0) {
                config.dst_mac_mode = DST_MAC_REFLECT;
            } else if (parse_mac(gw, config.gateway_mac)) {
                config.dst_mac_mode = DST_MAC_GW;
            } else {
                fprintf(stderr, "Failed to parse gateway address\n");
                usage(argv[0]);
                return 1;
            }
        } else if (strcmp(arg, "mac") == 0) {
            const char *mac = pop_arg(argc, argv, &idx);
            if (!mac) {
                fprintf(stderr, "expected mac address after 'mac'\n");
                usage(argv[0]);
                return 1;
            } else if (parse_mac(mac, config.magic_mac)) {
                /* Success */
            } else {
                fprintf(stderr, "Failed to parse mac address\n");
                usage(argv[0]);
                return 1;
            }
        } else if (strcmp(arg, "success") == 0) {
            if (!parse_action(pop_arg(argc, argv, &idx), &config.success_action)) {
                fprintf(stderr, "Failed to parse success action\n");
                usage(argv[1]);
                return 1;
            }
        } else if (strcmp(arg, "ignore") == 0) {
            if (!parse_action(pop_arg(argc, argv, &idx), &config.ignore_action)) {
                fprintf(stderr, "Failed to parse ignore action\n");
                usage(argv[1]);
                return 1;
            }
        } else if (strcmp(arg, "stats") == 0) {
            fprintf(stderr, "Stats\n");
            size_t num_cpu = libbpf_num_possible_cpus();
            uint64_t counter[num_cpu];
            for(uint32_t key = 0; key < COUNTER_MAX; ++key) {
                if ((bpf_map_lookup_elem(counters_fd, &key, counter)) != 0) {
                    fprintf(stderr,
                            "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
                    return 1;
                }

                uint64_t total = 0;
                for(size_t i = 0; i < num_cpu; ++i) {
                    total += counter[i];
                }

                printf("# HELP %s %s\n# TYPE %s counter\n%s %"PRIu64"\n\n",
                        metrics[key].name,
                        metrics[key].help_text,
                        metrics[key].name,
                        metrics[key].name,
                        total);
            }
            printf("\n");
        } else if (strcmp(arg, "map") == 0) {
            const char *from_prefix_st = pop_arg(argc, argv, &idx);
            const char *to_prefix_st = pop_arg(argc, argv, &idx);
            if (!from_prefix_st || !to_prefix_st) {
                fprintf(stderr, "Expected from and to prefix\n");
                usage(argv[0]);
                return 1;
            }
            struct sockaddr_storage from_prefix;
            struct sockaddr_storage to_prefix;
            if (!parse_prefix(from_prefix_st, &from_prefix)) {
                fprintf(stderr, "Failed to parse from prefix: %s\n", from_prefix_st);
                usage(argv[0]);
                return 1;
            }
            if (!parse_prefix(to_prefix_st, &to_prefix)) {
                fprintf(stderr, "Failed to parse to prefix: %s\n", to_prefix_st);
                usage(argv[0]);
                return 1;
            }
            if (from_prefix.ss_family == AF_INET && to_prefix.ss_family == AF_INET6) {
                ipv4_prefix src;
                ipv6_prefix dst;
                src.len = ((struct sockaddr_in *)&from_prefix)->sin_port;
                src.prefix = ((struct sockaddr_in *)&from_prefix)->sin_addr;
                dst.len = ((struct sockaddr_in6 *)&to_prefix)->sin6_port;
                dst.prefix = ((struct sockaddr_in6 *)&to_prefix)->sin6_addr;
                if ((err = bpf_map_update_elem(nat64_4to6_fd, &src, &dst, BPF_ANY)) != 0) {
                    libbpf_strerror(err, errmsg, sizeof(errmsg));
                    fprintf(stderr, "Error adding 4to6 mapping: %s\n", errmsg);
                }
            } else if (from_prefix.ss_family == AF_INET6 && to_prefix.ss_family == AF_INET) {
                ipv6_prefix src;
                ipv4_prefix dst;
                src.len = ((struct sockaddr_in6 *)&from_prefix)->sin6_port;
                src.prefix = ((struct sockaddr_in6 *)&from_prefix)->sin6_addr;
                dst.len = ((struct sockaddr_in *)&to_prefix)->sin_port;
                dst.prefix = ((struct sockaddr_in *)&to_prefix)->sin_addr;
                if ((err = bpf_map_update_elem(nat64_6to4_fd, &src, &dst, BPF_ANY)) != 0) {
                    libbpf_strerror(err, errmsg, sizeof(errmsg));
                    fprintf(stderr, "Error adding 4to6 mapping: %s\n", errmsg);
                }
            } else {
                fprintf(stderr, "Cannot map between these families\n");
                usage(argv[0]);
                return 1;
            }
        } else if (strcmp(arg, "dynamic") == 0) {
            const char *prefix = pop_arg(argc, argv, &idx);
            if (!prefix) {
                fprintf(stderr, "dynamic needs an ipv4 prefix argument\n");
                usage(argv[0]);
                return 1;
            }
            struct sockaddr_storage parsed_prefix;
            if (!parse_prefix(prefix, &parsed_prefix) && parsed_prefix.ss_family != AF_INET) {
                fprintf(stderr, "Failed to parse dynamic ipv4 prefix: %s\n", prefix);
                usage(argv[0]);
                return 1;
            }
            struct sockaddr_in *ipv4_prefix = (struct sockaddr_in *)&parsed_prefix;
            if (ipv4_prefix->sin_port > 32) {
                fprintf(stderr, "dynamic prefix length incorrect: %s\n", prefix);
                usage(argv[0]);
                return 1;
            }
            switch(ipv4_prefix->sin_port) {
                case 32:
                case 31:
                    for(size_t i = 0; i <= (32U - ipv4_prefix->sin_port); ++i) {
                        add_dynamic(nat64_dyn4_fd, htons(ntohs(ipv4_prefix->sin_addr.s_addr) + i));
                    }
                    break;
                default:
                    /* Do not include the network and broadcast address */
                    for(size_t i = 1; i < (32 - (unsigned)ipv4_prefix->sin_port); ++i)
                        add_dynamic(nat64_dyn4_fd, htons(ntohs(ipv4_prefix->sin_addr.s_addr) + i));
                    break;
            }
        } else {
            fprintf(stderr, "Unexpected config option %s\n", arg);
            usage(argv[0]);
            return 1;
        }

        arg = pop_arg(argc, argv, &idx);
    };

    /* apply the config map */
    if ((bpf_map_update_elem(configmap_fd, &zero, &config, 0)) != 0) {
        fprintf(stderr,
                "ERR: Failed to update configmap: %s\n", strerror(errno));
        return false;
    }

    if (do_attach) {
        if (!xdpprog && prog)
            xdpprog = xdp_program__from_bpf_obj(prog, "xdp");

        if (!xdpprog) {
            printf("failed to create xdp program\n");
        } else if (!attach_program(ifindex, xdpprog)) {
            fprintf(stderr, "Failed to attach ebpf program\n");
            return 1;
        }
    }

    return 0;
}

