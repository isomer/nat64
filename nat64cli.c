//#include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>
#include <xdp/libxdp.h>

#include "nat64.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *pin_path = "/proc/sys/fs/nat64/";

typedef struct map_t {
    ipv4_prefix v4;
    ipv6_prefix v6;
    enum {
        MAP_4TO6,
        MAP_6TO4,
        MAP_BOTH,
    } map;
    struct map_t *next;
} map_t;

static map_t *addr_map = NULL;

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
        printf("Prog=%p", *prog);
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

static bool load_program(const char *ifname, struct bpf_object **prog) {
    char errmsg[1024];
    int err = 0;

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);

    int ifindex;
    if ((ifindex = if_nametoindex(ifname)) == 0) {
        fprintf(stderr, "Unknown interface %s\n", ifname);
        return false;
    }

    *prog = bpf_object__open_file("nat64.bpf.o", NULL);
    if (!prog) {
        fprintf(stderr, "failed to open bpf program: %s", strerror(errno));
        return false;
    }

    if ((err = bpf_object__load(*prog)) != 0) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "warning: Load failed: %s\n", errmsg);
    }

    struct bpf_map *map = bpf_object__find_map_by_name(*prog, ".data");
    if (!map) {
        fprintf(stderr, "Failed to find config map\n");
        return false;
    }

    printf("got configmap!\n");

    if ((err = bpf_object__pin(*prog, pin_path)) != 0) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Pinning failed: %s\n", errmsg);
    }

    /* patch the configuration */
    int fd = bpf_map__fd(map);
    if (fd == -1) {
        fprintf(stderr, "Couldn't get map fd: %s\n", strerror(errno));
        return false;
    }

    uint32_t key = 0;
    configmap_t configmap;

    configmap = (configmap_t) {
        .version = VERSION,
        .success_action = XDP_TX,
        .ignore_action = XDP_DROP,
        .dst_mac_mode = DST_MAC_REFLECT,
        .magic_mac = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x64 },
    };

    if (!get_mac_address(ifname, configmap.gateway_mac)) {
        fprintf(stderr, "Failed to get mac address\n");
        return false;
    }

    if ((bpf_map_update_elem(fd, &key, &configmap, 0)) != 0) {
        fprintf(stderr,
                "ERR: Failed to update configmap: %s\n", strerror(errno));
        return false;
    }

    /* Set up the address maps */
    struct bpf_map *nat64_6to4 = bpf_object__find_map_by_name(*prog, "nat64_6to4");
    if (!nat64_6to4) {
        fprintf(stderr, "Couldn't find nat64_6to4 map\n");
        return false;
    }

    int nat64_6to4_fd = -1;
    if ((nat64_6to4_fd = bpf_map__fd(nat64_6to4)) == -1) {
        fprintf(stderr, "Failed to get nat64_6to4 fd\n");
        return false;
    }

    struct bpf_map *nat64_4to6 = bpf_object__find_map_by_name(*prog, "nat64_4to6");
    if (!nat64_4to6) {
        fprintf(stderr, "Couldn't find nat64_4to6 map\n");
        return false;
    }

    int nat64_4to6_fd = -1;
    if ((nat64_4to6_fd = bpf_map__fd(nat64_4to6)) == -1) {
        fprintf(stderr, "Failed to get nat64_4to6 fd\n");
        return false;
    }

    ipv6_prefix v6 = {
        .len = 96,
        .prefix.s6_addr = {
            0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
    };

    ipv4_prefix v4 = {
        .len = 0,
        .prefix.s_addr = htonl(0),
    };

    /* map 0.0.0.0/0 <=> 64:ff9b::/96 */
    if ((err = bpf_map_update_elem(nat64_6to4_fd, &v6, &v4, BPF_ANY)) != 0) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Error adding 6to4 mapping: %s\n", errmsg);
    }

    if ((err = bpf_map_update_elem(nat64_4to6_fd, &v4, &v6, BPF_ANY)) != 0) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Error adding 4to6 mapping: %s\n", errmsg);
    }

    /* map ::/0 to 100.64.0.1 */
    v4 = (ipv4_prefix) {
        .len = 32,
        .prefix.s_addr = inet_addr("100.64.0.1"),
    };
    v6 = (ipv6_prefix) {
        .len = 0,
        .prefix.s6_addr16 = { 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    if ((err = bpf_map_update_elem(nat64_6to4_fd, &v6, &v4, BPF_ANY)) != 0) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Error adding default 6to4 mapping: %s\n", errmsg);
    }

    ipv6_prefix test_prefix = {
        .len = 128,
        .prefix = {
            .s6_addr = {
                0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x01, 0x01
            }
        }
    };
    struct ipv4_prefix result;
    int ret = bpf_map_lookup_elem(nat64_6to4_fd, &test_prefix, &result);
    libbpf_strerror(ret, errmsg, sizeof(errmsg));
    fprintf(stderr, "self test status: %s\n", errmsg);
    fprintf(stderr, "result: %s/%d\n", inet_ntoa(result.prefix), result.len);

	return true;
}

static bool attach_program(const char *ifname, struct bpf_object *bpf_prog) {
    char errmsg[1024];
    int err = 0;
    int ifindex = -1;

    if ((ifindex = if_nametoindex(ifname)) == 0) {
        fprintf(stderr, "Unknown interface %s\n", ifname);
        return false;
    }

    printf("building program from bpf object\n");
    struct xdp_program *prog = xdp_program__from_bpf_obj(bpf_prog, "xdp");

    if (!prog) {
        printf("failed to create xdp program\n");
    }

    printf("starting attachment\n");
    if ((err = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0)) != 0) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: attaching program: %s\n", errmsg);
        return false;
    }

	return true;
}


int main(int argc, char *argv[]) {
    unsigned int ifindex = 0;
    struct bpf_object *prog = NULL;
    struct xdp_program *xdpprog = NULL;
    int mode = 0;
    const char *ifname = argv[1];

    if ((ifindex = if_nametoindex(ifname)) == 0) {
        fprintf(stderr, "Unknown interface %s\n", ifname);
        return false;
    }

    if (find_program_by_predicate(ifindex, predicate_by_name, "xdp_nat64", &xdpprog, &mode)) {
        fprintf(stderr, "Cleaning up old ebpf program\n");
        /* Remove the old copy */
        xdp_program__detach(xdpprog, ifindex, mode, 0);
        bpf_object__unpin(xdp_program__bpf_obj(xdpprog), pin_path);
        prog = NULL;
    }

    printf("Beginning program load\n");

    if (!load_program(ifname, &prog)) {
        fprintf(stderr, "Failed to load ebpf program\n");
        return 1;
    }

    if (!attach_program(ifname, prog)) {
        fprintf(stderr, "Failed to load ebpf program\n");
        return 1;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(prog, "nat64_counters");
    if (!map) {
        fprintf(stderr, "Failed to find config map\n");
        return false;
    }

#if 0
    size_t num_cpu = libbpf_num_possible_cpus();
    int fd = bpf_map__fd(map);
    for(;;) {

        uint64_t counter[num_cpu];
        for(uint32_t key = 0; key < 10; ++key) {

            if ((bpf_map_lookup_elem(fd, &key, counter)) != 0) {
                fprintf(stderr,
                        "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
                return 1;
            }

            uint64_t total = 0;
            for(size_t i = 0; i < num_cpu; ++i) {
                total += counter[i];
            }

            printf("%"PRIu64" ", total);
        }
        printf("\n");

        sleep(2);
    }
#endif

    return 0;
}

