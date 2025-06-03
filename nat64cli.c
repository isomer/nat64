#include "nat64.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <xdp/libxdp.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <inttypes.h>

static const char *pin_path = "/proc/sys/fs/nat64";

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


static bool init_configmap(struct xdp_program *prog) {
    struct bpf_object *bpf = xdp_program__bpf_obj(prog);
    if (bpf_object__pin_maps(bpf, pin_path) != 0) {
        fprintf(stderr, "failed to pin maps\n");
    }

    struct bpf_map *map = bpf_object__find_map_by_name(bpf, "nat64_configmap");
    if (!map) {
        fprintf(stderr, "Failed to find config map\n");
        return false;
    }


    return true; /* Success! */
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

static bool load_program(const char *ifname, struct xdp_program **prog) {
    char errmsg[1024];
    int err = 0;

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);

    int ifindex;
    if ((ifindex = if_nametoindex(ifname)) == 0) {
        fprintf(stderr, "Unknown interface %s\n", ifname);
        return false;
    }

    struct bpf_object *bpf_obj = bpf_object__open_file("nat64.bpf.o", NULL);
    if (!bpf_obj) {
        fprintf(stderr, "failed to open bpf program: %s", strerror(errno));
        return false;
    }

    if ((err = bpf_object__load(bpf_obj)) != 0) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "warning: Load failed: %s\n", errmsg);
    }

    struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, ".data");
    if (!map) {
        fprintf(stderr, "Failed to find config map\n");
        return false;
    }

    printf("got configmap!\n");

    if ((err = bpf_object__pin(bpf_obj, pin_path)) != 0) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Pinning failed: %s\n", errmsg);
    }

    /* patch the configuration */
    int fd = bpf_map__fd(map);
    if (fd == -1) {
        fprintf(stderr, "Couldn't get map fd: %s\n", strerror(errno));
    }

    uint32_t key = 0;
    configmap_t configmap;

    configmap = (configmap_t) {
        .version = VERSION,
        .success_action = XDP_TX,
        .ignore_action = XDP_DROP,
        .v6_prefix = { 0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, 0x00},
        .magic_mac = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x64 },
        .ipv4_addr = { 192, 168, 4, 4 },
        .v6_prefixlen = 96/8,
    };

    if (!get_mac_address(ifname, configmap.gateway_mac)) {
        fprintf(stderr, "Failed to get mac address\n");
        return false;
    }

    if ((bpf_map_update_elem(fd, &key, &configmap, 0)) != 0) {
        fprintf(stderr,
                "ERR: Failed to update configmap: %s\n", strerror(errno));
        //return false;
    }

    printf("building program from bpf object\n");
    *prog = xdp_program__from_bpf_obj(bpf_obj, "xdp");

    if (!*prog) {
        printf("failed to create xdp program\n");
    }

    printf("starting attachment\n");
    if ((err = xdp_program__attach(*prog, ifindex, XDP_MODE_SKB, 0)) != 0) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: attaching program: %s\n", errmsg);
        return false;
    }

	return true;
}


int main(int argc, char *argv[]) {
    unsigned int ifindex = 0;
    struct xdp_program *prog = NULL;
    int mode = 0;
    const char *ifname = argv[1];

    if ((ifindex = if_nametoindex(ifname)) == 0) {
        fprintf(stderr, "Unknown interface %s\n", ifname);
        return false;
    }

    if (find_program_by_predicate(ifindex, predicate_by_name, "xdp_nat64", &prog, &mode)) {
        fprintf(stderr, "Cleaning up old ebpf program\n");
        /* Remove the old copy */
        xdp_program__detach(prog, ifindex, mode, 0);
        bpf_object__unpin(xdp_program__bpf_obj(prog), pin_path);
        prog = NULL;
    }

    printf("Beginning program load\n");

    if (!load_program(ifname, &prog)) {
        fprintf(stderr, "Failed to load ebpf program\n");
        return 1;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "nat64_counters");
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

