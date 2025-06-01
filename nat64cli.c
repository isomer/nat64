#include "nat64.h"
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <inttypes.h>

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
    if (bpf_object__pin_maps(bpf, "/sys/fs/bpf/nat64") != 0) {
        fprintf(stderr, "failed to pin maps\n");
    }

    struct bpf_map *map = bpf_object__find_map_by_name(bpf, "nat64_configmap");
    if (!map) {
        fprintf(stderr, "Failed to find config map\n");
        return false;
    }

    int fd = bpf_map__fd(map);

    uint32_t key = 0;
    configmap_t configmap;
    if ((bpf_map_lookup_elem(fd, &key, &configmap)) != 0) {
        fprintf(stderr,
                "ERR: bpf_map_lookup_elem failed to find configmap entry");
        return false;
    }

    if (configmap.version != 0 && configmap.version != VERSION) {
        fprintf(stderr,
                "WARN: configmap has an unknown version\n");
    }

    configmap = (configmap_t) {
        .version = VERSION,
        .success_action = XDP_TX,
        .ignore_action = XDP_DROP,
        .v6_prefix = { },
        .magic_mac = { },
        .gateway_mac = { },
        .ipv4_addr = { 192, 168, 4, 4 },
    };

    if ((bpf_map_update_elem(fd, &key, &configmap, 0)) != 0) {
        fprintf(stderr,
                "ERR: Failed to update configmap\n");
        return false;
    }

    return true; /* Success! */
}

static bool load_program(int ifindex, struct xdp_program **prog) {
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

    xdp_opts.open_filename = "nat64.bpf.o";
	xdp_opts.prog_name = "xdp_nat64";
	xdp_opts.opts = &opts;

    *prog = xdp_program__create(&xdp_opts);

    int err = libxdp_get_error(*prog);
	if (err) {
		char errmsg[1024];
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: creating program: %s\n", errmsg);
        return false;
	}

    init_configmap(*prog);

    if ((err = xdp_program__attach(*prog, ifindex, XDP_MODE_SKB, 0)) != 0) {
		char errmsg[1024];
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

    if ((ifindex = if_nametoindex(argv[1])) == 0) {
        fprintf(stderr, "Unknown interface %s\n", argv[1]);
        return 1;
    }

    if (find_program_by_predicate(ifindex, predicate_by_name, "xdp_nat64", &prog, &mode)) {
        fprintf(stderr, "Cleaning up old ebpf program\n");
        /* Remove the old copy */
        xdp_program__detach(prog, ifindex, mode, 0);
        prog = NULL;
    }


    if (!load_program(ifindex, &prog)) {
        fprintf(stderr, "Failed to load ebpf program\n");
        return 1;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "nat64_counters");
    if (!map) {
        fprintf(stderr, "Failed to find config map\n");
        return false;
    }

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

    return 0;
}

