#include "test_bpf.h"
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

const size_t initial_offset = 128;

extern int xdp_nat64(__arg_ctx struct xdp_md *ctx);

struct test_case {
    const char *description;
    size_t input_len;
    uint8_t input[1024];
    size_t output_len;
    uint8_t output[1024];
} test_cases[] = {
    { "nat64 port-unreachable",
        78,
        {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x64,   /* Dst: 02:00:00:00:00:46 */
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00,   /* Src: 02:00:00:00:00:01 */
            0x08, 0x00,                           /* 0x0800: IPPROTO_IP */
            0x45, 0x00, 0x00, 0x38,               /* Version: 4  ihl: 5 (20), TOS: 0x00, Total Length: 64 */
            0x00, 0x00, 0x00, 0x00,               /* ID: 0x0000,  Flags: 000,  Offset: 0x0000 */
            0x76, 0x01, 0x70, 0x09,               /* TTL: 118, Protocol: 1 (ICMPv4), Checksum: 0x7009 */
            0x08, 0x08, 0x08, 0x08,               /* Src: 8.8.8.8 */
            0xc0, 0xa8, 0x04, 0x04,               /* Dst: 192.168.4.4 */
            0x03, 0x03, 0xc6, 0xf7,               /* Type: 3 (Unreachable) Code: 3 (Port unreachable), checksum: 0xc6f7 */
            0x00, 0x00, 0x00, 0x00,               /* Reserved: 0x0000 */
            0x45, 0x80, 0x00, 0x3c,               /* Version: 4  ihl: 5 (20), TOS: 0x80, Total Length: 60 */
            0x00, 0x00, 0x00, 0x00,               /* ID: 0x0000,  Flags: 000,  Offset: 0x0000 */
            0x04, 0x11, 0xe1, 0x75,               /* TTL: 4,  Protocol: 17 (UDP),  Checksum: 0xe175 */
            0xc0, 0xa8, 0x04, 0x04,               /* Src: 192.168.4.4 */
            0x08, 0x08, 0x08, 0x08,               /* Dst: 8.8.8.8 */
            0xb1, 0xd4, 0x82, 0xb5,               /* Src: 45524  Dst: 33461 */
            0x00, 0x28, 0x01, 0x53,               /* Length: 40  Checksum: 0x0153 */
        },
        118,
        {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00,   /* Dst: 02:00:00:00:00:01 */
            0x02, 0x00, 0x00, 0x00, 0x00, 0x64,   /* Src: 02:00:00:00:00:46 */
            0x86, 0xDD,                           /* Ethertype: 0x86DD (IPv6) */
            0x60, 0x00, 0x00, 0x00,
            0x00, 0x40, 0x3a, 0x76,
            0x00, 0x64, 0xff, 0x9b,               /* Src: 64:ff9b */
            0x00, 0x01, 0x00, 0x00,               /*       1:0    */
            0x00, 0x00, 0x00, 0x00,               /*       0:0    */
            0x08, 0x08, 0x08, 0x08,               /*      8.8.8.8 */
            0x00, 0x64, 0xff, 0x9b,               /* Dst: 64:ff9b */
            0x00, 0x01, 0x00, 0x00,               /*       1:0    */
            0x00, 0x00, 0x00, 0x00,               /*       0:0    */
            0xc0, 0xa8, 0x04, 0x04,               /*  192.168.4.4 */
            0x01, 0x04, 0xa5, 0xdc,               /* Type : 1 (Destination Unreachable)  Code: 4 (Port unreachable), Checksum: 0xa5dc */
            0x00, 0x00, 0x00, 0x00,               /* Reserved: 0x0000 */
            0x68, 0x00, 0x00, 0x00,               /* Version: 6 ... */
            0x00, 0x28, 0x11, 0x04,
            0x00, 0x64, 0xff, 0x9b,               /* Src: 64:ff9b */
            0x00, 0x01, 0x00, 0x00,               /*       1:0    */
            0x00, 0x00, 0x00, 0x00,               /*       0:0    */
            0xc0, 0xa8, 0x04, 0x04,               /*  192.168.4.4 */
            0x00, 0x64, 0xff, 0x9b,               /* Dst: 64:ff9b */
            0x00, 0x01, 0x00, 0x00,               /*       1:0    */
            0x00, 0x00, 0x00, 0x00,               /*       0:0    */
            0x08, 0x08, 0x08, 0x08,               /*      8.8.8.8 */
            0xb1, 0xd4, 0x82, 0xb5,               /* Src: 45524  Dst: 33461 */
            0x00, 0x28, 0x01, 0x51,               /* Length: 40  Checksum: 0x0151 */
        }
    }
};

bool perform_test(const struct test_case *test) {
    char buffer[2048];
    memcpy(&buffer[initial_offset], test->input, test->input_len);
    assert(initial_offset + test->input_len < sizeof(buffer));
    struct xdp_md ctx = {
        .data = (uintptr_t) &buffer[initial_offset],
        .data_end = (uintptr_t) &buffer[initial_offset + test->input_len],
        .data_meta = (uintptr_t) NULL,
        .ingress_ifindex = 1,
        .rx_queue_index = 1,
    };

    if (xdp_nat64(&ctx) != XDP_TX) {
        printf("not XDP_TX\n");
        return false;
    }

    if (ctx.data < (uintptr_t)buffer || ctx.data_end >= (uintptr_t)&buffer[sizeof(buffer)]) {
        printf("returned packet outside of buffer\n");
        return false;
    }

    if (ctx.data_end - ctx.data != test->output_len) {
        printf("Wrong length (%" PRIdPTR " vs %" PRIdPTR ") \n",
                ctx.data_end - ctx.data,
                test->output_len
                );
        return false;
    }

    if (memcmp((void *)ctx.data, test->output, test->output_len) != 0) {
        uint8_t *data = (void*)ctx.data;
        size_t i;
        for (i = 0; i < test->output_len; i+= 4) {
            printf("%02x%02x%s%02x%02x%s    %02x%02x %02x%02x\n",
                    data[i], data[i+1],
                    data[i] == test->output[i] && data[i+1] == test->output[i+1] ? " " : "*",
                    data[i+2], data[i+3],
                    data[i+2] == test->output[i+2] && data[i+3] == test->output[i+3] ? " " : "*",
                    test->output[i], test->output[i+1], test->output[i+2], test->output[i+3]);
        }
        printf("%zd\n", test->output_len - i);
        return false;
    }
    else
        return true;
}

int main(int argc, char *argv[]) {
    size_t count = sizeof(test_cases) / sizeof(test_cases[0]);
    for(size_t i = 0; i < count; ++i) {
        printf("%zi: %s - %s\n",
                i+1,
                perform_test(&test_cases[i]) ? "pass" : "fail",
                test_cases[i].description);
    }
}
