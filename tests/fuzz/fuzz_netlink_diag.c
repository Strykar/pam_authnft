// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Fuzzer for peer_parse_diag_chunk: the NETLINK_SOCK_DIAG response
 * walker inside peer_lookup_tcp. This is the only path in pam_authnft
 * where attacker-influenced kernel bytes flow into a hand-rolled
 * length-arithmetic / pointer-cast / NLMSG_OK walk — by far the
 * highest attacker-reachable parsing surface in the module.
 *
 * The function:
 *   - walks netlink messages via NLMSG_OK / NLMSG_NEXT
 *   - rejects payloads shorter than sizeof(inet_diag_msg)
 *   - matches inode against a caller-supplied set
 *   - extracts dst IPv4 / IPv6 with inet_ntop
 *   - holds back loopback matches in `pending` for fallback
 *
 * The harness derives the inode set from a slice of the fuzz input so
 * the matcher can fire on at least some inputs — if the inode list were
 * fixed, the OWNED branch would never be entered.
 *
 * Property assertions:
 *   - return value must be in {-1, 0, 1, 2}
 *   - on rc==1, `out` is NUL-terminated within out_sz
 *   - the parser must not read past `buf + len` (caught by ASan)
 */

#include "authnft.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int peer_parse_diag_chunk(const void *buf, size_t len,
                          const ino_t *inodes, int n_inodes,
                          char *out, size_t out_sz,
                          char *pending, size_t pending_sz,
                          const uint16_t *listen_ports, int n_listen);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8)
        return 0;

    /* Use the first 8 bytes to seed the inode set. Up to 8 inodes;
     * each is one byte from data[0..7] plus a fixed offset to avoid
     * inode 0 (reserved). The matcher fires when the netlink message
     * carries an idiag_inode equal to any value in this set. */
    ino_t inodes[8];
    int n_inodes = (size < 16) ? 4 : 8;
    for (int i = 0; i < n_inodes; i++)
        inodes[i] = (ino_t)data[i] + 1;

    /* Remaining bytes are the synthetic netlink response. */
    const uint8_t *buf = data + 8;
    size_t len = size - 8;

    /* Vary out_sz / pending_sz via two bytes of the inode-region so the
     * "buffer too small" branches inside peer_parse_diag_chunk get
     * exercised. The first byte selects out_sz, second selects
     * pending_sz, both biased toward small values. */
    static const size_t sizes[] = {1, 4, 8, 16, IP_STR_MAX};
    size_t out_sz = sizes[data[0] % (sizeof(sizes) / sizeof(sizes[0]))];
    size_t pending_sz = sizes[data[1] % (sizeof(sizes) / sizeof(sizes[0]))];

    char out[IP_STR_MAX] = {0};
    char pending[IP_STR_MAX] = {0};

    /* Derive a listen-port set from two input bytes so both the disabled
     * path (n_listen == 0) and the port-filter branch get exercised. The
     * filter only narrows which sockets qualify; it cannot change the
     * bounds or output-format invariants asserted below. */
    uint16_t listen_ports[4];
    int n_listen = data[2] % 5;      /* 0..4 */
    for (int i = 0; i < n_listen; i++)
        listen_ports[i] = (uint16_t)((data[(3 + i) % 8] << 8) | data[(4 + i) % 8]);

    int rc = peer_parse_diag_chunk(buf, len, inodes, n_inodes,
                                    out, out_sz,
                                    pending, pending_sz,
                                    n_listen ? listen_ports : NULL, n_listen);

    /* Property assertion: return code is one of the documented values. */
    if (rc != -1 && rc != 0 && rc != 1 && rc != 2)
        __builtin_trap();

    /* Property assertion: on success, out is NUL-terminated and the
     * stored string parses as a valid IP literal. We don't re-validate
     * via inet_pton (would re-do the work the function already did);
     * we just verify NUL-termination within bounds and printable
     * characters. */
    if (rc == 1) {
        size_t outlen = strnlen(out, out_sz);
        if (outlen >= out_sz)
            __builtin_trap();
        for (size_t i = 0; i < outlen; i++) {
            unsigned char c = (unsigned char)out[i];
            if (c < 0x20 || c > 0x7e)
                __builtin_trap();
        }
    }

    return 0;
}
