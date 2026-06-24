// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Drives nft_handler_cleanup_orphan directly, the way the parent does when a
 * sandboxed setup child is SIGSYS-killed: it has the per-session names but
 * not the jump-rule handle. Linked against the production objects because the
 * function is not exported from the .so. Built and run by
 * tests/orphan_cleanup_test.sh.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "authnft.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <chain> <set_v4> <set_v6> <set_cg>\n", argv[0]);
        return 2;
    }
    authnft_session_t sd;
    memset(&sd, 0, sizeof(sd));
    snprintf(sd.chain_name, sizeof(sd.chain_name), "%s", argv[1]);
    snprintf(sd.set_v4, sizeof(sd.set_v4), "%s", argv[2]);
    snprintf(sd.set_v6, sizeof(sd.set_v6), "%s", argv[3]);
    snprintf(sd.set_cg, sizeof(sd.set_cg), "%s", argv[4]);
    sd.jump_handle = 0;  /* a SIGSYS-killed child never reported the handle */

    int rc = nft_handler_cleanup_orphan(NULL, "orphantest", &sd);
    printf("orphan cleanup rc=%d\n", rc);
    return rc == PAM_SUCCESS ? 0 : 1;
}
