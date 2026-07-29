// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar
//
// Fault driver for the local audit harness. Links the production objects
// (built with -fsanitize=address,undefined) and drives nft_handler_setup's
// error returns directly, so a heap leak or use-after-free on any of them
// is caught by LeakSanitizer at exit instead of slipping through because
// the path was never executed by the happy-path integration tests.
//
// This is the piece the existing CI lacked: the integration suite drives
// nft_handler_setup for real via pamtester, but never under a leak
// detector, and never down the pre-substitution error returns. CID 1659576
// (frag_buf leak) lived in exactly that gap.
//
// Runs as root inside the rootful audit container, after run-audit.sh has
// created the authnft group, the test user, the fragment, and the
// /etc/pam.d/authnft_audit stub that pam_start needs.
//
// Scenarios (argv[1]):
//   happy     valid session -> setup succeeds -> cleanup. Leak-free baseline.
//   truncate  every session field maxed -> snprintf(cmd) may truncate
//             (nft_handler.c return PAM_BUF_ERR). Also answers whether that
//             path is reachable given the struct field caps, or defensive
//             only. Leak-free either way.
//   nftfail   pre-create a conflicting per-session chain so call 1 fails
//             (the EEXIST class). Drives the call-1-failure return.
//             Leak-free.
//
// A non-zero process exit comes only from LSan/UBSan (configured by the
// harness via ASAN_OPTIONS/UBSAN_OPTIONS exitcode), never from the driver
// itself — the driver prints the return code and exits 0 so the detector
// owns the verdict.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "authnft.h"

#include <nftables/libnftables.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Conversation that discards all module-emitted messages. pam_error()
 * on the failure paths calls this; it must allocate the response array
 * PAM expects and return cleanly. */
static int discard_conv(int num_msg, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata)
{
    (void)msg;
    (void)appdata;
    if (num_msg <= 0) {
        *resp = NULL;
        return PAM_SUCCESS;
    }
    struct pam_response *r = calloc((size_t)num_msg, sizeof(*r));
    if (!r)
        return PAM_BUF_ERR;
    *resp = r; /* info/error messages need no reply; .resp stays NULL */
    return PAM_SUCCESS;
}

static void fill_max(char *dst, size_t cap, char c)
{
    memset(dst, c, cap - 1);
    dst[cap - 1] = '\0';
}

static void baseline_session(authnft_session_t *sd)
{
    memset(sd, 0, sizeof(*sd));
    /* nft_handler_setup requires an id already allocated: the real caller
     * does it in the setup child before seccomp goes on, because the
     * counter needs syscalls the allowlist does not carry. This driver
     * calls setup directly and unsandboxed, so it allocates here. A
     * hardcoded value would do for the fault paths, but going through the
     * allocator keeps the driver exercising the same contract. */
    sd->session_mark = session_mark_alloc(NULL);
    snprintf(sd->cg_path, sizeof(sd->cg_path),
             "authnft.slice/authnft-audit.scope");
    snprintf(sd->chain_name, sizeof(sd->chain_name), "session_audit_1");
    snprintf(sd->set_v4, sizeof(sd->set_v4), "session_audit_1_v4");
    snprintf(sd->set_v6, sizeof(sd->set_v6), "session_audit_1_v6");
    snprintf(sd->set_cg, sizeof(sd->set_cg), "session_audit_1_cg");
    snprintf(sd->remote_ip, sizeof(sd->remote_ip), "127.0.0.1");
    sd->claims_tag[0] = '\0';
}

/* Pre-create the per-session chain as a base chain (with a hook) so the
 * session's regular `add chain` of the same name conflicts and call 1
 * fails. Returns the libnftables rc (0 = the conflict state was created). */
static int precreate_conflict(const char *chain)
{
    struct nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx)
        return -1;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "add table inet " TABLE_NAME "\n"
             "add chain inet " TABLE_NAME
             " %s { type filter hook input priority 0; }",
             chain);
    int rc = nft_run_cmd_from_buffer(ctx, cmd);
    nft_ctx_free(ctx);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <happy|truncate|nftfail> <user>\n",
                argv[0]);
        return 2;
    }
    const char *scen = argv[1];
    const char *user = argv[2];

    pam_handle_t *pamh = NULL;
    struct pam_conv conv = {discard_conv, NULL};
    int pr = pam_start("authnft_audit", user, &conv, &pamh);
    if (pr != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed: %d\n", pr);
        return 3;
    }

    authnft_session_t sd;
    baseline_session(&sd);
    int rc = -999;
    int verdict = 0;   /* non-zero => a return-code assertion failed */

    if (strcmp(scen, "happy") == 0) {
        /* The call2fail and handleparse cells reuse this scenario with the nft
         * interposer preloaded (nft_fail.so), which forces call 2 / the handle
         * parse to fail. So the expected return flips with the interposer: no
         * interposer => PAM_SUCCESS, interposer => a failure return. Asserting
         * both directions means every cell now proves it still drives the
         * return it exists to drive, instead of printing an unread line. */
        const int forced_fail = getenv("AUTHNFT_NFT_FAIL_ON") != NULL ||
                                getenv("AUTHNFT_NFT_CORRUPT_HANDLE") != NULL;
        rc = nft_handler_setup(pamh, user, getpid(), &sd, NULL);
        printf("[happy] setup rc=%d (PAM_SUCCESS=%d, interposer=%d)\n",
               rc, PAM_SUCCESS, forced_fail);
        if (!forced_fail && rc != PAM_SUCCESS) {
            fprintf(stderr, "[happy] FAIL: expected PAM_SUCCESS (%d)\n",
                    PAM_SUCCESS);
            verdict = 1;
        } else if (forced_fail && rc == PAM_SUCCESS) {
            fprintf(stderr, "[happy] FAIL: the nft interposer was active but "
                    "setup succeeded; this cell is not driving its failure "
                    "return any more\n");
            verdict = 1;
        }
        if (rc == PAM_SUCCESS)
            nft_handler_cleanup(pamh, user, &sd);
    } else if (strcmp(scen, "selfheal") == 0) {
        /* PID recycle onto a leaked session's names: a previous session for
         * this (user, pid) died without close_session, so its per-session
         * chain and sets are still in the kernel (only the element carries a
         * timeout). Call 1 then collides, and the self-heal must reap the
         * stale state and retry — otherwise the user is fail-closed out of
         * their own session until an admin intervenes.
         *
         * The collision is forced by the interposer (AUTHNFT_NFT_FAIL_ONCE),
         * which fails call 1 once with an "exists" error. It cannot be staged
         * by simply running setup twice: `add table`/`add chain`/`add set` are
         * idempotent in libnftables, so the second setup just succeeds and the
         * cell would pass even with the self-heal deleted — a test that proves
         * nothing. Negative control: remove the strstr("exists") branch in
         * nft_handler.c and this cell fails. */
        rc = nft_handler_setup(pamh, user, getpid(), &sd, NULL);
        printf("[selfheal] setup-over-stale rc=%d (PAM_SUCCESS=%d)\n",
               rc, PAM_SUCCESS);
        if (rc != PAM_SUCCESS) {
            fprintf(stderr, "[selfheal] FAIL: call 1 hit stale state and the "
                    "self-heal did not recover it; a recycled PID would "
                    "self-lock the user out\n");
            verdict = 1;
        }
        if (rc == PAM_SUCCESS)
            nft_handler_cleanup(pamh, user, &sd);
    } else if (strcmp(scen, "truncate") == 0) {
        fill_max(sd.cg_path, sizeof(sd.cg_path), 'A');
        fill_max(sd.chain_name, sizeof(sd.chain_name), 'B');
        fill_max(sd.set_v4, sizeof(sd.set_v4), 'C');
        fill_max(sd.set_v6, sizeof(sd.set_v6), 'D');
        fill_max(sd.set_cg, sizeof(sd.set_cg), 'E');
        fill_max(sd.claims_tag, sizeof(sd.claims_tag), 'F');
        rc = nft_handler_setup(pamh, user, getpid(), &sd, NULL);
        printf("[truncate] setup rc=%d  PAM_BUF_ERR=%d  "
               "truncation-path-reachable=%s\n",
               rc, PAM_BUF_ERR, rc == PAM_BUF_ERR ? "YES" : "no");
        if (rc == PAM_SUCCESS)
            nft_handler_cleanup(pamh, user, &sd);
    } else if (strcmp(scen, "nftfail") == 0) {
        /* Pre-create a *base* chain under the per-session name. Call 1 fails
         * with "already exists", which trips the self-heal; the reap deletes
         * the chain by name and the retry then hits the second collision the
         * base chain's hook leaves behind, so setup still fails. The point of
         * this cell is the call-1-failure return and its frag_buf free, so
         * assert it: if a change ever makes this path succeed, the scenario is
         * silently no longer driving the return it claims to
         * (the `selfheal` cell covers the recoverable case). */
        int crc = precreate_conflict(sd.chain_name);
        if (crc != 0)
            fprintf(stderr,
                    "[nftfail] note: conflict pre-create rc=%d "
                    "(call 1 may not fail as intended)\n",
                    crc);
        rc = nft_handler_setup(pamh, user, getpid(), &sd, NULL);
        printf("[nftfail] setup rc=%d (expect non-SUCCESS)\n", rc);
        if (rc == PAM_SUCCESS) {
            fprintf(stderr, "[nftfail] FAIL: setup succeeded; this cell no "
                    "longer drives the call-1-failure return\n");
            verdict = 1;
            nft_handler_cleanup(pamh, user, &sd);
        }
    } else {
        fprintf(stderr, "unknown scenario: %s\n", scen);
        pam_end(pamh, PAM_SUCCESS);
        return 2;
    }

    pam_end(pamh, PAM_SUCCESS);
    /* The leak/UB verdict is owned by the sanitizer's atexit check (exitcode
     * set via ASAN_OPTIONS/UBSAN_OPTIONS by the harness), which overrides this
     * on a leak. `verdict` adds the return-code verdict on top: a scenario
     * that no longer produces the nft_handler_setup return it exists to drive
     * now fails the audit instead of printing an unread line. */
    return verdict;
}
