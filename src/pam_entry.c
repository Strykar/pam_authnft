// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include "util_validators.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

static void free_pam_data(pam_handle_t *pamh, void *data, int error_status) {
    (void)pamh; (void)error_status;
    free(data);
}

static int is_debug_bypass_requested(int argc, const char **argv) {
    if (getenv("AUTHNFT_NO_SANDBOX")) return 1;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "AUTHNFT_NO_SANDBOX=1") == 0)
            return 1;
    }
    return 0;
}

/* util_is_valid_username and util_normalize_ip live in
 * src/util_validators.c; declarations in util_validators.h. The
 * extraction is the precondition for unit + mutation testing of
 * the pure decision surfaces. See docs/MUTATION_ASAN_EXPERIMENT.md. */

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *user = NULL;
    const char *rhost = NULL;
    char norm_ip[IP_STR_MAX] = {0};
    int session_pid = getpid();

    (void)flags;

    if (pam_get_item(pamh, PAM_USER, (const void **)&user) != PAM_SUCCESS ||
        !user || !util_is_valid_username(user))
        return PAM_SESSION_ERR;

    if (strcmp(user, "root") == 0) {
        DEBUG_PRINT("PAM: root user, skipping");
        return PAM_SUCCESS;
    }

    DEBUG_PRINT("PAM: open_session for user=%s pid=%d", user, session_pid);

    /*
     * PAM_RHOST handling. sshd with `UseDNS yes` writes a hostname here,
     * not an IP; historically that tripped inet_pton and denied login.
     * Policies:
     *   lax (default) — normalize if possible, else cg-only fallback.
     *   strict        — deny on any non-IP PAM_RHOST.
     *   kernel        — prefer the sock_diag-derived peer over PAM_RHOST;
     *                   log a warning on divergence; fall back to lax
     *                   semantics if the kernel lookup fails.
     */
    int strict_rhost = 0, kernel_rhost = 0;
    const char *claims_env = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "rhost_policy=strict") == 0) strict_rhost = 1;
        else if (strcmp(argv[i], "rhost_policy=kernel") == 0) kernel_rhost = 1;
        else if (strncmp(argv[i], "claims_env=", 11) == 0) claims_env = argv[i] + 11;
    }

    int rhost_parsed = 0;
    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS && rhost) {
        rhost_parsed = util_normalize_ip(rhost, norm_ip, sizeof(norm_ip));
    }

    if (kernel_rhost) {
        char kern_ip[IP_STR_MAX] = {0};
        if (peer_lookup_tcp(pamh, session_pid, kern_ip, sizeof(kern_ip))) {
            /* Normalize kernel peer (v4-mapped v6 → plain v4) so the
             * divergence comparison and set selection use the same form
             * as the PAM_RHOST path. */
            char tmp_ip[IP_STR_MAX];
            if (util_normalize_ip(kern_ip, tmp_ip, sizeof(tmp_ip)))
                memcpy(kern_ip, tmp_ip, sizeof(kern_ip));
            if (rhost_parsed && strcmp(kern_ip, norm_ip) != 0) {
                pam_syslog(pamh, LOG_WARNING,
                           "authnft: PAM_RHOST/kernel peer divergence: "
                           "app='%s' kernel='%s' — trusting kernel",
                           norm_ip, kern_ip);
            } else if (!rhost_parsed && rhost) {
                pam_syslog(pamh, LOG_WARNING,
                           "authnft: PAM_RHOST '%s' unparseable, "
                           "using kernel-derived peer %s",
                           rhost, kern_ip);
            }
            memcpy(norm_ip, kern_ip, sizeof(norm_ip));
            rhost_parsed = 1;
        } else {
            pam_syslog(pamh, LOG_INFO,
                       "authnft: kernel peer lookup failed for pid %d, "
                       "falling back to PAM_RHOST", session_pid);
            /* rhost_parsed retains whatever util_normalize_ip returned */
        }
    }

    if (!rhost_parsed) {
        if (rhost) {
            DEBUG_PRINT("PAM: unparseable PAM_RHOST: %s", rhost);
            if (strict_rhost) {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: PAM_RHOST '%s' not an IP literal (strict policy)",
                           rhost);
                return PAM_SESSION_ERR;
            }
            pam_syslog(pamh, LOG_INFO,
                       "authnft: PAM_RHOST '%s' not an IP literal, binding cgroup only",
                       rhost);
        } else {
            DEBUG_PRINT("PAM: PAM_RHOST not set");
            if (strict_rhost) return PAM_SESSION_ERR;
        }
        norm_ip[0] = '\0';
    }

    if (is_debug_bypass_requested(argc, argv)) {
        pam_syslog(pamh, LOG_DEBUG, "authnft: seccomp bypassed");
    } else {
        if (sandbox_apply(pamh) < 0) {
            pam_syslog(pamh, LOG_ERR, "authnft: failed to apply sandbox");
            return PAM_SESSION_ERR;
        }
    }

    if (bus_handler_start(pamh, user, session_pid) < 0)
        return PAM_SESSION_ERR;

    /*
     * Construct cg_path deterministically from the scope we just created
     * rather than reading /proc/<pid>/cgroup. The path is guaranteed by
     * the Slice=authnft.slice parameter in StartTransientUnit; reading
     * /proc would race with the cgroup migration (the kernel updates
     * /proc/<pid>/cgroup asynchronously after the D-Bus call returns).
     *
     * Persist cg_path + scope_unit + the normalized IP that was actually
     * bound. The stored remote_ip (empty string for the cg-only path)
     * tells close_session which set to delete from. cg_path is what the
     * kernel resolves to the u64 inode at nft insert time via
     * `socket cgroupv2 level 2`; scope_unit is the filename key for
     * session JSON files. Both fields are fixed-size inside the struct
     * so free_pam_data remains a plain free(data). Key name
     * 'authnft_cg_id' predates this struct (invariant #3); kept for
     * lifecycle compatibility.
     */
    authnft_session_t *sd = calloc(1, sizeof(*sd));
    if (!sd) {
        pam_syslog(pamh, LOG_ERR, "authnft: out of memory storing session data");
        /* bus_handler_start created the scope unit above; roll it back
         * so a failed open_session leaves no orphan in systemd state. */
        (void)bus_handler_stop(pamh, user, session_pid);
        return PAM_SESSION_ERR;
    }
    snprintf(sd->scope_unit, sizeof(sd->scope_unit), "authnft-%s-%d.scope",
             user, session_pid);
    snprintf(sd->cg_path, sizeof(sd->cg_path), "authnft.slice/%s",
             sd->scope_unit);
    /* Build per-session nft names. Usernames may contain '-' and '.'
     * which are not valid in nftables identifiers (hyphen is parsed as
     * subtraction). Replace with '_'. */
    char safe_user[MAX_USER_LEN + 1];
    snprintf(safe_user, sizeof(safe_user), "%s", user);
    for (char *p = safe_user; *p; p++) {
        if (*p == '-' || *p == '.') *p = '_';
    }
    snprintf(sd->chain_name, sizeof(sd->chain_name), "session_%s_%d",
             safe_user, session_pid);
    snprintf(sd->set_v4, sizeof(sd->set_v4), "session_%s_%d_v4",
             safe_user, session_pid);
    snprintf(sd->set_v6, sizeof(sd->set_v6), "session_%s_%d_v6",
             safe_user, session_pid);
    snprintf(sd->set_cg, sizeof(sd->set_cg), "session_%s_%d_cg",
             safe_user, session_pid);
    memcpy(sd->remote_ip, norm_ip, sizeof(sd->remote_ip));
    if (claims_env) {
        (void)keyring_fetch_tag(pamh, claims_env, sd->claims_tag,
                                sizeof(sd->claims_tag));
    }
    event_correlation_capture(pamh, sd->correlation_id,
                              sizeof(sd->correlation_id));
    if (pam_set_data(pamh, "authnft_cg_id", sd, free_pam_data) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "authnft: failed to store session data");
        free(sd);
        (void)bus_handler_stop(pamh, user, session_pid);
        return PAM_SESSION_ERR;
    }

    int rc = nft_handler_setup(pamh, user, sd);
    if (rc == PAM_SUCCESS) {
        (void)session_file_write(pamh, sd, user, session_pid);
        event_open_emit(pamh, sd, user, session_pid);
    } else {
        /* nft_handler_setup rolled back its own partial nft state.
         * The systemd scope created by bus_handler_start above is
         * still live — roll it back too. `sd` stays registered with
         * PAM and is freed by free_pam_data when the handle ends. */
        (void)bus_handler_stop(pamh, user, session_pid);
    }
    return rc;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv) {
    const char *user = NULL;
    (void)flags; (void)argc; (void)argv;

    if (pam_get_item(pamh, PAM_USER, (const void **)&user) != PAM_SUCCESS || !user)
        return PAM_SUCCESS;

    if (strcmp(user, "root") == 0)
        return PAM_SUCCESS;

    const authnft_session_t *sd = NULL;
    if (pam_get_data(pamh, "authnft_cg_id",
                     (const void **)&sd) != PAM_SUCCESS || !sd) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: no stored session data for %s — element may persist",
                   user);
        return PAM_SUCCESS;
    }

    DEBUG_PRINT("PAM: close_session for user=%s chain=%s handle=%" PRIu64,
                user, sd->chain_name, sd->jump_handle);

    if (nft_handler_cleanup(pamh, user, sd) != PAM_SUCCESS)
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: cleanup failed for %s — per-session state may persist", user);

    (void)session_file_remove(pamh, sd->scope_unit);
    event_close_emit(pamh, sd, user);

    return PAM_SUCCESS;
}
