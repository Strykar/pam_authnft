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
#include <sys/wait.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#ifdef AUTHNFT_COVERAGE
/* Coverage builds only (make coverage-report): the setup child exits
 * with _exit, which skips the atexit hook gcov flushes from, so its
 * counters (sandbox_apply, the whole setup path) would be lost. Never
 * defined in production builds. */
extern void __gcov_dump(void);
#define AUTHNFT_GCOV_DUMP() __gcov_dump()
#else
#define AUTHNFT_GCOV_DUMP() do { } while (0)
#endif

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

/*
 * Emit the user-facing message for a fragment rejection. nft_handler_setup
 * reports the reason rather than calling pam_error itself, because it runs in
 * a forked child whose PAM conversation writes never reach the connecting
 * user (see run_sandboxed_nft_setup). The parent emits it instead, for both
 * the forked and the bypass path. NONE and non-fragment errors are silent;
 * those are still logged via pam_syslog and the audit channel in the child.
 */
static void emit_reject_message(pam_handle_t *pamh, const char *user,
                                authnft_reject_reason reason) {
    char path[sizeof(RULES_DIR) + MAX_USER_LEN + 2];
    snprintf(path, sizeof(path), "%s/%s", RULES_DIR, user);
    switch (reason) {
    case AUTHNFT_REJECT_FRAGMENT_MISSING:
        pam_error(pamh, "authnft: no rule fragment at %s — add one and reconnect.",
                  path);
        break;
    case AUTHNFT_REJECT_FRAGMENT_PERMS:
        pam_error(pamh, "authnft: fragment %s must be root-owned and not "
                  "group- or world-writable, in a 0700 root:root directory.",
                  path);
        break;
    case AUTHNFT_REJECT_FRAGMENT_UNREADABLE:
        pam_error(pamh, "authnft: fragment %s could not be read.", path);
        break;
    case AUTHNFT_REJECT_FRAGMENT_CONTENT:
        pam_error(pamh, "authnft: fragment %s rejected by content validator.",
                  path);
        break;
    case AUTHNFT_REJECT_FRAGMENT_SYNTAX:
        pam_error(pamh, "authnft: fragment syntax error — check /var/log/auth.log");
        break;
    case AUTHNFT_REJECT_NONE:
        break;
    }
}

/*
 * Run the seccomp-sandboxed nftables setup in a forked child.
 *
 * sshd calls pam_open_session in its privsep monitor, before the monitor
 * forks the process that becomes the user's session (in sshd-session.c
 * do_pam_session runs ahead of privsep_postauth, and the monitor stays in
 * monitor_child_postauth). A seccomp filter installed in the monitor is
 * inherited by that later session fork, and neither clone nor execve is in
 * the allowlist — it was derived from a pamtester open+close cycle, which
 * forks no command — so the session is killed with SIGSYS. Installing the
 * filter in a short-lived child of open_session instead keeps the monitor
 * unfiltered, while still containing nft_handler_setup, the one step that
 * feeds semi-trusted input (the user's fragment) through libnftables. The
 * child's nftables changes live in the kernel and outlast it; it returns
 * the setup result and the parsed jump-rule handle (which close_session
 * needs for teardown) to the parent over a pipe.
 *
 * Fails closed with PAM_SESSION_ERR on a short read or an abnormally-exited
 * child. A child killed by SIGSYS means the allowlist is missing a syscall
 * the setup path needs — the same fail-closed posture sandbox_apply itself
 * takes on a rule-registration error.
 *
 * bus_handler_start stays in the unsandboxed parent: its only non-
 * deterministic input is systemd's reply over the system bus, not user
 * data, so it is not the surface the sandbox exists to contain.
 */
static int run_sandboxed_nft_setup(pam_handle_t *pamh, const char *user,
                                   int session_pid, authnft_session_t *sd,
                                   int bypass) {
    if (bypass) {
        pam_syslog(pamh, LOG_DEBUG, "authnft: seccomp bypassed");
        if (!nft_user_in_authnft_group(pamh, user))
            return PAM_SUCCESS;
        authnft_reject_reason reason = AUTHNFT_REJECT_NONE;
        int rc = nft_handler_setup(pamh, user, session_pid, sd, &reason);
        emit_reject_message(pamh, user, reason);
        return rc;
    }

    struct setup_result {
        int rc;
        uint64_t jump_handle;
        authnft_reject_reason reason;
    } res = { PAM_SESSION_ERR, 0, AUTHNFT_REJECT_NONE };

    int pfd[2];
    if (pipe(pfd) < 0) {
        pam_syslog(pamh, LOG_ERR, "authnft: pipe failed: %m");
        return PAM_SESSION_ERR;
    }

    pid_t pid = fork();
    if (pid < 0) {
        pam_syslog(pamh, LOG_ERR, "authnft: fork failed: %m");
        close(pfd[0]);
        close(pfd[1]);
        return PAM_SESSION_ERR;
    }

    if (pid == 0) {
        /* The only process that ever carries the filter. nft_handler_setup's
         * kernel-side nft state persists after this child _exit()s. */
        close(pfd[0]);
        /* Resolve authnft group membership here, in the child but BEFORE the
         * seccomp filter: NSS backends (sss, ldap, systemd) run unsandboxed so
         * they cannot SIGSYS-kill the child, and any NSS connection state dies
         * with this short-lived child instead of persisting in the sshd
         * monitor, where it raced the transient-scope teardown on a failed
         * session. A non-member is not managed by authnft — pass through. */
        if (!nft_user_in_authnft_group(pamh, user))
            res.rc = PAM_SUCCESS;
        else if (sandbox_apply(pamh) < 0)
            pam_syslog(pamh, LOG_ERR, "authnft: failed to apply sandbox");
        else
            res.rc = nft_handler_setup(pamh, user, session_pid, sd, &res.reason);
        res.jump_handle = sd->jump_handle;
        for (size_t off = 0; off < sizeof(res); ) {
            ssize_t w = write(pfd[1], (const char *)&res + off,
                              sizeof(res) - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
        close(pfd[1]);
        AUTHNFT_GCOV_DUMP();
        _exit(0);
    }

    /* Unsandboxed parent (the sshd monitor): collect the result and reap. */
    close(pfd[1]);
    size_t off = 0;
    while (off < sizeof(res)) {
        ssize_t r = read(pfd[0], (char *)&res + off, sizeof(res) - off);
        if (r <= 0) break;
        off += (size_t)r;
    }
    close(pfd[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;

    if (off != sizeof(res) || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (WIFSIGNALED(status))
            pam_syslog(pamh, LOG_ERR,
                       "authnft: sandboxed setup child killed by signal %d "
                       "(SIGSYS here means the allowlist is missing a syscall "
                       "the setup path needs) — failing the session",
                       WTERMSIG(status));
        else
            pam_syslog(pamh, LOG_ERR,
                       "authnft: sandboxed setup child reported only %zu of "
                       "%zu bytes — failing the session", off, sizeof(res));
        /* The child died before it could roll back its own partial nft
         * state, and never reported the jump handle. Reap whatever it had
         * already committed by name. */
        (void)nft_handler_cleanup_orphan(pamh, user, sd);
        return PAM_SESSION_ERR;
    }

    sd->jump_handle = res.jump_handle;
    emit_reject_message(pamh, user, res.reason);
    return res.rc;
}

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

    int bypass = is_debug_bypass_requested(argc, argv);

    /* The seccomp filter is applied inside run_sandboxed_nft_setup's child,
     * not in this process — see that function for why. bus_handler_start
     * runs here, unsandboxed, in the (sshd monitor) caller. */
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

    int rc = run_sandboxed_nft_setup(pamh, user, session_pid, sd, bypass);
    if (rc == PAM_SUCCESS) {
        (void)session_file_write(pamh, sd, user, session_pid);
        event_open_emit(pamh, sd, user, session_pid);
    } else {
        /* The per-session nft state is already gone by the time we reach
         * here: on a clean setup failure the child ran nft_partial_cleanup
         * before reporting, and on an abnormal child death (SIGSYS from an
         * allowlist gap) run_sandboxed_nft_setup reaped it by name with
         * nft_handler_cleanup_orphan. Only the systemd scope is left to undo.
         * `sd` stays registered with PAM and is freed by free_pam_data when
         * the handle ends. */
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
