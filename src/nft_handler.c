// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include "nft_validator.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <nftables/libnftables.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>

/* Forward-declared: defined later in this file. read_file caps at
 * 64 KiB and is also used by substitute_placeholders. */
static char *read_file(const char *path, size_t *out_len);

/* validate_fragment_buf, substitute_placeholders, and user_in_group
 * live in src/nft_validator.c; declarations in nft_validator.h. The
 * extraction is the precondition for unit + mutation testing of the
 * pure decision surfaces. See docs/MUTATION_ASAN_EXPERIMENT.md. */

/*
 * Path-accepting wrapper. Reads the file once via read_file, then runs
 * validate_fragment_buf. Used by the fuzzer harness (which presents
 * input as a path via memfd_create + /proc/self/fd) and by callers
 * that don't already have the buffer in hand.
 *
 * Production callers in nft_handler_setup pre-read the fragment via
 * read_file and call validate_fragment_buf directly, then reuse the
 * same buffer for substitute_placeholders. That eliminates a redundant
 * file read and closes the TOCTOU window between validation and
 * substitution.
 */
#ifndef FUZZ_BUILD
static __attribute__((unused))
#endif
int validate_fragment_content(pam_handle_t *pamh, const char *path) {
    size_t buf_len = 0;
    char *buf = read_file(path, &buf_len);
    if (!buf) return -1;
    int rc = validate_fragment_buf(pamh, path, buf, buf_len);
    free(buf);
    return rc;
}

/*
 * Read a file into a malloc'd buffer. Returns NULL on failure.
 * Caller must free(). *out_len is set to the content length.
 */
static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0 || sz > 65536) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

/*
 * Best-effort rollback of partial nft state created by nft_handler_setup
 * before it failed. Removes the per-session chain, three sets, and (if
 * captured) the jump rule. Tolerates absent objects — if nothing was
 * created yet (e.g., call 1 failed atomically), the transaction will
 * fail and we discard the result.
 *
 * Edge case: if call 2 succeeded but the handle parse failed, the jump
 * rule exists in the kernel but `sd->jump_handle` is still 0. We can't
 * delete-by-name (nftables requires handle), so the jump rule leaks in
 * that path. Documented; rare (only fires on a libnftables echo-format
 * regression).
 */
static void nft_partial_cleanup(struct nft_ctx *ctx,
                                 const authnft_session_t *sd) {
    char cmd[CMD_BUF_SIZE];

    if (sd->jump_handle) {
        snprintf(cmd, sizeof(cmd),
                 "delete rule inet %s filter handle %" PRIu64,
                 TABLE_NAME, sd->jump_handle);
        (void)nft_run_cmd_from_buffer(ctx, cmd);
    }

    snprintf(cmd, sizeof(cmd),
             "flush chain inet %s %s\n"
             "delete chain inet %s %s\n"
             "delete set inet %s %s\n"
             "delete set inet %s %s\n"
             "delete set inet %s %s",
             TABLE_NAME, sd->chain_name,
             TABLE_NAME, sd->chain_name,
             TABLE_NAME, sd->set_v4,
             TABLE_NAME, sd->set_v6,
             TABLE_NAME, sd->set_cg);
    (void)nft_run_cmd_from_buffer(ctx, cmd);
}

/*
 * Resolve authnft group membership via getgrouplist(3), which consults the
 * full NSS stack (compat, files, sss, ldap, systemd, ...) and returns every
 * group the user is in, including the primary — unlike a gr_mem walk, which
 * is empty on sssd/ldap hosts with the default enumerate=false. Returns 1 if
 * `user` is a member of the 'authnft' group, 0 otherwise (including when the
 * group or the user does not resolve).
 *
 * Runs in the setup child but BEFORE sandbox_apply. NSS backends dlopen
 * modules that issue syscalls the seccomp allowlist does not cover — sssd/ldap
 * open their own sockets and nss_ldap can drive a TLS handshake — and the
 * allowlist was derived from a files-backend trace, so resolving membership
 * after the filter is installed would SIGSYS-kill a legitimate directory
 * user's session. Doing it unsandboxed avoids that; doing it in the child
 * rather than the sshd monitor keeps NSS connection state out of the process
 * that owns the transient scope, whose teardown it otherwise raced on a failed
 * session (see run_sandboxed_nft_setup in src/pam_entry.c).
 */
int nft_user_in_authnft_group(pam_handle_t *pamh, const char *user) {
    (void)pamh;
    struct group *grp = getgrnam("authnft");
    if (!grp) return 0;
    struct passwd *pw = getpwnam(user);
    if (!pw) return 0;

    int ngroups = 64;
    gid_t groups[64];
    int rc = getgrouplist(user, pw->pw_gid, groups, &ngroups);
    if (rc >= 0)
        return user_in_group(grp->gr_gid, groups, (size_t)ngroups) ? 1 : 0;

    /* Buffer too small — user belongs to >64 groups. Allocate the size
     * getgrouplist reported and retry once. */
    gid_t *big = calloc((size_t)ngroups, sizeof(gid_t));
    if (!big) return 0;
    rc = getgrouplist(user, pw->pw_gid, big, &ngroups);
    int in = (rc >= 0) && user_in_group(grp->gr_gid, big, (size_t)ngroups);
    free(big);
    return in;
}

int nft_handler_setup(pam_handle_t *pamh, const char *user,
                      int session_pid, authnft_session_t *sd,
                      authnft_reject_reason *reason) {
    struct nft_ctx *ctx;
    char cmd[CMD_BUF_SIZE];
    char user_conf_path[256];
    struct stat st;
    int result;

    if (strcmp(user, "root") == 0) return PAM_SUCCESS;

    if (!sd || sd->cg_path[0] == '\0') {
        pam_syslog(pamh, LOG_ERR, "authnft: setup called with empty cg_path");
        return PAM_SESSION_ERR;
    }

    DEBUG_PRINT("nft_handler_setup: user=%s cg=%s chain=%s",
                user, sd->cg_path, sd->chain_name);

    /* authnft group membership was resolved by the caller in the
     * unsandboxed parent (nft_user_in_authnft_group, from
     * pam_sm_open_session before the fork) so no NSS backend runs under
     * the seccomp filter. A non-member never reaches this function. */

    /* Fragment validation: must exist, be root-owned, and not world-writable. */
    snprintf(user_conf_path, sizeof(user_conf_path), "%s/%s", RULES_DIR, user);
    DEBUG_PRINT("loading fragment: %s", user_conf_path);

    if (stat(user_conf_path, &st) != 0) {
        (void)pam_syslog(pamh, LOG_ERR,
                         "authnft: missing fragment for %s at %s", user, user_conf_path);
        authnft_audit_fragment_reject(user, "missing", user_conf_path);
        if (reason) *reason = AUTHNFT_REJECT_FRAGMENT_MISSING;
        return PAM_AUTH_ERR;
    }

    if (st.st_uid != 0 || (st.st_mode & S_IWOTH)) {
        (void)pam_syslog(pamh, LOG_ERR,
                         "authnft: insecure permissions on %s (uid=%d mode=%o)",
                         user_conf_path, st.st_uid, st.st_mode);
        authnft_audit_fragment_reject(user, "perms", user_conf_path);
        if (reason) *reason = AUTHNFT_REJECT_FRAGMENT_PERMS;
        return PAM_AUTH_ERR;
    }

    /* Read the fragment once, reuse the buffer for both validation and
     * placeholder substitution below. Eliminates a redundant fopen and
     * closes the TOCTOU window between validate-by-path and read-by-path
     * where an admin could have rewritten the file between checks. */
    size_t frag_len = 0;
    char *frag_buf = read_file(user_conf_path, &frag_len);
    if (!frag_buf) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: could not read fragment %s", user_conf_path);
        authnft_audit_fragment_reject(user, "content", user_conf_path);
        if (reason) *reason = AUTHNFT_REJECT_FRAGMENT_UNREADABLE;
        return PAM_AUTH_ERR;
    }

    /* Content validation: verb scan, include path check. */
    if (validate_fragment_buf(pamh, user_conf_path, frag_buf, frag_len) < 0) {
        free(frag_buf);
        authnft_audit_fragment_reject(user, "content", user_conf_path);
        if (reason) *reason = AUTHNFT_REJECT_FRAGMENT_CONTENT;
        return PAM_AUTH_ERR;
    }

    /* Determine which per-session set gets the element. */
    const char *remote_ip = sd->remote_ip[0] ? sd->remote_ip : NULL;
    int cg_only = (remote_ip == NULL);
    int is_v6 = !cg_only && (strchr(remote_ip, ':') != NULL);
    const char *set_name = cg_only ? sd->set_cg : (is_v6 ? sd->set_v6 : sd->set_v4);

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) {
        free(frag_buf);
        return PAM_SERVICE_ERR;
    }

    /*
     * Probe the shared filter chain for the ct accept rule. nftables
     * `add rule` is always-append; without this probe the chain would
     * grow by one ct rule per session_open across the host's lifetime.
     * On first session ever (chain doesn't exist) the list call fails
     * and we fall through to including the rule in call 1, which
     * creates the chain at the same time. On subsequent sessions the
     * chain exists with the rule, the probe matches, and we omit it.
     *
     * The probe-then-add pattern races between concurrent open_sessions:
     * two simultaneous probes can both see "rule absent" and both add
     * it. The window is small and the resulting duplicates are still
     * harmless (first rule matches, rest skipped). Net effect: chain
     * size stays O(concurrent-burst-size) instead of O(total-sessions).
     */
    nft_ctx_buffer_output(ctx);
    int probe_rc = nft_run_cmd_from_buffer(ctx,
        "list chain inet " TABLE_NAME " filter");
    const char *probe_out = nft_ctx_get_output_buffer(ctx);
    int ct_rule_present = (probe_rc == 0 && probe_out &&
        strstr(probe_out, "ct state established,related accept") != NULL);
    nft_ctx_unbuffer_output(ctx);

    const char *ct_rule_line = ct_rule_present
        ? ""
        : "add rule inet " TABLE_NAME " filter ct state established,related accept\n";

    /*
     * Call 1: infrastructure + per-session chain/sets + element.
     * add table and add chain are idempotent in libnftables. The ct
     * rule is included only when the probe above did not find it.
     */
    char *claims_tag = sd->claims_tag[0] ? sd->claims_tag : NULL;
    char tag_part[CLAIMS_TAG_MAX + 8] = "";
    if (claims_tag)
        snprintf(tag_part, sizeof(tag_part), " [%s]", claims_tag);

    if (cg_only) {
        result = snprintf(cmd, sizeof(cmd),
                  "add table inet %s\n"
                  "add chain inet %s filter { type filter hook input priority filter - 1; policy accept; }\n"
                  "%s"
                  "add chain inet %s %s\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2; flags timeout; }\n"
                  "add element inet %s %s { \"%s\" timeout 1d comment \"%s (PID:%d)%s\" }",
                  TABLE_NAME,
                  TABLE_NAME,
                  ct_rule_line,
                  TABLE_NAME, sd->chain_name,
                  TABLE_NAME, sd->set_v4,
                  TABLE_NAME, sd->set_v6,
                  TABLE_NAME, sd->set_cg,
                  TABLE_NAME, set_name, sd->cg_path, user, session_pid, tag_part);
    } else {
        result = snprintf(cmd, sizeof(cmd),
                  "add table inet %s\n"
                  "add chain inet %s filter { type filter hook input priority filter - 1; policy accept; }\n"
                  "%s"
                  "add chain inet %s %s\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2; flags timeout; }\n"
                  "add element inet %s %s { \"%s\" . %s timeout 1d comment \"%s (PID:%d)%s\" }",
                  TABLE_NAME,
                  TABLE_NAME,
                  ct_rule_line,
                  TABLE_NAME, sd->chain_name,
                  TABLE_NAME, sd->set_v4,
                  TABLE_NAME, sd->set_v6,
                  TABLE_NAME, sd->set_cg,
                  TABLE_NAME, set_name, sd->cg_path, remote_ip, user, session_pid, tag_part);
    }

    if (result < 0 || (size_t)result >= sizeof(cmd)) {
        free(frag_buf);
        nft_ctx_free(ctx);
        return PAM_BUF_ERR;
    }

    DEBUG_PRINT("nft call 1 (infra+sets):\n%s", cmd);
    if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        /* "chain already exists" / "set already exists" on call 1 has a
         * specific operational cause: a previous session for the same
         * (user, pid) leaked its per-session state (privsep close-session
         * leak, OOM-killed daemon, kernel panic, etc.). The per-session
         * chain, sets, and jump rule have no timeout of their own — only
         * the element does — so the leak survives until the same PID
         * recycles. PIDs recycle on busy hosts within minutes; a user
         * opening a new session on the recycled PID lands on the stale
         * names and, without recovery, is denied a session (fail-closed
         * self-lockout). Self-heal: reap the stale (user, pid) state by
         * name (recovers the old jump handle by listing the shared chain,
         * same as nft_handler_cleanup_orphan), then retry call 1 once. */
        /* Stale per-session state surfaces as "already exists" (EEXIST) or,
         * when a leftover set is still referenced, "Device or resource busy"
         * (EBUSY), depending on which object collides and the nft version.
         * Match both. The recovery is scoped to this (user, pid) name and
         * retried once, so a false match on an unrelated error costs only a
         * no-op cleanup and a single retry that fails the same way. */
        if (err_msg && (strstr(err_msg, "exists") || strstr(err_msg, "EEXIST") ||
                        strstr(err_msg, "busy") || strstr(err_msg, "BUSY"))) {
            pam_syslog(pamh, LOG_WARNING,
                       "authnft: setup call 1 hit stale per-session state for "
                       "%s/%s (likely PID-recycle after a leaked session) — "
                       "reaping it and retrying",
                       user, sd->chain_name);
            (void)nft_handler_cleanup_orphan(pamh, user, sd);
            if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
                err_msg = nft_ctx_get_error_buffer(ctx);
                pam_syslog(pamh, LOG_ERR,
                           "authnft: setup call 1 still failing after reaping "
                           "stale state for %s/%s: %s",
                           user, sd->chain_name, err_msg);
                free(frag_buf);
                nft_ctx_free(ctx);
                return PAM_SERVICE_ERR;
            }
        } else {
            pam_syslog(pamh, LOG_ERR, "authnft: setup call 1 failed: %s", err_msg);
            free(frag_buf);
            nft_ctx_free(ctx);
            return PAM_SERVICE_ERR;
        }
    }

    /*
     * Call 2: jump rule in the shared filter chain. ECHO + HANDLE flags
     * make libnftables print the committed rule with its kernel-assigned
     * handle, which we parse and store for cleanup.
     */
    nft_ctx_output_set_flags(ctx,
        NFT_CTX_OUTPUT_ECHO | NFT_CTX_OUTPUT_HANDLE);
    nft_ctx_buffer_output(ctx);

    snprintf(cmd, sizeof(cmd),
             "add rule inet %s filter jump %s",
             TABLE_NAME, sd->chain_name);

    DEBUG_PRINT("nft call 2 (jump rule):\n%s", cmd);
    if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        pam_syslog(pamh, LOG_ERR, "authnft: jump rule failed: %s", err_msg);
        nft_ctx_unbuffer_output(ctx);
        /* Roll back call 1 state. jump_handle is still 0 so the
         * partial cleanup skips the rule-delete branch correctly. */
        nft_partial_cleanup(ctx, sd);
        free(frag_buf);
        nft_ctx_free(ctx);
        return PAM_SERVICE_ERR;
    }

    /* nft prints rule output as: <body> [comment "..."] # handle <id>.
     * If a comment ever contains the substring "# handle N", strstr would
     * find that first and sscanf would extract the wrong number. The jump
     * rule we just added has no comment, but a future maintainer adding
     * one (e.g., to encode scope_unit for cleanup hardening) would silently
     * break this parser. Scan for the LAST occurrence — the real handle
     * marker is always last on the line. See nftables rule.c:520-521 for
     * the print order: comment, then handle. */
    const char *out = nft_ctx_get_output_buffer(ctx);
    uint64_t handle = 0;
    const char *h = NULL;
    if (out) {
        for (const char *p = out, *q; (q = strstr(p, "# handle ")); p = q + 9)
            h = q;
    }
    if (!h || sscanf(h, "# handle %" SCNu64, &handle) != 1 || handle == 0) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: could not parse jump rule handle from nft output");
        nft_ctx_unbuffer_output(ctx);
        /* Roll back call 1 state. The jump rule was committed (call 2
         * succeeded) but we never captured its handle, so it leaks
         * here — see comment on nft_partial_cleanup. */
        nft_partial_cleanup(ctx, sd);
        free(frag_buf);
        nft_ctx_free(ctx);
        return PAM_SERVICE_ERR;
    }
    sd->jump_handle = handle;
    DEBUG_PRINT("jump rule handle: %" PRIu64, handle);

    nft_ctx_unbuffer_output(ctx);
    /* Clear ECHO/HANDLE flags for call 3 — fragment output is noise. */
    nft_ctx_output_set_flags(ctx, 0);

    /*
     * Call 3: read the fragment, substitute placeholders, execute.
     *
     * Four placeholders are replaced with live per-session names:
     *   @session_v4    → per-session IPv4 set name
     *   @session_v6    → per-session IPv6 set name
     *   @session_cg    → per-session cgroup-only set name
     *   @session_chain → per-session chain name
     *
     * Substitution is token-aware: occurrences inside #-comments and
     * "..." quoted strings are skipped. Token boundary check prevents
     * partial matches (e.g., @session_v4x is not substituted).
     *
     * Placeholders are resolved in the top-level fragment only.
     * Files pulled in via nftables `include` are parsed by libnftables
     * directly and do not receive substitution. This is documented as
     * a design choice: per-session rules use placeholders; shared
     * includes use the shared filter chain with accept-only rules.
     *
     * frag_buf was read once at the top of this function (just before
     * validate_fragment_buf) and is reused here unchanged. No second
     * file read; no TOCTOU window between validation and substitution.
     */

    /* Set placeholders keep the @ prefix (nft set-reference syntax).
     * Chain placeholder drops it (chain names are bare identifiers). */
    char rep_v4[SET_NAME_MAX + 2], rep_v6[SET_NAME_MAX + 2],
         rep_cg[SET_NAME_MAX + 2];
    snprintf(rep_v4, sizeof(rep_v4), "@%s", sd->set_v4);
    snprintf(rep_v6, sizeof(rep_v6), "@%s", sd->set_v6);
    snprintf(rep_cg, sizeof(rep_cg), "@%s", sd->set_cg);

    const char *placeholders[4] = {
        "@session_v4", "@session_v6", "@session_cg", "@session_chain"
    };
    const char *replacements[4] = {
        rep_v4, rep_v6, rep_cg, sd->chain_name
    };
    char *subst_buf = substitute_placeholders(frag_buf, frag_len,
                                               placeholders, replacements);
    free(frag_buf);
    if (!subst_buf) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: placeholder substitution failed for %s",
                   user_conf_path);
        nft_partial_cleanup(ctx, sd);
        nft_ctx_free(ctx);
        return PAM_SERVICE_ERR;
    }

    DEBUG_PRINT("nft call 3 (substituted fragment):\n%s", subst_buf);
    if (nft_run_cmd_from_buffer(ctx, subst_buf) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        (void)pam_syslog(pamh, LOG_ERR,
                         "authnft: syntax error in %s: %s", user_conf_path, err_msg);
        authnft_audit_fragment_reject(user, "nft-syntax", user_conf_path);
        if (reason) *reason = AUTHNFT_REJECT_FRAGMENT_SYNTAX;
        free(subst_buf);
        nft_partial_cleanup(ctx, sd);
        nft_ctx_free(ctx);
        return PAM_AUTH_ERR;
    }
    free(subst_buf);

    nft_ctx_free(ctx);
    return PAM_SUCCESS;
}

int nft_handler_cleanup(pam_handle_t *pamh, const char *user,
                        const authnft_session_t *sd) {
    struct nft_ctx *ctx;
    char cmd[CMD_BUF_SIZE];

    if (strcmp(user, "root") == 0) return PAM_SUCCESS;
    if (!sd || sd->chain_name[0] == '\0') return PAM_SESSION_ERR;

    DEBUG_PRINT("nft_handler_cleanup: user=%s chain=%s handle=%" PRIu64,
                user, sd->chain_name, sd->jump_handle);

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return PAM_SESSION_ERR;

    /*
     * Fast path: tear down the whole per-session state in one transaction,
     * in dependency order — jump rule first (a chain cannot be deleted
     * while a rule jumps to it), then flush+delete the chain (removing the
     * fragment rules that reference the sets), then the three sets. This is
     * the normal close, where every object still exists.
     */
    int n = snprintf(cmd, sizeof(cmd),
             "delete rule inet %s filter handle %" PRIu64 "\n"
             "flush chain inet %s %s\n"
             "delete chain inet %s %s\n"
             "delete set inet %s %s\n"
             "delete set inet %s %s\n"
             "delete set inet %s %s",
             TABLE_NAME, sd->jump_handle,
             TABLE_NAME, sd->chain_name,
             TABLE_NAME, sd->chain_name,
             TABLE_NAME, sd->set_v4,
             TABLE_NAME, sd->set_v6,
             TABLE_NAME, sd->set_cg);

    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        nft_ctx_free(ctx);
        return PAM_SESSION_ERR;
    }

    DEBUG_PRINT("cleanup:\n%s", cmd);
    if (nft_run_cmd_from_buffer(ctx, cmd) == 0) {
        nft_ctx_free(ctx);
        return PAM_SUCCESS;
    }

    /*
     * The atomic transaction aborted because one object was already gone —
     * the 24h element timeout reaped it, a prior orphan reap ran, or an
     * operator cleaned up by hand. nftables rolls the whole transaction
     * back on the first failure, so the other five objects are still in the
     * kernel. Delete each in its own transaction, same dependency order, so
     * a single missing object cannot strand the rest. Every step tolerates
     * an absent object. Best-effort: close_session must always unwind, so
     * this returns PAM_SUCCESS regardless (the 24h timeout remains the final
     * backstop for the element, and the per-object deletes clear the chain,
     * sets, and jump rule that have no timeout of their own).
     */
    pam_syslog(pamh, LOG_INFO,
               "authnft: atomic cleanup for %s aborted (an object was already "
               "gone) — falling back to per-object teardown", user);

    if (sd->jump_handle) {
        snprintf(cmd, sizeof(cmd),
                 "delete rule inet %s filter handle %" PRIu64,
                 TABLE_NAME, sd->jump_handle);
        (void)nft_run_cmd_from_buffer(ctx, cmd);
    }
    snprintf(cmd, sizeof(cmd),
             "flush chain inet %s %s\ndelete chain inet %s %s",
             TABLE_NAME, sd->chain_name, TABLE_NAME, sd->chain_name);
    (void)nft_run_cmd_from_buffer(ctx, cmd);
    snprintf(cmd, sizeof(cmd), "delete set inet %s %s", TABLE_NAME, sd->set_v4);
    (void)nft_run_cmd_from_buffer(ctx, cmd);
    snprintf(cmd, sizeof(cmd), "delete set inet %s %s", TABLE_NAME, sd->set_v6);
    (void)nft_run_cmd_from_buffer(ctx, cmd);
    snprintf(cmd, sizeof(cmd), "delete set inet %s %s", TABLE_NAME, sd->set_cg);
    (void)nft_run_cmd_from_buffer(ctx, cmd);

    nft_ctx_free(ctx);
    return PAM_SUCCESS;
}

/*
 * Best-effort teardown for the case where the sandboxed setup child died (a
 * SIGSYS from an allowlist gap) before it could roll back its own partial
 * state. The parent calls this with the per-session names it built before
 * the fork, but without the jump-rule handle the child never reported.
 * Recover the handle by listing the shared filter chain and matching the
 * jump to our per-session chain, delete that rule, then drop the chain and
 * the three sets. Every step tolerates an absent object, so a child that
 * died before committing anything is a clean no-op.
 */
int nft_handler_cleanup_orphan(pam_handle_t *pamh, const char *user,
                               const authnft_session_t *sd) {
    (void)pamh;  /* no logging here; the caller reports the failure context */
    if (strcmp(user, "root") == 0) return PAM_SUCCESS;
    if (!sd || sd->chain_name[0] == '\0') return PAM_SESSION_ERR;

    struct nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return PAM_SESSION_ERR;

    /* Recover the jump-rule handle: list the shared chain with handles and
     * find "jump <chain_name> ". The trailing space keeps a shorter pid from
     * matching a longer one (session_u_12 vs session_u_123). The jump rule
     * carries no comment, so the first "# handle" after the match is ours. */
    uint64_t handle = 0;
    nft_ctx_output_set_flags(ctx, NFT_CTX_OUTPUT_HANDLE);
    nft_ctx_buffer_output(ctx);
    if (nft_run_cmd_from_buffer(ctx,
            "list chain inet " TABLE_NAME " filter") == 0) {
        const char *out = nft_ctx_get_output_buffer(ctx);
        char needle[CHAIN_NAME_MAX + 8];
        snprintf(needle, sizeof(needle), "jump %s ", sd->chain_name);
        const char *j = out ? strstr(out, needle) : NULL;
        const char *h = j ? strstr(j, "# handle ") : NULL;
        if (h) (void)sscanf(h, "# handle %" SCNu64, &handle);
    }
    nft_ctx_unbuffer_output(ctx);
    nft_ctx_output_set_flags(ctx, 0);

    char cmd[CMD_BUF_SIZE];
    /* Drop the jump rule first; a chain cannot be deleted while a rule still
     * jumps to it. Separate transaction so a missing handle does not abort
     * the chain/set teardown below. */
    if (handle) {
        snprintf(cmd, sizeof(cmd),
                 "delete rule inet %s filter handle %" PRIu64,
                 TABLE_NAME, handle);
        (void)nft_run_cmd_from_buffer(ctx, cmd);
    }

    snprintf(cmd, sizeof(cmd),
             "flush chain inet %s %s\n"
             "delete chain inet %s %s\n"
             "delete set inet %s %s\n"
             "delete set inet %s %s\n"
             "delete set inet %s %s",
             TABLE_NAME, sd->chain_name,
             TABLE_NAME, sd->chain_name,
             TABLE_NAME, sd->set_v4,
             TABLE_NAME, sd->set_v6,
             TABLE_NAME, sd->set_cg);
    (void)nft_run_cmd_from_buffer(ctx, cmd);

    nft_ctx_free(ctx);
    return PAM_SUCCESS;
}
