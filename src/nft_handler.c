// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <nftables/libnftables.h>
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

/*
 * Fragment content validation against a pre-read buffer. Walks the buffer
 * by '\n' to avoid buffer-boundary verb truncation, then rejects:
 *   - Disallowed verbs: flush, delete, destroy, reset, list, rename,
 *     insert, replace, monitor
 *   - 'add rule inet authnft filter ...' targeting the shared filter chain;
 *     fragments must target the per-session chain via the @session_chain
 *     placeholder
 *   - include paths outside /etc/authnft/, relative paths, '..' segments,
 *     and glob characters
 *
 * `path` is used only for log messages — the validator never re-opens it,
 * so callers can pass a synthetic name when validating in-memory content.
 *
 * Trust model: fragments are admin-authored (root-owned, not world-writable;
 * checked by stat(2) earlier). This validator is defense-in-depth and a
 * typo-catcher; it is NOT a sandbox for untrusted input. See
 * docs/INTEGRATIONS.txt §4 for the full producer trust contract.
 *
 * Returns 0 if valid, -1 if rejected (reason logged via pam_syslog).
 */
static int validate_fragment_buf(pam_handle_t *pamh, const char *path,
                                  const char *buf, size_t buf_len) {
    static const char *bad_verbs[] = {
        "flush", "delete", "destroy", "reset", "list", "rename",
        "insert", "replace", "monitor", NULL
    };
    /* `destroy` covers the same surface as `delete` (TABLE/CHAIN/RULE/SET/
     * MAP/ELEMENT/FLOWTABLE/COUNTER/QUOTA/CT/LIMIT/SECMARK/SYNPROXY/
     * TUNNEL — see nftables parser_bison.y) but with cmd_alloc(CMD_DESTROY)
     * semantics that tolerate ENOENT silently. Without it, a fragment
     * could bypass the `delete` block via `destroy table inet authnft`. */
    static const char shared_chain_prefix[] = "add rule inet " TABLE_NAME " filter";
    static const size_t shared_chain_prefix_len = sizeof(shared_chain_prefix) - 1;

    int rc = 0;
    int lineno = 1;
    const char *p = buf;
    const char *end = buf + buf_len;

    while (p < end) {
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;
        size_t line_len = (size_t)(line_end - p);

        /* Skip leading whitespace */
        const char *t = p;
        while (t < line_end && (*t == ' ' || *t == '\t')) t++;
        size_t tlen = (size_t)(line_end - t);

        /* Skip empty lines and comments */
        if (tlen == 0 || *t == '#') goto next;

        /* Disallowed-verb check. Verb match requires a word boundary
         * (space/tab/end-of-line) so 'flushy' wouldn't trip 'flush'. */
        for (int i = 0; bad_verbs[i]; i++) {
            size_t vlen = strlen(bad_verbs[i]);
            if (tlen >= vlen && memcmp(t, bad_verbs[i], vlen) == 0 &&
                (tlen == vlen || t[vlen] == ' ' || t[vlen] == '\t')) {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: fragment %s:%d uses disallowed verb '%s'",
                           path, lineno, bad_verbs[i]);
                rc = -1;
                goto out;
            }
        }

        /* Reject 'add rule inet authnft filter ...' — fragments must target
         * the per-session chain via @session_chain. The shared filter chain
         * is owned by pam_authnft; any rule a fragment installs there
         * persists across sessions and affects every other session. */
        if (tlen >= shared_chain_prefix_len &&
            memcmp(t, shared_chain_prefix, shared_chain_prefix_len) == 0 &&
            (tlen == shared_chain_prefix_len ||
             t[shared_chain_prefix_len] == ' ' ||
             t[shared_chain_prefix_len] == '\t')) {
            pam_syslog(pamh, LOG_ERR,
                       "authnft: fragment %s:%d targets shared 'filter' chain; "
                       "fragments must target the per-session chain via "
                       "the @session_chain placeholder", path, lineno);
            rc = -1;
            goto out;
        }

        /* include path validation: absolute, under /etc/authnft/, no '..',
         * no glob characters. */
        if (tlen >= 8 && memcmp(t, "include", 7) == 0 &&
            (t[7] == ' ' || t[7] == '\t' || t[7] == '"')) {
            const char *q = t + 7;
            while (q < line_end && (*q == ' ' || *q == '\t')) q++;
            if (q < line_end && *q == '"') q++;

            if (q >= line_end || *q != '/') {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: fragment %s:%d uses relative include path",
                           path, lineno);
                rc = -1;
                goto out;
            }
            if ((size_t)(line_end - q) < 13 ||
                memcmp(q, "/etc/authnft/", 13) != 0) {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: fragment %s:%d includes path outside "
                           "/etc/authnft/", path, lineno);
                rc = -1;
                goto out;
            }
            /* Reject '..' segments anywhere in the path. A literal '..'
             * preceded by '/' or path start, followed by '/' or path
             * end, escapes the /etc/authnft/ prefix check. */
            for (const char *g = q; g < line_end && *g != '"'; g++) {
                if (*g == '.' && g + 1 < line_end && g[1] == '.' &&
                    (g == q || g[-1] == '/') &&
                    (g + 2 >= line_end || g[2] == '/' ||
                     g[2] == '"' || g[2] == ' ' || g[2] == '\t')) {
                    pam_syslog(pamh, LOG_ERR,
                               "authnft: fragment %s:%d include path "
                               "contains '..' segment", path, lineno);
                    rc = -1;
                    goto out;
                }
                if (*g == '*' || *g == '?' || *g == '[') {
                    pam_syslog(pamh, LOG_ERR,
                               "authnft: fragment %s:%d include path contains "
                               "glob character '%c'", path, lineno, *g);
                    rc = -1;
                    goto out;
                }
            }
        }

next:
        p = line_end + (line_end < end ? 1 : 0);
        lineno++;
        (void)line_len;
    }

out:
    return rc;
}

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
 * Token-aware placeholder substitution. Replaces each of the four
 * placeholders (@session_v4, @session_v6, @session_cg, @session_chain)
 * with the live per-session names, skipping occurrences inside
 * #-comments and "..." quoted strings.
 *
 * Token boundary check: the character after the placeholder must not
 * be [A-Za-z0-9_] to avoid partial matches (e.g., @session_v4x).
 *
 * Returns a new malloc'd buffer with substitutions applied, or NULL
 * on allocation failure. Caller must free().
 */
#ifndef FUZZ_BUILD
static
#endif
char *substitute_placeholders(const char *src, size_t src_len,
                              const char *placeholders[4],
                              const char *replacements[4]) {
    /* Worst case: every placeholder expands. Over-allocate. */
    size_t max_expand = src_len * 2 + 1;
    char *out = malloc(max_expand);
    if (!out) return NULL;

    size_t wi = 0;
    int in_comment = 0;
    int in_quote = 0;

    size_t i = 0;
    while (i < src_len) {
        char c = src[i];

        /* Reset both in_comment and in_quote at line boundaries.
         * nftables does not support multi-line "..." string literals in
         * fragments, so treating quoting as line-local is correct. The
         * earlier line-aware reset for in_comment but not in_quote
         * meant an unterminated " on one line silently disabled
         * placeholder substitution for the rest of the file — a
         * confusing failure mode. The fragment then fails libnftables
         * syntax check (because @session_v4 etc. are unsubstituted),
         * which is fail-safe but hides the cause. */
        if (c == '\n') { in_comment = 0; in_quote = 0; }
        if (!in_quote && c == '#') { in_comment = 1; }
        if (!in_comment && c == '"') { in_quote = !in_quote; }

        if (in_comment || in_quote) {
            /* Same bound check as the unmatched path below: leave room
             * for the trailing '\0'. A long quoted string or comment
             * after a placeholder expansion could otherwise overrun. */
            if (wi + 1 >= max_expand) {
                free(out);
                return NULL;
            }
            out[wi++] = c;
            i++;
            continue;
        }

        /* Try each placeholder. */
        int matched = 0;
        for (int p = 0; p < 4; p++) {
            size_t plen = strlen(placeholders[p]);
            if (i + plen <= src_len &&
                memcmp(&src[i], placeholders[p], plen) == 0) {
                /* Token boundary: next char must not be identifier-like. */
                char next = (i + plen < src_len) ? src[i + plen] : '\0';
                if ((next >= 'A' && next <= 'Z') ||
                    (next >= 'a' && next <= 'z') ||
                    (next >= '0' && next <= '9') ||
                    next == '_') {
                    break; /* Partial match, don't substitute. */
                }
                size_t rlen = strlen(replacements[p]);
                if (wi + rlen >= max_expand) {
                    free(out);
                    return NULL;
                }
                memcpy(&out[wi], replacements[p], rlen);
                wi += rlen;
                i += plen;
                matched = 1;
                break;
            }
        }
        if (!matched) {
            /* Mirror the matched-path check: leave room for the
             * trailing '\0' written after the loop. Without this guard,
             * a placeholder expansion that pushes wi to max_expand-1
             * followed by an unmatched byte advances wi to max_expand,
             * causing the terminator to write one past the buffer. */
            if (wi + 1 >= max_expand) {
                free(out);
                return NULL;
            }
            out[wi++] = c;
            i++;
        }
    }
    out[wi] = '\0';
    return out;
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

int nft_handler_setup(pam_handle_t *pamh, const char *user,
                      authnft_session_t *sd) {
    struct nft_ctx *ctx;
    char cmd[CMD_BUF_SIZE];
    char user_conf_path[256];
    char display_msg[512];
    struct stat st;
    int result;

    if (strcmp(user, "root") == 0) return PAM_SUCCESS;

    if (!sd || sd->cg_path[0] == '\0') {
        pam_syslog(pamh, LOG_ERR, "authnft: setup called with empty cg_path");
        return PAM_SESSION_ERR;
    }

    DEBUG_PRINT("nft_handler_setup: user=%s cg=%s chain=%s",
                user, sd->cg_path, sd->chain_name);

    /* Group membership check via getgrouplist(3).
     *
     * Earlier code walked grp->gr_mem from getgrnam("authnft"). On hosts
     * with SSSD or sssd-ldap and the (default) enumerate=false setting,
     * gr_mem is empty even when the user is a legitimate member through
     * directory memberOf. The user would silently fall through to
     * "not in group, passing through" and never get the per-session
     * firewall rules — a fail-safe but surprising failure mode.
     *
     * getgrouplist(3) consults the full NSS resolution (compat, files,
     * sss, ldap, ...) and returns every group the user is in, including
     * the primary. Match the authnft GID against that list. */
    struct group *grp = getgrnam("authnft");
    int in_group = 0;
    if (grp) {
        struct passwd *pw = getpwnam(user);
        if (pw) {
            int ngroups = 64;
            gid_t groups[64];
            int rc = getgrouplist(user, pw->pw_gid, groups, &ngroups);
            if (rc < 0) {
                /* Buffer too small — user belongs to >64 groups. Allocate
                 * the size getgrouplist reported and retry once. */
                gid_t *big = calloc((size_t)ngroups, sizeof(gid_t));
                if (big) {
                    rc = getgrouplist(user, pw->pw_gid, big, &ngroups);
                    if (rc >= 0) {
                        for (int i = 0; i < ngroups; i++)
                            if (big[i] == grp->gr_gid) { in_group = 1; break; }
                    }
                    free(big);
                }
            } else {
                for (int i = 0; i < ngroups; i++)
                    if (groups[i] == grp->gr_gid) { in_group = 1; break; }
            }
        }
    }

    if (!in_group) {
        DEBUG_PRINT("user %s not in 'authnft' group, passing through", user);
        return PAM_SUCCESS;
    }

    /* Fragment validation: must exist, be root-owned, and not world-writable. */
    snprintf(user_conf_path, sizeof(user_conf_path), "%s/%s", RULES_DIR, user);
    DEBUG_PRINT("loading fragment: %s", user_conf_path);

    if (stat(user_conf_path, &st) != 0) {
        (void)pam_syslog(pamh, LOG_ERR,
                         "authnft: missing fragment for %s at %s", user, user_conf_path);
        authnft_audit_fragment_reject(user, "missing", user_conf_path);
        snprintf(display_msg, sizeof(display_msg),
                 "authnft: no rule fragment at %s — add one and reconnect.",
                 user_conf_path);
        pam_error(pamh, "%s", display_msg);
        return PAM_AUTH_ERR;
    }

    if (st.st_uid != 0 || (st.st_mode & S_IWOTH)) {
        (void)pam_syslog(pamh, LOG_ERR,
                         "authnft: insecure permissions on %s (uid=%d mode=%o)",
                         user_conf_path, st.st_uid, st.st_mode);
        authnft_audit_fragment_reject(user, "perms", user_conf_path);
        pam_error(pamh, "authnft: fragment %s must be root-owned and not world-writable.",
                  user_conf_path);
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
        pam_error(pamh, "authnft: fragment %s could not be read.",
                  user_conf_path);
        return PAM_AUTH_ERR;
    }

    /* Content validation: verb scan, include path check. */
    if (validate_fragment_buf(pamh, user_conf_path, frag_buf, frag_len) < 0) {
        free(frag_buf);
        authnft_audit_fragment_reject(user, "content", user_conf_path);
        pam_error(pamh, "authnft: fragment %s rejected by content validator.",
                  user_conf_path);
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
                  TABLE_NAME, set_name, sd->cg_path, user, getpid(), tag_part);
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
                  TABLE_NAME, set_name, sd->cg_path, remote_ip, user, getpid(), tag_part);
    }

    if (result < 0 || (size_t)result >= sizeof(cmd)) {
        nft_ctx_free(ctx);
        return PAM_BUF_ERR;
    }

    DEBUG_PRINT("nft call 1 (infra+sets):\n%s", cmd);
    if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        /* "chain already exists" / "set already exists" on call 1 has a
         * specific operational cause: a previous session for the same
         * (user, pid) leaked its per-session state (privsep close-session
         * leak, OOM-killed daemon, kernel panic, etc.) and the 24h
         * element timeout has not yet evicted it. PIDs recycle on busy
         * hosts within minutes; a user opening a new session that lands
         * on the same PID hits this path. Surface it distinctly so an
         * operator can recognize the symptom and clean up by hand
         * (`nft delete chain inet authnft session_<user>_<pid>` and the
         * matching sets). */
        if (err_msg && (strstr(err_msg, "exists") || strstr(err_msg, "EEXIST"))) {
            pam_syslog(pamh, LOG_ERR,
                       "authnft: setup call 1 failed (per-session state for "
                       "%s/%s already present — likely PID-recycle after a "
                       "leaked session; check `nft list table inet authnft` "
                       "for stale chain/sets): %s",
                       user, sd->chain_name, err_msg);
        } else {
            pam_syslog(pamh, LOG_ERR, "authnft: setup call 1 failed: %s", err_msg);
        }
        nft_ctx_free(ctx);
        return PAM_SERVICE_ERR;
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
        pam_error(pamh, "authnft: fragment syntax error — check /var/log/auth.log");
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
     * Tear down per-session state in dependency order:
     *   1. Delete the jump rule from the shared filter chain (by handle).
     *   2. Flush the per-session chain (removes all rules, unblocking
     *      set deletion).
     *   3. Delete the per-session chain.
     *   4. Delete the three per-session sets.
     *
     * A single transaction ensures atomicity. If any object was already
     * reaped (timeout, manual cleanup), the transaction fails; we fall
     * through to the best-effort path.
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
    if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: cleanup failed for %s: %s", user, err_msg);
        nft_ctx_free(ctx);
        return PAM_SESSION_ERR;
    }

    nft_ctx_free(ctx);
    return PAM_SUCCESS;
}
