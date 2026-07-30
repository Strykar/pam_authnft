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
#include <limits.h>
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
 * Recursive include validation.
 *
 * validate_fragment_buf is pure by contract (include/nft_validator.h): it
 * never opens or stats anything, which is what lets the unit tests, the
 * fuzzer's memfd harness and the mutation runs drive it with plain
 * buffers. Include resolution therefore lives here, where the stat(2) and
 * the read already happen, and re-enters the validator for each file it
 * pulls in.
 *
 * Before this, the scan covered the top-level buffer only while
 * libnftables resolved includes at execution, so an included file reached
 * the kernel with no verb check at all. `flush ruleset` in an include ran
 * and returned 0. Issue #108.
 *
 * Included files get NFT_FRAG_INCLUDED, which keeps the verb denylist and
 * the include-path rules but drops the shared-chain guard, because
 * INTEGRATIONS.txt §4.6 makes the shared chain their documented target.
 */
/* Rule comments identify the gate in `nft list` output and give the probe
 * something to match that the rule text alone cannot: both gate arms share
 * the ct-state prefix with the unconditional rule they replaced. */
#define GATE_UNSESSIONED_COMMENT "authnft-est-unsessioned"
#define GATE_LIVE_COMMENT        "authnft-est-live"

/* nftables takes these as literals, so they are spelled rather than
 * computed. Kept beside AUTHNFT_MARK_MASK/ADMIN in authnft.h by the
 * build-time assertion below. */
#define AUTHNFT_MARK_MASK_STR  "0x00ffffff"
#define AUTHNFT_MARK_ADMIN_STR "0xff000000"

_Static_assert(AUTHNFT_MARK_MASK == 0x00ffffffu,
               "AUTHNFT_MARK_MASK_STR is out of step with AUTHNFT_MARK_MASK");
_Static_assert(AUTHNFT_MARK_ADMIN == 0xff000000u,
               "AUTHNFT_MARK_ADMIN_STR is out of step with AUTHNFT_MARK_ADMIN");

#define INC_MAX_DEPTH 4
#define INC_MAX_FILES 16
#define INC_PATH_MAX  256

/*
 * The directory a fragment or an included file lives in must be root-only.
 *
 * This is the check that carries the confidentiality, not the file mode.
 * With a 0700 directory a non-root user cannot traverse in, so a 0644
 * fragment is unreachable; without it, 0644 exposes every user's network
 * policy to every local user, and the file mode is the only thing left
 * standing. examples_generator.sh has emitted `chmod 700` here since the
 * beginning and called it "root-owned, not world-readable", `make install`
 * left it 0755, the docs never stated it as a requirement, and nothing
 * verified it. All four now agree.
 */
static int check_dir_root_only(pam_handle_t *pamh, const char *file_path)
{
    char dir[PATH_MAX];
    const char *slash = strrchr(file_path, '/');
    struct stat ds;

    if (!slash || slash == file_path) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: cannot derive directory of %s", file_path);
        return -1;
    }
    size_t n = (size_t)(slash - file_path);
    if (n >= sizeof(dir)) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: directory path too long for %s", file_path);
        return -1;
    }
    memcpy(dir, file_path, n);
    dir[n] = '\0';

    if (stat(dir, &ds) != 0) {
        pam_syslog(pamh, LOG_ERR, "authnft: cannot stat %s", dir);
        return -1;
    }
    if (ds.st_uid != 0 || (ds.st_mode & (S_IRWXG | S_IRWXO))) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: %s must be root-only (want 0700 root:root, "
                   "have %04o uid=%d)",
                   dir, ds.st_mode & 07777, ds.st_uid);
        return -1;
    }
    return 0;
}

/*
 * Permission bar for a fragment or an included file: root-owned, and not
 * writable by group or other.
 *
 * Group-write is the one that matters. `authnft` is exactly the set of
 * users the module gates, so a 0664 root:authnft fragment lets any gated
 * user rewrite any other's rules and have them installed as root at the
 * next session open. Nothing legitimate needs it, so rejecting it costs
 * nothing; 0644 stays valid, which is what INTEGRATIONS.txt §4.4 tells
 * producers to write.
 */
static int check_file_perms(pam_handle_t *pamh, const char *path,
                            const struct stat *fs)
{
    if (fs->st_uid != 0 || (fs->st_mode & (S_IWGRP | S_IWOTH))) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: insecure permissions on %s (uid=%d mode=%04o); "
                   "must be root-owned and not group- or world-writable",
                   path, fs->st_uid, fs->st_mode & 07777);
        return -1;
    }
    return 0;
}

struct include_walk {
    pam_handle_t *pamh;
    int depth;
    size_t nseen;
    char seen[INC_MAX_FILES][INC_PATH_MAX];
};

static int validate_include(void *ctx, const char *inc_path);

static int validate_include(void *ctx, const char *inc_path) {
    struct include_walk *w = ctx;
    struct stat ist;

    if (strlen(inc_path) >= INC_PATH_MAX) {
        pam_syslog(w->pamh, LOG_ERR,
                   "authnft: include path over %d bytes: %s",
                   INC_PATH_MAX, inc_path);
        return -1;
    }
    /* Doubles as cycle detection and as a repeat-include budget: nftables
     * has no include guard, so a self-referential file would recurse until
     * the depth cap and a diamond would be read twice. */
    for (size_t i = 0; i < w->nseen; i++) {
        if (strcmp(w->seen[i], inc_path) == 0) {
            pam_syslog(w->pamh, LOG_ERR,
                       "authnft: include cycle or repeat: %s", inc_path);
            return -1;
        }
    }
    if (w->nseen >= INC_MAX_FILES) {
        pam_syslog(w->pamh, LOG_ERR,
                   "authnft: fragment pulls in more than %d files",
                   INC_MAX_FILES);
        return -1;
    }
    if (w->depth >= INC_MAX_DEPTH) {
        pam_syslog(w->pamh, LOG_ERR,
                   "authnft: include nested deeper than %d: %s",
                   INC_MAX_DEPTH, inc_path);
        return -1;
    }

    /* Same bar the top-level fragment clears. An included file had no
     * permission check at all before this. */
    if (stat(inc_path, &ist) != 0) {
        pam_syslog(w->pamh, LOG_ERR,
                   "authnft: missing include %s", inc_path);
        return -1;
    }
    if (!S_ISREG(ist.st_mode)) {
        pam_syslog(w->pamh, LOG_ERR,
                   "authnft: include %s is not a regular file", inc_path);
        return -1;
    }
    if (check_file_perms(w->pamh, inc_path, &ist) < 0 ||
        check_dir_root_only(w->pamh, inc_path) < 0)
        return -1;

    size_t ilen = 0;
    char *ibuf = read_file(inc_path, &ilen);
    if (!ibuf) {
        pam_syslog(w->pamh, LOG_ERR,
                   "authnft: could not read include %s", inc_path);
        return -1;
    }

    snprintf(w->seen[w->nseen], INC_PATH_MAX, "%s", inc_path);
    w->nseen++;
    w->depth++;
    int rc = validate_fragment_buf_ex(w->pamh, inc_path, ibuf, ilen,
                                      NFT_FRAG_INCLUDED,
                                      validate_include, w);
    w->depth--;
    free(ibuf);
    return rc;
}

/*
 * Test seam: the include walk nft_handler_setup runs, callable without a
 * PAM stack. Extern per the visibility model in include/nft_validator.h —
 * pam_authnft.map's `local: *;` keeps it out of the .so ABI, and test
 * binaries link the .o directly.
 */
int authnft_validate_fragment_includes(pam_handle_t *pamh, const char *path,
                                       const char *buf, size_t buf_len) {
    struct include_walk iw = { .pamh = pamh, .depth = 0, .nseen = 0 };
    return validate_fragment_buf_ex(pamh, path, buf, buf_len, 0,
                                    validate_include, &iw);
}


/*
 * Handle of the shared chain's ct accept rule, or 0 if it cannot be read.
 *
 * The session jump is placed immediately after this rule rather than at the
 * head of the chain. Both keep every jump ahead of a site deny appended
 * later, which is what #105 needs. Only this one leaves the
 * established-accept first: with jumps at the head, every packet of every
 * established flow walks every live session chain before reaching it, a
 * per-packet cost that grows with the number of logged-in users. Measured
 * at three sessions: each chain counted 15 packets of a single unsessioned
 * flow that the ct rule then accepted 14 times.
 */
/*
 * Scan a `list chain` output (HANDLE flag set) for the pre-gate module's
 * unconditional established-accept: the ct-state prefix with no "ct mark"
 * on the line. Returns how many lines match; fills out[] (when given)
 * with up to cap parsed rule handles.
 *
 * The handle is taken from the LAST "# handle " on the line. nft prints
 * the rule handle at end of line, after any user comment, so a comment
 * containing the literal "# handle " cannot spoof the parse — the same
 * defence as the jump-handle parse in nft_handler_setup. A line whose
 * handle does not parse to a nonzero number is counted but not filled:
 * it is still a live legacy accept, just not one this pass can delete.
 */
static size_t scan_legacy_accepts(const char *out, uint64_t *handles,
                                  size_t cap, size_t *n_fill) {
    size_t n_match = 0, fill = 0;
    const char *line = out;

    while (line && (line = strstr(line, "ct state established,related"))) {
        const char *eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);
        if (!memmem(line, len, "ct mark", 7)) {
            const char *hp = NULL, *p = line;
            size_t rem = len;
            const char *next;
            while ((next = memmem(p, rem, "# handle ", 9)) != NULL) {
                hp = next;
                rem -= (size_t)(next + 9 - p);
                p = next + 9;
            }
            n_match++;
            if (hp && handles && fill < cap) {
                uint64_t h = strtoull(hp + 9, NULL, 10);
                if (h) handles[fill++] = h;
            }
        }
        line = eol ? eol + 1 : line + len;
    }
    if (n_fill) *n_fill = fill;
    return n_match;
}

static uint64_t ct_rule_handle(struct nft_ctx *ctx) {
    nft_ctx_output_set_flags(ctx, NFT_CTX_OUTPUT_HANDLE);
    nft_ctx_buffer_output(ctx);
    int rc = nft_run_cmd_from_buffer(ctx,
        "list chain inet " TABLE_NAME " filter");
    const char *out = nft_ctx_get_output_buffer(ctx);
    uint64_t handle = 0;

    if (rc == 0 && out) {
        /* Anchor on the live arm specifically: it is the second of the two
         * gate rules, so positioning after it puts the jump after both.
         * Matching the shared ct-state prefix would find the first arm and
         * wedge every session jump between them. */
        const char *line = strstr(out, GATE_LIVE_COMMENT);
        if (!line) line = strstr(out, "ct state established,related");
        if (line) {
            /* Bound the search to this rule's line: an unhandled ct rule
             * would otherwise pick up the next rule's handle. */
            const char *eol = strchr(line, '\n');
            const char *hp = strstr(line, "# handle ");
            if (hp && (!eol || hp < eol))
                handle = strtoull(hp + 9, NULL, 10);
        }
    }
    nft_ctx_unbuffer_output(ctx);
    nft_ctx_output_set_flags(ctx, 0);
    return handle;
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

    /* Call 1 put the id in live_sessions, so a failure after it leaves the
     * element behind. Nothing carries the id, since the session never got
     * its jump rule and ids are never reused, so this is a leak rather than
     * a hole. Without it the set grows by one per failed session for the
     * life of the boot. Its own transaction: the batch below is discarded
     * wholesale when an object is missing, and bundling this in would tie
     * the element's removal to theirs. */
    if (sd->session_mark) {
        snprintf(cmd, sizeof(cmd),
                 "delete element inet %s live_sessions { 0x%08x }",
                 TABLE_NAME, sd->session_mark);
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

    /* authnft group membership was resolved by the caller in the setup child,
     * before sandbox_apply (nft_user_in_authnft_group), so no NSS backend runs
     * under the seccomp filter and its connection state dies with the child
     * rather than lingering in the sshd monitor that owns the transient scope.
     * A non-member never reaches this function. */

    /* Fragment validation: must exist, clear the permission bar, and sit
     * in a root-only directory. See check_file_perms/check_dir_root_only. */
    snprintf(user_conf_path, sizeof(user_conf_path), "%s/%s", RULES_DIR, user);
    DEBUG_PRINT("loading fragment: %s", user_conf_path);

    if (stat(user_conf_path, &st) != 0) {
        (void)pam_syslog(pamh, LOG_ERR,
                         "authnft: missing fragment for %s at %s", user, user_conf_path);
        authnft_audit_fragment_reject(user, "missing", user_conf_path);
        if (reason) *reason = AUTHNFT_REJECT_FRAGMENT_MISSING;
        return PAM_AUTH_ERR;
    }

    if (check_file_perms(pamh, user_conf_path, &st) < 0 ||
        check_dir_root_only(pamh, user_conf_path) < 0) {
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

    /* Content validation: verb scan, include path check, and the contents
     * of every file the fragment includes (see validate_include). */
    if (authnft_validate_fragment_includes(pamh, user_conf_path,
                                          frag_buf, frag_len) < 0) {
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

    /* The id is allocated by the caller, before the seccomp filter goes on:
     * the counter needs syscalls the setup allowlist does not carry. */
    if (sd->session_mark == 0) {
        pam_syslog(pamh, LOG_ERR, "authnft: no session mark for %s", user);
        free(frag_buf);
        return PAM_SESSION_ERR;
    }

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
    nft_ctx_output_set_flags(ctx, NFT_CTX_OUTPUT_HANDLE);
    nft_ctx_buffer_output(ctx);
    int probe_rc = nft_run_cmd_from_buffer(ctx,
        "list chain inet " TABLE_NAME " filter");
    const char *probe_out = nft_ctx_get_output_buffer(ctx);
    int gate_present = (probe_rc == 0 && probe_out &&
        strstr(probe_out, GATE_LIVE_COMMENT) != NULL);

    /*
     * An unconditional `ct state established,related accept` nullifies the
     * gate: the gate's arms decline a revoked flow (mark set, id not live),
     * but evaluation then continues and the unconditional rule accepts it.
     * The module shipped exactly that rule before the gate, and its
     * probe-then-add pattern raced concurrent opens the same way the
     * gate's does (above), so an upgraded host that raced can hold several
     * copies. One survivor is enough: sweep them all, not just the first.
     *
     * Matched by absence of "ct mark": the gate rules carry the same
     * ct-state prefix, so a substring test on the prefix alone would also
     * match them and delete the gate instead.
     *
     * The cap is one concurrent-open burst's worth. If a chain somehow
     * holds more, the next session open sweeps the remainder: the probe
     * runs on every open.
     */
    uint64_t legacy_handles[8];
    size_t n_legacy = 0;
    size_t n_match = scan_legacy_accepts(probe_rc == 0 ? probe_out : NULL,
                                         legacy_handles,
                                         sizeof(legacy_handles) /
                                         sizeof(legacy_handles[0]),
                                         &n_legacy);
    nft_ctx_unbuffer_output(ctx);
    nft_ctx_output_set_flags(ctx, 0);

    /*
     * The sweep is shared-chain repair, not per-session state, so it runs
     * as its own transaction and is judged by its postcondition. Two
     * concurrent opens on an upgraded host can both probe the same
     * handles; the loser's delete then fails with ENOENT. That is not a
     * failure of the postcondition — the rules are gone — so on any sweep
     * error, re-probe: if no legacy rule remains, a concurrent open swept
     * it and this open proceeds. If one remains, the gate cannot be
     * trusted and the open fails closed.
     */
    if (n_match != n_legacy) {
        /* A matching line whose handle did not parse. With the HANDLE
         * flag set libnftables always prints one, so this is unreachable
         * short of a broken library; if it happens, the rule cannot be
         * deleted and the gate cannot be trusted. Deny. */
        pam_syslog(pamh, LOG_ERR,
                   "authnft: %zu unconditional established-accept(s) with no "
                   "parseable handle; denying rather than opening a session "
                   "they would make irrevocable", n_match - n_legacy);
        free(frag_buf);
        nft_ctx_free(ctx);
        return PAM_SERVICE_ERR;
    }
    if (n_legacy) {
        char legacy_cmd[8 * 64] = "";
        size_t legacy_off = 0;
        for (size_t i = 0; i < n_legacy; i++) {
            pam_syslog(pamh, LOG_WARNING,
                       "authnft: removing an unconditional established-accept "
                       "(handle %" PRIu64 ") that would defeat session revocation",
                       legacy_handles[i]);
            int n = snprintf(legacy_cmd + legacy_off,
                             sizeof(legacy_cmd) - legacy_off,
                             "delete rule inet " TABLE_NAME " filter handle %" PRIu64 "\n",
                             legacy_handles[i]);
            if (n < 0 || (size_t)n >= sizeof(legacy_cmd) - legacy_off)
                break;
            legacy_off += (size_t)n;
        }
        if (nft_run_cmd_from_buffer(ctx, legacy_cmd) != 0) {
            nft_ctx_output_set_flags(ctx, NFT_CTX_OUTPUT_HANDLE);
            nft_ctx_buffer_output(ctx);
            int rp_rc = nft_run_cmd_from_buffer(ctx,
                "list chain inet " TABLE_NAME " filter");
            const char *rp_out = nft_ctx_get_output_buffer(ctx);
            size_t left = scan_legacy_accepts(rp_rc == 0 ? rp_out : NULL,
                                              NULL, 0, NULL);
            /* The concurrent winner's call 1 installed the gate too;
             * refresh so this open does not insert a duplicate pair. */
            gate_present = (rp_rc == 0 && rp_out &&
                strstr(rp_out, GATE_LIVE_COMMENT) != NULL);
            nft_ctx_unbuffer_output(ctx);
            nft_ctx_output_set_flags(ctx, 0);
            if (rp_rc != 0 || left > 0) {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: could not remove the unconditional "
                           "established-accept (%zu left); denying rather "
                           "than opening a session it would make "
                           "irrevocable", left);
                free(frag_buf);
                nft_ctx_free(ctx);
                return PAM_SERVICE_ERR;
            }
            pam_syslog(pamh, LOG_NOTICE,
                       "authnft: legacy established-accept already removed "
                       "by a concurrent session open");
        }
    }

    /*
     * The gate. Untagged flows accept unconditionally: that is the SSH
     * connection and everything else the module does not govern. Tagged
     * flows accept only while their id is still in live_sessions, so close
     * revoking the element revokes the flow.
     *
     * Both arms mask before comparing. Testing against a bare 0 would treat
     * any flow an administrator's own rule had marked as unsessioned and
     * hand it a free accept (I6).
     *
     * Inserted, not added. The chain can predate the gate with site rules
     * already in it: ADMIN_GUIDE has the boot loader restore the site deny
     * before the first session opens. `add` appends the gate behind that
     * deny, and the session jump positioned after the gate lands behind it
     * too, shadowing every session (the E10 arm). On a fresh chain insert
     * and add coincide. Sequential inserts stack at the head in reverse,
     * so the live arm goes first in the buffer to keep the chain reading
     * unsessioned-then-live.
     */
    const char *ct_rule_line = gate_present
        ? ""
        : "add set inet " TABLE_NAME " live_sessions { type mark; }\n"
          "insert rule inet " TABLE_NAME " filter ct state established,related "
          "ct mark and " AUTHNFT_MARK_MASK_STR " @live_sessions accept comment \""
          GATE_LIVE_COMMENT "\"\n"
          "insert rule inet " TABLE_NAME " filter ct state established,related "
          "ct mark and " AUTHNFT_MARK_MASK_STR " 0x0 accept comment \""
          GATE_UNSESSIONED_COMMENT "\"\n";

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
                  "add set inet %s live_sessions { type mark; }\n"
                  "%s"
                  "add chain inet %s %s\n"
                  "add rule inet %s %s ct state new ct mark set ct mark and "
                  AUTHNFT_MARK_ADMIN_STR " or 0x%08x\n"
                  "add element inet %s live_sessions { 0x%08x }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2; flags timeout; }\n"
                  "add element inet %s %s { \"%s\" timeout 1d comment \"%s (PID:%d)%s\" }",
                  TABLE_NAME,
                  TABLE_NAME,
                  TABLE_NAME,
                  ct_rule_line,
                  TABLE_NAME, sd->chain_name,
                  TABLE_NAME, sd->chain_name, sd->session_mark,
                  TABLE_NAME, sd->session_mark,
                  TABLE_NAME, sd->set_v4,
                  TABLE_NAME, sd->set_v6,
                  TABLE_NAME, sd->set_cg,
                  TABLE_NAME, set_name, sd->cg_path, user, session_pid, tag_part);
    } else {
        result = snprintf(cmd, sizeof(cmd),
                  "add table inet %s\n"
                  "add chain inet %s filter { type filter hook input priority filter - 1; policy accept; }\n"
                  "add set inet %s live_sessions { type mark; }\n"
                  "%s"
                  "add chain inet %s %s\n"
                  "add rule inet %s %s ct state new ct mark set ct mark and "
                  AUTHNFT_MARK_ADMIN_STR " or 0x%08x\n"
                  "add element inet %s live_sessions { 0x%08x }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2; flags timeout; }\n"
                  "add element inet %s %s { \"%s\" . %s timeout 1d comment \"%s (PID:%d)%s\" }",
                  TABLE_NAME,
                  TABLE_NAME,
                  TABLE_NAME,
                  ct_rule_line,
                  TABLE_NAME, sd->chain_name,
                  TABLE_NAME, sd->chain_name, sd->session_mark,
                  TABLE_NAME, sd->session_mark,
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
     *
     * Positioned after the ct rule, not appended. The site's default-deny
     * lives outside the module and the admin can only place it after the
     * jumps that exist when they place it. Appending put every later
     * session behind it: the session authenticated, installed
     * correct-looking rules, and passed no traffic, while an earlier
     * session on the same host kept working.
     *
     * Order among session jumps does not matter: each matches only its
     * own cgroup and source, so at most one can fire for a given packet.
     * What does matter is that the ct rule stays first, so established
     * traffic short-circuits before walking any session chain.
     *
     * Measured as E4 (appended, shadowed) against E6 (admitted), with E5
     * and E7 as controls, plus E8 for a deny that predates every session,
     * in tests/packet_flow_matrix.sh. #105.
     */
    /* Read the handle before switching the context into echo mode for call
     * 2: ct_rule_handle drives its own buffering and flags, and doing that
     * inside call 2's setup tears down the echo output the jump-handle
     * parse below depends on. */
    uint64_t cth = ct_rule_handle(ctx);

    nft_ctx_output_set_flags(ctx,
        NFT_CTX_OUTPUT_ECHO | NFT_CTX_OUTPUT_HANDLE);
    nft_ctx_buffer_output(ctx);

    if (cth) {
        snprintf(cmd, sizeof(cmd),
                 "add rule inet %s filter position %" PRIu64 " jump %s",
                 TABLE_NAME, cth, sd->chain_name);
    } else {
        /* Fall back to the head of the chain. Still ahead of any site deny,
         * so #105 stays fixed; it only costs the established fast path. A
         * slower correct order beats a denied login. */
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: could not read the ct rule handle; placing the "
                   "jump at the head of the shared chain");
        snprintf(cmd, sizeof(cmd),
                 "insert rule inet %s filter jump %s",
                 TABLE_NAME, sd->chain_name);
    }

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
     * Revocation first, in its own transaction. This is the only part of
     * close that affects traffic already flowing: dropping the id from
     * live_sessions makes the gate stop accepting the session's established
     * flows on their next packet. Everything below is housekeeping, and
     * bundling the two would mean a housekeeping failure leaves the flows
     * admitted. Skipped when no id was allocated, because deleting an
     * absent element fails the whole transaction.
     */
    if (sd->session_mark) {
        char revoke[128];
        snprintf(revoke, sizeof(revoke),
                 "delete element inet %s live_sessions { 0x%08x }",
                 TABLE_NAME, sd->session_mark);
        if (nft_run_cmd_from_buffer(ctx, revoke) != 0) {
            pam_syslog(pamh, LOG_WARNING,
                       "authnft: could not revoke session mark 0x%08x for %s: "
                       "%s", sd->session_mark, user,
                       nft_ctx_get_error_buffer(ctx));
        } else {
            DEBUG_PRINT("revoked session mark 0x%08x", sd->session_mark);
        }
    }

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
