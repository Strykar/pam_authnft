// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Pure input-validation surface of the nft handler. Three functions
 * extracted from src/nft_handler.c so they can be unit-tested and
 * mutation-tested in isolation. See include/nft_validator.h for the
 * visibility model.
 */

#include "authnft.h"
#include "nft_validator.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* Rejection list. `destroy` covers the same surface as `delete` (TABLE/
 * CHAIN/RULE/SET/MAP/ELEMENT/FLOWTABLE/COUNTER/QUOTA/CT/LIMIT/SECMARK/
 * SYNPROXY/TUNNEL — see nftables parser_bison.y) but with cmd_alloc
 * (CMD_DESTROY) semantics that tolerate ENOENT silently. Without it, a
 * fragment could bypass the `delete` block via `destroy table inet
 * authnft`. Convention for enumerated rejection lists: array + count,
 * both extern, declared together in the header. */
const char *const nft_validator_bad_verbs[] = {
    "flush", "delete", "destroy", "reset", "list", "rename",
    "insert", "replace", "monitor"
};
const size_t nft_validator_bad_verbs_count =
    sizeof(nft_validator_bad_verbs) / sizeof(nft_validator_bad_verbs[0]);

/*
 * Fragment content validation against a pre-read buffer. Walks the
 * buffer by '\n' to avoid buffer-boundary verb truncation, then rejects:
 *   - Disallowed verbs from nft_validator_bad_verbs[]
 *   - 'add rule inet authnft filter ...' targeting the shared filter
 *     chain; fragments must target the per-session chain via
 *     @session_chain
 *   - include paths outside /etc/authnft/, relative paths, '..'
 *     segments, glob characters
 *
 * Trust model: fragments are admin-authored (root-owned, not
 * world-writable; checked by stat(2) earlier). This validator is
 * defense-in-depth and a typo-catcher; it is NOT a sandbox for
 * untrusted input. See docs/INTEGRATIONS.txt §4.
 */
int validate_fragment_buf(pam_handle_t *pamh, const char *path,
                          const char *buf, size_t buf_len)
{
    static const char shared_chain_prefix[] =
        "add rule inet " TABLE_NAME " filter";
    static const size_t shared_chain_prefix_len =
        sizeof(shared_chain_prefix) - 1;

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
        for (size_t i = 0; i < nft_validator_bad_verbs_count; i++) {
            size_t vlen = strlen(nft_validator_bad_verbs[i]);
            if (tlen >= vlen &&
                memcmp(t, nft_validator_bad_verbs[i], vlen) == 0 &&
                (tlen == vlen || t[vlen] == ' ' || t[vlen] == '\t')) {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: fragment %s:%d uses disallowed verb '%s'",
                           path, lineno, nft_validator_bad_verbs[i]);
                rc = -1;
                goto out;
            }
        }

        /* Reject 'add rule inet authnft filter ...' — fragments must
         * target the per-session chain via @session_chain. The shared
         * filter chain is owned by pam_authnft; any rule a fragment
         * installs there persists across sessions and affects every
         * other session. */
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

        /* include path validation: absolute, under /etc/authnft/, no
         * '..', no glob characters. */
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
char *substitute_placeholders(const char *src, size_t src_len,
                              const char *placeholders[4],
                              const char *replacements[4])
{
    /* Worst case: src is entirely back-to-back occurrences of whichever
     * placeholder has the largest replacement-to-placeholder length
     * ratio. The previous src_len*2 bound was wrong: @session_v4 (11
     * bytes) maps to a set-name up to SET_NAME_MAX+1 bytes (81), a
     * ~7.4x expansion, so a fragment full of @session_v4 would fail
     * the wi+rlen guard below even though it was perfectly valid.
     *
     * Use ceil(max_rep_len / min_ph_len) as the per-byte expansion
     * bound. Slightly loose (mixes the worst rep_len with the worst
     * ph_len from possibly different placeholders) but always safe
     * and avoids a per-pair fraction comparison. */
    size_t max_rep_len = 0;
    size_t min_ph_len = SIZE_MAX;
    for (size_t k = 0; k < 4; k++) {
        size_t plen = strlen(placeholders[k]);
        size_t rlen = strlen(replacements[k]);
        if (plen == 0) return NULL;
        if (rlen > max_rep_len) max_rep_len = rlen;
        if (plen < min_ph_len) min_ph_len = plen;
    }
    size_t ratio = (max_rep_len + min_ph_len - 1) / min_ph_len;
    if (ratio < 1) ratio = 1;
    if (src_len > (SIZE_MAX - 1) / ratio) return NULL;
    size_t max_expand = src_len * ratio + 1;
    char *out = malloc(max_expand);
    if (!out) return NULL;

    size_t wi = 0;
    int in_comment = 0;
    int in_quote = 0;

    size_t i = 0;
    while (i < src_len) {
        char c = src[i];

        /* Reset both in_comment and in_quote at line boundaries.
         * nftables does not support multi-line "..." string literals
         * in fragments, so treating quoting as line-local is correct.
         * The earlier line-aware reset for in_comment but not
         * in_quote meant an unterminated " on one line silently
         * disabled placeholder substitution for the rest of the file
         * — a confusing failure mode. The fragment then fails
         * libnftables syntax check (because @session_v4 etc. are
         * unsubstituted), which is fail-safe but hides the cause. */
        if (c == '\n') { in_comment = 0; in_quote = 0; }
        if (!in_quote && c == '#') { in_comment = 1; }
        if (!in_comment && c == '"') { in_quote = !in_quote; }

        if (in_comment || in_quote) {
            /* Same bound check as the unmatched path below: leave
             * room for the trailing '\0'. A long quoted string or
             * comment after a placeholder expansion could otherwise
             * overrun. */
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
                /* Token boundary: next char must not be identifier. */
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
             * trailing '\0' written after the loop. Without this
             * guard, a placeholder expansion that pushes wi to
             * max_expand-1 followed by an unmatched byte advances
             * wi to max_expand, causing the terminator to write
             * one past the buffer. */
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
 * Membership predicate over getgrouplist(3) output. Extracted from
 * the inline loop in nft_handler_setup so the SSSD-naive regression
 * (closed by the switch from grp->gr_mem walk to getgrouplist) has
 * a standalone test surface.
 *
 * Pure: no I/O, no NSS calls. The NSS resolution stays in the
 * caller; this function asks only "is `target` in the list?"
 */
bool user_in_group(gid_t target, const gid_t *groups, size_t ngroups)
{
    if (!groups) return false;
    for (size_t i = 0; i < ngroups; i++) {
        if (groups[i] == target) return true;
    }
    return false;
}
