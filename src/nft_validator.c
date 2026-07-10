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

/* Whitespace inside a fragment statement. Newline and CR count too, so a
 * multi-line "{ ... }" block tokenizes as one statement. */
static int is_frag_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* Copy the next whitespace-delimited token from [*pp, end) into tok
 * (NUL-terminated, truncated to cap). A token that opens with '"' runs to
 * the matching close quote so a quoted include path with embedded spaces
 * stays one token. Advances *pp past the token. Returns the token's true
 * length (which may exceed cap-1 if truncated), or 0 if none remain. */
static size_t next_token(const char **pp, const char *end,
                         char *tok, size_t cap)
{
    const char *p = *pp;
    while (p < end && is_frag_ws(*p)) p++;
    if (p >= end) { if (cap) tok[0] = '\0'; *pp = p; return 0; }

    const char *ts = p;
    if (*p == '"') {
        p++;                                  /* opening quote */
        while (p < end && *p != '"') p++;
        if (p < end) p++;                     /* closing quote */
    } else {
        while (p < end && !is_frag_ws(*p)) p++;
    }
    size_t len = (size_t)(p - ts);
    *pp = p;

    size_t n = (cap && len < cap - 1) ? len : (cap ? cap - 1 : 0);
    if (cap) { memcpy(tok, ts, n); tok[n] = '\0'; }
    return len;
}

/* Validate one nftables statement [s, e). Rejects (returns -1):
 *   - a disallowed leading verb from nft_validator_bad_verbs[]
 *   - "add rule inet authnft filter ..." (the shared chain; fragments must
 *     target the per-session chain via @session_chain)
 *   - an include path that is relative, outside /etc/authnft/, or carries a
 *     '..' segment or a glob character
 * Matching is token-based, so extra or non-canonical whitespace between
 * keywords does not evade the shared-chain guard. Returns 0 on accept. */
static int check_statement(pam_handle_t *pamh, const char *path, int lineno,
                           const char *s, const char *e)
{
    const char *p = s;
    char t0[32];
    if (next_token(&p, e, t0, sizeof(t0)) == 0)
        return 0;  /* whitespace/comment-only statement */

    for (size_t i = 0; i < nft_validator_bad_verbs_count; i++) {
        if (strcmp(t0, nft_validator_bad_verbs[i]) == 0) {
            pam_syslog(pamh, LOG_ERR,
                       "authnft: fragment %s:%d uses disallowed verb '%s'",
                       path, lineno, nft_validator_bad_verbs[i]);
            return -1;
        }
    }

    /* Shared-chain guard: reject "add rule inet authnft filter ...". Rules a
     * fragment installs there persist across sessions and affect every other
     * session; per-session rules must go through @session_chain. */
    if (strcmp(t0, "add") == 0) {
        static const char *const shared[5] =
            { "add", "rule", "inet", TABLE_NAME, "filter" };
        const char *q = s;
        char tk[64];
        int match = 1;
        for (int k = 0; k < 5; k++) {
            if (next_token(&q, e, tk, sizeof(tk)) == 0 ||
                strcmp(tk, shared[k]) != 0) {
                match = 0;
                break;
            }
        }
        if (match) {
            pam_syslog(pamh, LOG_ERR,
                       "authnft: fragment %s:%d targets shared 'filter' chain; "
                       "fragments must target the per-session chain via the "
                       "@session_chain placeholder", path, lineno);
            return -1;
        }
    }

    /* include path validation: absolute, under /etc/authnft/, no '..', no
     * glob characters. */
    if (strcmp(t0, "include") == 0) {
        char raw[512];
        size_t rl = next_token(&p, e, raw, sizeof(raw));
        if (rl == 0 || rl >= sizeof(raw)) {
            pam_syslog(pamh, LOG_ERR,
                       "authnft: fragment %s:%d has a missing or over-long "
                       "include path", path, lineno);
            return -1;
        }
        char *ps = raw;
        size_t plen = strlen(ps);
        if (plen && ps[0] == '"') {          /* strip surrounding quotes */
            ps++; plen--;
            if (plen && ps[plen - 1] == '"') { ps[plen - 1] = '\0'; plen--; }
        }
        if (plen == 0 || ps[0] != '/') {
            pam_syslog(pamh, LOG_ERR,
                       "authnft: fragment %s:%d uses relative include path",
                       path, lineno);
            return -1;
        }
        if (plen < 13 || memcmp(ps, "/etc/authnft/", 13) != 0) {
            pam_syslog(pamh, LOG_ERR,
                       "authnft: fragment %s:%d includes path outside "
                       "/etc/authnft/", path, lineno);
            return -1;
        }
        for (size_t g = 0; g + 1 < plen; g++) {
            if (ps[g] == '.' && ps[g + 1] == '.' &&
                (g == 0 || ps[g - 1] == '/') &&
                (g + 2 >= plen || ps[g + 2] == '/')) {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: fragment %s:%d include path contains "
                           "'..' segment", path, lineno);
                return -1;
            }
        }
        for (size_t g = 0; g < plen; g++) {
            if (ps[g] == '*' || ps[g] == '?' || ps[g] == '[') {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: fragment %s:%d include path contains "
                           "glob character '%c'", path, lineno, ps[g]);
                return -1;
            }
        }
    }

    return 0;
}

/*
 * Fragment content validation against a pre-read buffer.
 *
 * nftables separates commands by BOTH newline and ';', so a first-token
 * scan of each '\n'-delimited line misses a disallowed verb hidden after a
 * ';' ("add table x; flush ruleset"). This walks the buffer as a stream of
 * statements split on ';' or '\n' at brace-depth 0, tracking "..." quotes
 * and '#' comments so a separator inside either is not a split point, then
 * checks each statement's leading verb, shared-chain target, and include
 * path (see check_statement). Token-based matching also defeats
 * non-canonical whitespace ("add  rule inet authnft filter").
 *
 * Trust model: fragments are admin-authored (root-owned, not
 * world-writable; checked by stat(2) earlier). This validator is
 * defense-in-depth and a typo-catcher; it is NOT a sandbox for untrusted
 * input. See docs/INTEGRATIONS.txt §4.
 */
int validate_fragment_buf(pam_handle_t *pamh, const char *path,
                          const char *buf, size_t buf_len)
{
    const char *end = buf + buf_len;
    const char *stmt = buf;      /* start of the current statement */
    int lineno = 1;
    int stmt_lineno = 1;         /* line the current statement started on */
    int in_quote = 0, in_comment = 0, depth = 0, has_content = 0;

    for (const char *p = buf; p < end; p++) {
        char c = *p;
        int is_sep = 0;

        if (in_comment) {
            if (c == '\n') { in_comment = 0; is_sep = (depth == 0); }
        } else if (in_quote) {
            /* nftables has no multi-line string literals; a newline closes
             * an unterminated quote and separates the statement. */
            if (c == '"') in_quote = 0;
            else if (c == '\n') { in_quote = 0; is_sep = (depth == 0); }
        } else if (c == '#') {
            in_comment = 1;
        } else if (c == '"') {
            in_quote = 1; has_content = 1;
        } else if (c == '{') {
            depth++; has_content = 1;
        } else if (c == '}') {
            if (depth > 0) depth--;
            has_content = 1;
        } else if ((c == ';' || c == '\n') && depth == 0) {
            is_sep = 1;
        } else if (!is_frag_ws(c)) {
            has_content = 1;
        }

        if (is_sep) {
            if (has_content &&
                check_statement(pamh, path, stmt_lineno, stmt, p) < 0)
                return -1;
            stmt = p + 1;
            has_content = 0;
            stmt_lineno = lineno + (c == '\n' ? 1 : 0);
        }
        if (c == '\n') lineno++;
    }

    /* Final statement: no trailing separator, or an unbalanced '{' that
     * never closed. Check it regardless of depth so a trailing bad verb
     * cannot hide behind a missing '}'. */
    if (!in_comment && has_content &&
        check_statement(pamh, path, stmt_lineno, stmt, end) < 0)
        return -1;

    return 0;
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
