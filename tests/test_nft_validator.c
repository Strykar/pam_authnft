/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2025 Avinash H. Duduskar
 *
 * Unit tests for the pure decision surfaces extracted from
 * src/nft_handler.c into src/nft_validator.c.
 *
 * Two test-design patterns coexist here, by intent:
 *
 *   - Per-entry explicit tests for nft_validator_bad_verbs[] (one
 *     hand-written assert per literal). Gives mull mutation density:
 *     each literal is a distinct death-point for a mutant that
 *     deletes or rewrites the rejection branch for that verb.
 *
 *   - Structural enumeration test that iterates nft_validator_bad_verbs[]
 *     at test time and asserts every entry is rejected. Guards
 *     against an array-shape regression that the explicit tests
 *     would miss if someone removed both the verb entry and its
 *     corresponding explicit test in the same commit.
 *
 * Both patterns are required. Removing either leaves a class of
 * regression undefended.
 *
 * The substitute_placeholders overflow tests are coupled to ASan:
 * an under-allocation mutant (mull mutating the max_expand math)
 * survives a unit test that only checks NULL-vs-non-NULL. The test
 * binary must therefore be built with -fsanitize=address; that's
 * the validator-mutation workflow's single-job design — see
 * docs/MUTATION_ASAN_EXPERIMENT.md.
 */

#include "nft_validator.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define FAIL(fmt, ...) do { \
    fprintf(stderr, "[FAIL] %s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__); \
    failures++; \
} while (0)

#define EXPECT(cond) do { \
    if (!(cond)) FAIL("expected: %s", #cond); \
} while (0)

#define EXPECT_EQ_INT(actual, expected) do { \
    int _a = (actual), _e = (expected); \
    if (_a != _e) FAIL("expected %d, got %d", _e, _a); \
} while (0)

/* -------------------------------------------------------------------- */
/* validate_fragment_buf — disallowed verbs                              */
/* -------------------------------------------------------------------- */

static int reject_verb(const char *verb)
{
    char line[128];
    snprintf(line, sizeof(line), "%s table inet authnft\n", verb);
    return validate_fragment_buf(NULL, "test.nft", line, strlen(line));
}

#define EXPECT_VERB_REJECTED(VERB) do { \
    int rc = reject_verb(VERB); \
    if (rc != -1) FAIL("verb '%s' was not rejected (rc=%d)", VERB, rc); \
} while (0)

static void test_bad_verbs_explicit(void)
{
    /* One hand-written assertion per literal entry in
     * nft_validator_bad_verbs[]. Maximises mull mutation density:
     * each verb literal is its own death-point. */
    EXPECT_VERB_REJECTED("flush");
    EXPECT_VERB_REJECTED("delete");
    EXPECT_VERB_REJECTED("destroy");
    EXPECT_VERB_REJECTED("reset");
    EXPECT_VERB_REJECTED("list");
    EXPECT_VERB_REJECTED("rename");
    EXPECT_VERB_REJECTED("insert");
    EXPECT_VERB_REJECTED("replace");
    EXPECT_VERB_REJECTED("monitor");
}

static void test_bad_verbs_structural(void)
{
    /* Iterate the array at test time. Catches array-shape regressions
     * that pair with same-commit deletion of an explicit test. The
     * companion `_count` is the canonical length; sentinel terminations
     * are rejected as a convention because they couple array shape to
     * iteration pattern. */
    EXPECT(nft_validator_bad_verbs_count >= 9);
    for (size_t i = 0; i < nft_validator_bad_verbs_count; i++) {
        const char *verb = nft_validator_bad_verbs[i];
        EXPECT(verb != NULL);
        int rc = reject_verb(verb);
        if (rc != -1)
            FAIL("array entry [%zu] = '%s' not rejected (rc=%d)",
                 i, verb, rc);
    }
}

static void test_bad_verbs_word_boundary(void)
{
    /* 'flushy' must NOT match 'flush' — verb match requires a word
     * boundary (space/tab/end-of-line) on the byte after the literal. */
    const char *line = "flushy table inet authnft\n";
    int rc = validate_fragment_buf(NULL, "test.nft", line, strlen(line));
    EXPECT_EQ_INT(rc, 0);
}

/* -------------------------------------------------------------------- */
/* validate_fragment_buf — other rejections                              */
/* -------------------------------------------------------------------- */

static void test_shared_chain_rejected(void)
{
    const char *line =
        "add rule inet authnft filter ip saddr 1.2.3.4 accept\n";
    int rc = validate_fragment_buf(NULL, "test.nft", line, strlen(line));
    EXPECT_EQ_INT(rc, -1);
}

static void test_include_path_traversal(void)
{
    const char *cases[] = {
        "include \"relative/path\"\n",
        "include \"/etc/passwd\"\n",
        "include \"/etc/authnft/../passwd\"\n",
        "include \"/etc/authnft/*.nft\"\n",
        "include \"/etc/authnft/?.nft\"\n",
        "include \"/etc/authnft/[abc].nft\"\n",
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        int rc = validate_fragment_buf(NULL, "test.nft",
                                       cases[i], strlen(cases[i]));
        if (rc != -1)
            FAIL("include case [%zu] '%s' not rejected", i, cases[i]);
    }
}

static void test_include_path_accepted(void)
{
    const char *line = "include \"/etc/authnft/rules.nft\"\n";
    int rc = validate_fragment_buf(NULL, "test.nft", line, strlen(line));
    EXPECT_EQ_INT(rc, 0);
}

static void test_empty_and_comment_lines(void)
{
    const char *line = "\n# comment\n\n  # indented comment\n\n";
    int rc = validate_fragment_buf(NULL, "test.nft", line, strlen(line));
    EXPECT_EQ_INT(rc, 0);
}

/* nftables separates commands by ';' as well as newline; a bad verb or a
 * shared-chain target hidden after a ';' must still be rejected. */
static void test_semicolon_separated_bad_verb(void)
{
    const char *cases[] = {
        "add table inet authnft; flush ruleset\n",
        "add table inet authnft ; delete table inet authnft\n",
        "add rule inet authnft @session_chain accept; include \"/etc/passwd\"\n",
        "add rule inet authnft @session_chain accept; add rule inet authnft filter accept\n",
        "flush ruleset {",          /* unbalanced brace must not hide the verb */
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        int rc = validate_fragment_buf(NULL, "test.nft",
                                       cases[i], strlen(cases[i]));
        if (rc != -1)
            FAIL("';'-hidden case [%zu] '%s' not rejected", i, cases[i]);
    }
}

/* A bad verb on the last line hidden behind a trailing '#' comment with no
 * closing newline must still be rejected. The buffer ends with in_comment
 * set; the final-statement check must not skip on that (regression: the
 * `!in_comment` guard let `flush ruleset # x` through with no trailing \n). */
static void test_trailing_comment_bad_verb(void)
{
    const char *cases[] = {
        "flush ruleset # wipe",                 /* no trailing newline */
        "add table inet t; flush ruleset # x",  /* ';'-split, then comment */
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        int rc = validate_fragment_buf(NULL, "test.nft",
                                       cases[i], strlen(cases[i]));
        if (rc != -1)
            FAIL("trailing-comment case [%zu] '%s' not rejected", i, cases[i]);
    }
}

/* Non-canonical whitespace between keywords must not evade the
 * shared-chain guard (token-based match, not fixed-string memcmp). */
static void test_shared_chain_whitespace(void)
{
    const char *cases[] = {
        "add  rule inet authnft filter accept\n",
        "add\trule\tinet\tauthnft\tfilter accept\n",
        "  add rule   inet   authnft   filter drop\n",
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        int rc = validate_fragment_buf(NULL, "test.nft",
                                       cases[i], strlen(cases[i]));
        if (rc != -1)
            FAIL("whitespace shared-chain case [%zu] '%s' not rejected",
                 i, cases[i]);
    }
}

/* Legitimate fragments must still pass: ';'-joined per-session rules, an
 * anonymous set with '{ }', and a ';' inside a brace block (a set-definition
 * property separator at depth > 0, not a top-level command boundary). */
static void test_legit_multi_statement_accepted(void)
{
    const char *cases[] = {
        "add rule inet authnft @session_chain accept; "
            "add rule inet authnft @session_chain drop\n",
        "add rule inet authnft @session_chain tcp dport { 22, 80, 443 } accept\n",
        "add rule inet authnft @session_chain ip saddr @session_v4 accept ; "
            "add rule inet authnft @session_chain ip6 saddr @session_v6 accept\n",
        /* ';' inside '{ }' is at depth 1, so it must not split the statement
         * (else "flags timeout" / "}" would be checked as bare statements). */
        "add set inet authnft mine { typeof ip saddr; flags timeout; }\n",
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        int rc = validate_fragment_buf(NULL, "test.nft",
                                       cases[i], strlen(cases[i]));
        if (rc != 0)
            FAIL("legit case [%zu] '%s' wrongly rejected (rc=%d)",
                 i, cases[i], rc);
    }
}

/* -------------------------------------------------------------------- */
/* validate_fragment_buf_ex — include reporting and the included flag    */
/* -------------------------------------------------------------------- */

/* Collector standing in for nft_handler.c's validate_include, minus the
 * filesystem. Keeps these tests pure, which is the whole reason include
 * resolution lives in the caller and not in the validator. */
struct seen_includes {
    int n;
    char path[8][256];
    int reject_at;   /* -1 to accept everything */
};

static int collect_include(void *ctx, const char *inc_path)
{
    struct seen_includes *s = ctx;
    if (s->n < 8)
        snprintf(s->path[s->n], sizeof(s->path[0]), "%s", inc_path);
    s->n++;
    return (s->reject_at >= 0 && s->n > s->reject_at) ? -1 : 0;
}

static void test_include_paths_reported(void)
{
    struct seen_includes s = { .n = 0, .reject_at = -1 };
    const char *frag =
        "include \"/etc/authnft/groups/a.nft\"\n"
        "add rule inet authnft @session_chain accept\n"
        "include \"/etc/authnft/groups/b.nft\"\n";
    int rc = validate_fragment_buf_ex(NULL, "test.nft", frag, strlen(frag),
                                      0, collect_include, &s);
    EXPECT_EQ_INT(rc, 0);
    EXPECT_EQ_INT(s.n, 2);
    /* Quotes must be stripped, or the caller stats a path that cannot exist. */
    EXPECT(strcmp(s.path[0], "/etc/authnft/groups/a.nft") == 0);
    EXPECT(strcmp(s.path[1], "/etc/authnft/groups/b.nft") == 0);
}

static void test_include_callback_rejection_propagates(void)
{
    /* A callback that refuses must fail the whole fragment. This is how a
     * bad verb inside an included file reaches the caller as PAM_AUTH_ERR. */
    struct seen_includes s = { .n = 0, .reject_at = 0 };
    const char *frag = "include \"/etc/authnft/groups/a.nft\"\n";
    int rc = validate_fragment_buf_ex(NULL, "test.nft", frag, strlen(frag),
                                      0, collect_include, &s);
    EXPECT_EQ_INT(rc, -1);
}

static void test_included_flag_relaxes_shared_chain_only(void)
{
    /* INTEGRATIONS.txt 4.6 makes the shared chain an included file's
     * documented target, so it must be accepted there... */
    const char *shared = "add rule inet authnft filter tcp dport 22 accept\n";
    EXPECT_EQ_INT(validate_fragment_buf_ex(NULL, "inc.nft", shared,
                                           strlen(shared),
                                           NFT_FRAG_INCLUDED, NULL, NULL), 0);
    /* ...and rejected in a top-level fragment, as before. */
    EXPECT_EQ_INT(validate_fragment_buf_ex(NULL, "top.nft", shared,
                                           strlen(shared),
                                           0, NULL, NULL), -1);
}

static void test_included_flag_still_rejects_bad_verbs(void)
{
    /* The bug in #108: an included file ran with no verb check at all.
     * Relaxing the shared-chain guard must not relax this. */
    for (size_t i = 0; i < nft_validator_bad_verbs_count; i++) {
        char line[128];
        snprintf(line, sizeof(line), "%s ruleset\n", nft_validator_bad_verbs[i]);
        int rc = validate_fragment_buf_ex(NULL, "inc.nft", line, strlen(line),
                                          NFT_FRAG_INCLUDED, NULL, NULL);
        if (rc != -1)
            FAIL("verb '%s' accepted inside an included file (rc=%d)",
                 nft_validator_bad_verbs[i], rc);
    }
}

static void test_include_path_rules_apply_when_included(void)
{
    /* An include reached through an include is still path-checked, or the
     * /etc/authnft/ confinement ends one level down. */
    const char *escape = "include \"/tmp/evil.nft\"\n";
    EXPECT_EQ_INT(validate_fragment_buf_ex(NULL, "inc.nft", escape,
                                           strlen(escape),
                                           NFT_FRAG_INCLUDED, NULL, NULL), -1);
}

static void test_validate_fragment_buf_unchanged(void)
{
    /* The old entry point must behave exactly as before: includes are
     * path-checked, not followed, and nothing is reported. */
    const char *frag = "include \"/etc/authnft/groups/a.nft\"\n";
    EXPECT_EQ_INT(validate_fragment_buf(NULL, "test.nft", frag,
                                        strlen(frag)), 0);
}

/* -------------------------------------------------------------------- */
/* substitute_placeholders — ASan-coupled overflow tests                 */
/* -------------------------------------------------------------------- */

static const char *PLACEHOLDERS[4] = {
    "@session_v4", "@session_v6", "@session_cg", "@session_chain"
};

static void test_substitute_basic(void)
{
    const char *reps[4] = { "v4_set", "v6_set", "cg_set", "chain_x" };
    const char *src = "add element inet authnft @session_v4 { ... }";
    char *out = substitute_placeholders(src, strlen(src), PLACEHOLDERS, reps);
    EXPECT(out != NULL);
    if (out) {
        EXPECT(strstr(out, "v4_set") != NULL);
        EXPECT(strstr(out, "@session_v4") == NULL);
        free(out);
    }
}

static void test_substitute_token_boundary(void)
{
    /* @session_v4x must NOT be substituted — partial-match
     * suppression via identifier-class lookahead. */
    const char *reps[4] = { "v4_set", "v6_set", "cg_set", "chain_x" };
    const char *src = "garbage @session_v4x more";
    char *out = substitute_placeholders(src, strlen(src), PLACEHOLDERS, reps);
    EXPECT(out != NULL);
    if (out) {
        EXPECT(strstr(out, "@session_v4x") != NULL);
        EXPECT(strstr(out, "v4_set") == NULL);
        free(out);
    }
}

static void test_substitute_in_comment(void)
{
    const char *reps[4] = { "v4_set", "v6_set", "cg_set", "chain_x" };
    const char *src = "# @session_v4 in comment\nadd @session_v4 rule\n";
    char *out = substitute_placeholders(src, strlen(src), PLACEHOLDERS, reps);
    EXPECT(out != NULL);
    if (out) {
        EXPECT(strstr(out, "# @session_v4 in comment") != NULL);
        EXPECT(strstr(out, "add v4_set rule") != NULL);
        free(out);
    }
}

static void test_substitute_in_quote(void)
{
    const char *reps[4] = { "v4_set", "v6_set", "cg_set", "chain_x" };
    const char *src = "literal \"@session_v4 quoted\" then @session_v4";
    char *out = substitute_placeholders(src, strlen(src), PLACEHOLDERS, reps);
    EXPECT(out != NULL);
    if (out) {
        EXPECT(strstr(out, "\"@session_v4 quoted\"") != NULL);
        /* The second @session_v4 outside the quote should be replaced. */
        EXPECT(strstr(out, "then v4_set") != NULL);
        free(out);
    }
}

static void test_substitute_overflow_boundary(void)
{
    /* Construct an input dense with placeholders mapping to long
     * replacements. With the correct max_expand math, the output is
     * within bounds. A mull mutation that shrinks the bound by even
     * one byte causes an under-allocated malloc; the subsequent
     * memcpy writes past the buffer, which -fsanitize=address
     * catches as heap-buffer-overflow. Without ASan, this test
     * passes whether the math is right or wrong. */
    char longrep[81];
    memset(longrep, 'x', sizeof(longrep) - 1);
    longrep[sizeof(longrep) - 1] = '\0';
    const char *reps[4] = { longrep, "v6", "cg", "chain" };

    /* 128 @session_v4 occurrences = the worst-case ratio path. */
    char src[128 * 12];
    size_t pos = 0;
    for (int i = 0; i < 128; i++) {
        memcpy(src + pos, "@session_v4 ", 12);
        pos += 12;
    }

    char *out = substitute_placeholders(src, pos, PLACEHOLDERS, reps);
    EXPECT(out != NULL);
    if (out) {
        /* Spot-check: the output begins with the long replacement. */
        EXPECT(strncmp(out, longrep, 80) == 0);
        free(out);
    }
}

static void test_substitute_empty(void)
{
    const char *reps[4] = { "v4", "v6", "cg", "chain" };
    char *out = substitute_placeholders("", 0, PLACEHOLDERS, reps);
    EXPECT(out != NULL);
    if (out) {
        EXPECT_EQ_INT((int)strlen(out), 0);
        free(out);
    }
}

static void test_substitute_empty_placeholder_rejected(void)
{
    /* A zero-length placeholder is invalid input; the function
     * returns NULL rather than entering an infinite-match loop. */
    const char *bad_ph[4] = { "", "@session_v6", "@session_cg", "@session_chain" };
    const char *reps[4]   = { "v4", "v6", "cg", "chain" };
    char *out = substitute_placeholders("anything", 8, bad_ph, reps);
    EXPECT(out == NULL);
}

/* -------------------------------------------------------------------- */
/* user_in_group                                                         */
/* -------------------------------------------------------------------- */

static void test_user_in_group_present_at_front(void)
{
    gid_t groups[] = { 100, 200, 300 };
    EXPECT(user_in_group(100, groups, 3) == true);
}

static void test_user_in_group_present_at_end(void)
{
    gid_t groups[] = { 100, 200, 300 };
    EXPECT(user_in_group(300, groups, 3) == true);
}

static void test_user_in_group_present_in_middle(void)
{
    gid_t groups[] = { 100, 200, 300 };
    EXPECT(user_in_group(200, groups, 3) == true);
}

static void test_user_in_group_absent(void)
{
    gid_t groups[] = { 100, 200, 300 };
    EXPECT(user_in_group(999, groups, 3) == false);
}

static void test_user_in_group_empty(void)
{
    gid_t groups[] = { 0 };
    EXPECT(user_in_group(100, groups, 0) == false);
}

static void test_user_in_group_null_groups(void)
{
    EXPECT(user_in_group(100, NULL, 0) == false);
}

/* -------------------------------------------------------------------- */
/* main                                                                  */
/* -------------------------------------------------------------------- */

int main(void)
{
    test_bad_verbs_explicit();
    test_bad_verbs_structural();
    test_bad_verbs_word_boundary();
    test_shared_chain_rejected();
    test_include_path_traversal();
    test_include_path_accepted();
    test_empty_and_comment_lines();
    test_semicolon_separated_bad_verb();
    test_trailing_comment_bad_verb();
    test_shared_chain_whitespace();
    test_legit_multi_statement_accepted();

    test_include_paths_reported();
    test_include_callback_rejection_propagates();
    test_included_flag_relaxes_shared_chain_only();
    test_included_flag_still_rejects_bad_verbs();
    test_include_path_rules_apply_when_included();
    test_validate_fragment_buf_unchanged();

    test_substitute_basic();
    test_substitute_token_boundary();
    test_substitute_in_comment();
    test_substitute_in_quote();
    test_substitute_overflow_boundary();
    test_substitute_empty();
    test_substitute_empty_placeholder_rejected();

    test_user_in_group_present_at_front();
    test_user_in_group_present_at_end();
    test_user_in_group_present_in_middle();
    test_user_in_group_absent();
    test_user_in_group_empty();
    test_user_in_group_null_groups();

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("nft_validator: all tests passed\n");
    return 0;
}
