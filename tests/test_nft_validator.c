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
