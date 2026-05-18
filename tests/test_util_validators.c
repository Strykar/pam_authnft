/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2025 Avinash H. Duduskar
 *
 * Unit tests for the pure decision surfaces in src/util_validators.c.
 *
 * Pattern inheritance from #49 (nft_validator PR):
 *
 *   - Built with -fsanitize=address,undefined per #49's one-binary
 *     ASan+mull compose precedent (docs/MUTATION_ASAN_EXPERIMENT.md).
 *
 *   - util_normalize_ip's overflow-boundary test follows the same
 *     pattern as substitute_placeholders's in test_nft_validator.c:
 *     plant an output buffer of exactly the size the function should
 *     reject, confirm the function rejects, and rely on ASan to catch
 *     any boundary mutation (>= → >) that lets the rejection slip.
 *     Convention: test the rejection-on-insufficient-size path with
 *     the exact buffer size that exercises the boundary check.
 *
 *   - The structural+explicit-list pattern from #49 does NOT apply
 *     here. None of the three util functions has an enumerated
 *     rejection list (util_is_valid_username rejects via character-
 *     class predicate; util_normalize_ip rejects via parser failure;
 *     validate_cgroup_path rejects via positional invariant). The
 *     pattern is conditional on the function shape, not universal.
 *     Cargo-culting it here would generate tests without
 *     corresponding death-points for mull to find.
 */

#include "util_validators.h"
#include "authnft.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef CGROUP_PATH_MAX
#define CGROUP_PATH_MAX 256
#endif

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

#define EXPECT_EQ_STR(actual, expected) do { \
    const char *_a = (actual), *_e = (expected); \
    if (strcmp(_a, _e) != 0) FAIL("expected '%s', got '%s'", _e, _a); \
} while (0)

/* -------------------------------------------------------------------- */
/* util_is_valid_username                                                */
/* -------------------------------------------------------------------- */

static void test_username_accepts_alphanumeric(void)
{
    EXPECT(util_is_valid_username("alice") == 1);
    EXPECT(util_is_valid_username("user42") == 1);
    EXPECT(util_is_valid_username("a") == 1);
}

static void test_username_accepts_allowed_specials(void)
{
    EXPECT(util_is_valid_username("a.b") == 1);
    EXPECT(util_is_valid_username("a_b") == 1);
    EXPECT(util_is_valid_username("a-b") == 1);
    EXPECT(util_is_valid_username("a.b_c-d") == 1);
}

static void test_username_rejects_empty_and_null(void)
{
    EXPECT(util_is_valid_username(NULL) == 0);
    EXPECT(util_is_valid_username("") == 0);
}

static void test_username_rejects_leading_special(void)
{
    /* Leading '-' and '.' are rejected explicitly — '-' to avoid
     * arg-parser confusion downstream, '.' to defeat the canonical
     * path-traversal seed. */
    EXPECT(util_is_valid_username("-user") == 0);
    EXPECT(util_is_valid_username(".user") == 0);
}

static void test_username_rejects_length_overflow(void)
{
    char too_long[MAX_USER_LEN + 8];
    memset(too_long, 'a', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    EXPECT(util_is_valid_username(too_long) == 0);

    /* Exactly MAX_USER_LEN is accepted; one over is rejected. */
    char exact[MAX_USER_LEN + 1];
    memset(exact, 'a', MAX_USER_LEN);
    exact[MAX_USER_LEN] = '\0';
    EXPECT(util_is_valid_username(exact) == 1);

    char one_over[MAX_USER_LEN + 2];
    memset(one_over, 'a', MAX_USER_LEN + 1);
    one_over[MAX_USER_LEN + 1] = '\0';
    EXPECT(util_is_valid_username(one_over) == 0);
}

static void test_username_rejects_shell_metacharacters(void)
{
    const char *bad[] = {
        "a;b", "a&b", "a|b", "a$b", "a`b", "a(b", "a)b",
        "a<b", "a>b", "a\"b", "a'b", "a\\b", "a*b", "a?b",
        "a[b", "a]b", "a{b", "a}b", "a b", "a\tb", "a\nb",
        NULL,
    };
    for (size_t i = 0; bad[i]; i++) {
        if (util_is_valid_username(bad[i]) != 0)
            FAIL("metachar in '%s' was not rejected", bad[i]);
    }
}

static void test_username_rejects_path_traversal(void)
{
    EXPECT(util_is_valid_username("../etc/passwd") == 0);
    EXPECT(util_is_valid_username("a/b") == 0);
    EXPECT(util_is_valid_username("..") == 0);
    EXPECT(util_is_valid_username("a..b") == 1); /* embedded dots OK */
}

/* -------------------------------------------------------------------- */
/* util_normalize_ip                                                     */
/* -------------------------------------------------------------------- */

static void test_normalize_ipv4(void)
{
    char out[IP_STR_MAX];
    EXPECT(util_normalize_ip("192.0.2.1", out, sizeof(out)) == 1);
    EXPECT_EQ_STR(out, "192.0.2.1");
}

static void test_normalize_ipv6(void)
{
    char out[IP_STR_MAX];
    EXPECT(util_normalize_ip("2001:db8::1", out, sizeof(out)) == 1);
    EXPECT_EQ_STR(out, "2001:db8::1");
}

static void test_normalize_zone_stripped(void)
{
    char out[IP_STR_MAX];
    EXPECT(util_normalize_ip("fe80::1%eth0", out, sizeof(out)) == 1);
    EXPECT_EQ_STR(out, "fe80::1");
}

static void test_normalize_v4_mapped_v6_extracted(void)
{
    /* ::ffff:a.b.c.d → "a.b.c.d" so the element lands in the v4 set
     * rather than the v6 set. Class of regression: sshd listening on
     * :: with IPV6_V6ONLY=0 producing v4-mapped addresses. */
    char out[IP_STR_MAX];
    EXPECT(util_normalize_ip("::ffff:10.0.0.1", out, sizeof(out)) == 1);
    EXPECT_EQ_STR(out, "10.0.0.1");
}

static void test_normalize_rejects_null_and_empty(void)
{
    char out[IP_STR_MAX];
    EXPECT(util_normalize_ip(NULL, out, sizeof(out)) == 0);
    EXPECT(util_normalize_ip("1.2.3.4", NULL, sizeof(out)) == 0);
    EXPECT(util_normalize_ip("1.2.3.4", out, 0) == 0);
    EXPECT(util_normalize_ip("", out, sizeof(out)) == 0);
}

static void test_normalize_rejects_hostname(void)
{
    char out[IP_STR_MAX];
    EXPECT(util_normalize_ip("bastion.example", out, sizeof(out)) == 0);
    EXPECT(util_normalize_ip("not an ip", out, sizeof(out)) == 0);
}

/*
 * ASan-coupled boundary test. The function's contract:
 *
 *     if (core_len == 0 || core_len >= out_sz) return 0;
 *
 * For "1.2.3.4" core_len is 7, and the subsequent memcpy writes
 * core_len + 1 = 8 bytes (7 chars + NUL). The rejection branch
 * uses `>=`: when out_sz == core_len + 1 (8) the function accepts
 * and writes 8 bytes; when out_sz == core_len (7) the function
 * rejects and writes nothing.
 *
 * A mull mutation flipping `>=` to `>` would make out_sz == 7
 * succeed instead of fail, and the memcpy would write 8 bytes into
 * a 7-byte stack buffer — heap-OOB-equivalent, caught by ASan as a
 * stack-buffer-overflow. Without ASan, the survival would be
 * silent.
 *
 * Convention this test sets: for any validator with an output-
 * buffer contract, plant a buffer of exactly the size that
 * exercises the rejection boundary, and rely on ASan to catch
 * the mutation kill.
 */
static void test_normalize_overflow_boundary(void)
{
    /* Buffer exactly large enough to hold "1.2.3.4\0" (8 bytes). */
    char fits[8];
    int rc = util_normalize_ip("1.2.3.4", fits, sizeof(fits));
    EXPECT(rc == 1);
    EXPECT_EQ_STR(fits, "1.2.3.4");

    /* Buffer one byte too small (7 bytes). Function must reject;
     * any mutation that lets it accept will overflow this exact
     * 7-byte stack array — ASan trips. */
    char too_small[7];
    rc = util_normalize_ip("1.2.3.4", too_small, sizeof(too_small));
    EXPECT(rc == 0);
}

/*
 * Closes the line-55 survivor from the PR #50 first-run audit
 * (`if (core_len >= sizeof(core)) return 0;`, mutated `>=` → `>`).
 *
 * The earlier `if (core_len == 0 || core_len >= out_sz) return 0;`
 * at line 52 rejects any input where core_len >= out_sz. Normal
 * callers pass `sizeof(out_buf)` for out_sz, which for typical
 * IP_STR_MAX-sized buffers is 64 — same as `sizeof(core)`. The
 * line-55 check is therefore unreachable in the normal-out_sz
 * case: line 52 catches first.
 *
 * Defensive programming preserves line 55 anyway, for callers that
 * pass an out_sz LARGER than IP_STR_MAX. This test exercises that
 * path: plant a 64-character non-IP input and an out_sz > 64. The
 * function must reject (returns 0). A mutation that lets the
 * rejection slip would memcpy 64 bytes into the 64-byte stack
 * `core[]` and write the NUL terminator at core[64], a one-byte
 * stack-buffer-overflow that ASan catches.
 */
static void test_normalize_core_buffer_boundary(void)
{
    char large_out[IP_STR_MAX * 2];
    char input[IP_STR_MAX + 1];
    memset(input, 'x', IP_STR_MAX);
    input[IP_STR_MAX] = '\0';
    int rc = util_normalize_ip(input, large_out, sizeof(large_out));
    EXPECT_EQ_INT(rc, 0);
}

/* -------------------------------------------------------------------- */
/* validate_cgroup_path                                                  */
/* -------------------------------------------------------------------- */

static void test_cgroup_accepts_canonical(void)
{
    char out[CGROUP_PATH_MAX];
    EXPECT(validate_cgroup_path("/authnft.slice/foo.scope", out, sizeof(out)) == 0);
    EXPECT_EQ_STR(out, "authnft.slice/foo.scope");
}

static void test_cgroup_rejects_no_leading_slash(void)
{
    char out[CGROUP_PATH_MAX];
    EXPECT(validate_cgroup_path("authnft.slice/foo.scope", out, sizeof(out)) == -1);
    EXPECT_EQ_INT(out[0], '\0');
}

static void test_cgroup_rejects_wrong_slice(void)
{
    char out[CGROUP_PATH_MAX];
    EXPECT(validate_cgroup_path("/user.slice/foo.scope", out, sizeof(out)) == -1);
    EXPECT_EQ_INT(out[0], '\0');
}

static void test_cgroup_rejects_deeper_path(void)
{
    /* Third component is disallowed: depth invariant is exactly two
     * components under root. */
    char out[CGROUP_PATH_MAX];
    EXPECT(validate_cgroup_path("/authnft.slice/foo.scope/bar",
                                 out, sizeof(out)) == -1);
    EXPECT_EQ_INT(out[0], '\0');
}

static void test_cgroup_rejects_missing_scope_suffix(void)
{
    char out[CGROUP_PATH_MAX];
    EXPECT(validate_cgroup_path("/authnft.slice/foo", out, sizeof(out)) == -1);
    EXPECT_EQ_INT(out[0], '\0');
}

static void test_cgroup_rejects_empty_name(void)
{
    char out[CGROUP_PATH_MAX];
    EXPECT(validate_cgroup_path("/authnft.slice/", out, sizeof(out)) == -1);
    EXPECT_EQ_INT(out[0], '\0');
}

static void test_cgroup_rejects_null_and_zero_size(void)
{
    char out[CGROUP_PATH_MAX];
    EXPECT(validate_cgroup_path(NULL, out, sizeof(out)) == -1);
    EXPECT(validate_cgroup_path("/authnft.slice/foo.scope", NULL, 0) == -1);
    EXPECT(validate_cgroup_path("/authnft.slice/foo.scope", out, 0) == -1);
}

static void test_cgroup_rejects_undersized_output(void)
{
    /* Same boundary-buffer pattern as util_normalize_ip. The
     * function copies p (the leading-slash-stripped form) of length
     * total = strlen("authnft.slice/foo.scope") = 23. It rejects
     * when total >= out_sz. */
    char tight[24];   /* exactly enough: 23 + NUL */
    EXPECT(validate_cgroup_path("/authnft.slice/foo.scope",
                                 tight, sizeof(tight)) == 0);

    char one_short[23];   /* one byte short of fitting */
    EXPECT(validate_cgroup_path("/authnft.slice/foo.scope",
                                 one_short, sizeof(one_short)) == -1);
    EXPECT_EQ_INT(one_short[0], '\0');
}

/*
 * Closes the line-104 survivor from the PR #50 first-run audit
 * (`if (slen < 7 || memcmp(...) != 0) return -1;`, mutated `<` → `<=`).
 *
 * A name of length exactly 7 ("x.scope" — single-character scope
 * name plus ".scope" suffix) is the minimum valid form. The
 * original `slen < 7` accepts it (7 is not < 7); a mutation to
 * `<=` rejects it (7 <= 7 is true). Existing tests use
 * "foo.scope" (slen=9) which doesn't exercise the boundary.
 */
static void test_cgroup_accepts_min_length_name(void)
{
    char out[CGROUP_PATH_MAX];
    int rc = validate_cgroup_path("/authnft.slice/x.scope", out, sizeof(out));
    EXPECT_EQ_INT(rc, 0);
    EXPECT_EQ_STR(out, "authnft.slice/x.scope");
}

/* -------------------------------------------------------------------- */
/* main                                                                  */
/* -------------------------------------------------------------------- */

int main(void)
{
    test_username_accepts_alphanumeric();
    test_username_accepts_allowed_specials();
    test_username_rejects_empty_and_null();
    test_username_rejects_leading_special();
    test_username_rejects_length_overflow();
    test_username_rejects_shell_metacharacters();
    test_username_rejects_path_traversal();

    test_normalize_ipv4();
    test_normalize_ipv6();
    test_normalize_zone_stripped();
    test_normalize_v4_mapped_v6_extracted();
    test_normalize_rejects_null_and_empty();
    test_normalize_rejects_hostname();
    test_normalize_overflow_boundary();
    test_normalize_core_buffer_boundary();

    test_cgroup_accepts_canonical();
    test_cgroup_rejects_no_leading_slash();
    test_cgroup_rejects_wrong_slice();
    test_cgroup_rejects_deeper_path();
    test_cgroup_rejects_missing_scope_suffix();
    test_cgroup_rejects_empty_name();
    test_cgroup_rejects_null_and_zero_size();
    test_cgroup_rejects_undersized_output();
    test_cgroup_accepts_min_length_name();

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("util_validators: all tests passed\n");
    return 0;
}
