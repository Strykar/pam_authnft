/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test wrapper for the compose-suppression stub. Plants the input
 * that triggers the OOB write under the mutated line-B check.
 * Mirrors test_normalize_core_buffer_boundary in
 * tests/test_util_validators.c (the test that catches the mutant
 * locally but not in the mull+ASan compose).
 *
 * Discipline:
 *   - The test calls faithful_check with input of exactly
 *     CORE_SIZE (64) characters and an out_sz > CORE_SIZE.
 *   - The function must reject (returns -1). A mutation that
 *     lets the rejection slip writes core[64]='\0' off the end of
 *     the 64-byte stack buffer; ASan should catch the one-byte
 *     stack-buffer-overflow.
 *   - Under ASan locally without mull's pass plugin, the mutated
 *     binary exits 1 with explicit AddressSanitizer:
 *     stack-buffer-overflow diagnostic. The investigation tests
 *     whether the compose suppresses this detection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int faithful_check(const char *in, char *out, size_t out_sz);

static int failures = 0;

static void test_boundary_case(void)
{
    char input[65];   /* 64 chars + NUL */
    char out[128];    /* larger than CORE_SIZE so line A's check does NOT
                       * reject before line B is reached */
    memset(input, 'x', 64);
    input[64] = '\0';

    int rc = faithful_check(input, out, sizeof(out));
    if (rc != -1) {
        fprintf(stderr, "[FAIL] expected -1, got %d\n", rc);
        failures++;
    }
}

static void test_within_bounds(void)
{
    /* Sanity: short input is accepted. Confirms the function works
     * normally and the failure mode under the mutant is specifically
     * the boundary case. */
    char out[128];
    int rc = faithful_check("hello", out, sizeof(out));
    if (rc != 0) {
        fprintf(stderr, "[FAIL] expected 0, got %d\n", rc);
        failures++;
    }
}

static void test_line_a_rejects(void)
{
    /* If out_sz <= CORE_SIZE, line A rejects first. Sanity check
     * that line A's path is reachable independently of line B's. */
    char input[20];
    memset(input, 'y', 19);
    input[19] = '\0';
    char small_out[10];
    int rc = faithful_check(input, small_out, sizeof(small_out));
    if (rc != -1) {
        fprintf(stderr, "[FAIL] expected -1 (line A), got %d\n", rc);
        failures++;
    }
}

int main(void)
{
    test_within_bounds();
    test_line_a_rejects();
    test_boundary_case();

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("compose_suppression: all tests passed\n");
    return 0;
}
