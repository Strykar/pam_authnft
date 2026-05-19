/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Test wrapper for the mull+ASan stack-instrumentation
 * suppression investigation. Design is signal-path-agnostic:
 * no return-value assertions, main returns 0 unconditionally.
 * The only paths to non-zero exit come from runtime
 * instrumentation tripping (ASan, UBSan, fortify, ...) — what
 * those paths are depends on the build flags, which vary
 * per-run.
 *
 * Per-run interpretation (which signals are active, what
 * (status_code, stderr_content) pairs mean, and what
 * evidentiary gaps a run cannot resolve) lives in the
 * workflow's build-step comment for that run. The test file
 * deliberately does not encode a verdict mapping: 4a learned
 * that build-config-dependent mappings in this file age poorly
 * across runs. The lesson — pre-state verdict mappings in
 * empirical-observable form per run, not as a stable shared
 * mapping in the test file — is codified in
 * docs/MUTATION_ASAN_INVESTIGATION_2.md after the
 * investigation concludes.
 *
 * Boundary trace (invariant across runs):
 *   Input: 64 'x' + NUL, out_sz 128.
 *   Original line B (>=): 64 >= 64 true, return -1, no OOB write.
 *   Mutant line B (>):    64 > 64 false, fall through, write
 *                         core[64] one byte past the stack array.
 *
 * Line-47's cxx_ge_to_gt mutant is equivalent on this test
 * surface (in_len = 5 and in_len = 64 both produce the same
 * branch outcome under either operator), so it appears as a
 * status=2 survivor regardless of which sanitiser fires at
 * line B. Filter SQLite by line_number = 51 when reading the
 * H0' verdict.
 */

#include <stddef.h>
#include <string.h>

extern int faithful_check(const char *in, char *out, size_t out_sz);

/* Coverage driver, not a test of correctness. Mull's coverage-
 * driven filtering needs the function reached on a non-boundary
 * path; without this call, the line-51 mutant may be filtered
 * before generation. Removing this function changes the mutant
 * surface, not just the assertions. */
static void test_within_bounds(void)
{
        char out[128];
        (void)faithful_check("hello", out, sizeof(out));
}

static void test_boundary_case(void)
{
        char input[65];
        char out[128];
        memset(input, 'x', 64);
        input[64] = '\0';   /* strlen(input) == 64, exactly sizeof(core) */
        (void)faithful_check(input, out, sizeof(out));
}

int main(void)
{
        test_within_bounds();
        test_boundary_case();
        return 0;
}
