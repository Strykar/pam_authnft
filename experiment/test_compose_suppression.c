/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Run 4a: test redesigned so ASan stack-instrumentation is the
 * sole kill signal for the line-B (sizeof(core)) mutant.
 *
 * Runs 1-2's tests asserted on the boundary call's return value,
 * which conflated assertion-kill with ASan-kill (both produce
 * status=1 in mull's SQLite report). Run 2's H0 falsification
 * rested on that conflation and does not hold; this run is the
 * first unambiguous H0 test in the investigation.
 *
 * Boundary trace: input is 64 'x' + NUL, out_sz 128.
 *   Original line B (>=): 64 >= 64 true, return -1, no OOB write.
 *   Mutant line B (>):    64 > 64 false, fall through, write
 *                         core[64] one byte past the stack array.
 *
 * Verdict mapping for the line-51 cxx_ge_to_gt mutant
 * (filter SQLite by line_number = 51, not just by mutator):
 *   status=4 (Crashed):  ASan aborted on core[64] — H0 falsified.
 *   status=2 (Passed):   no abort, mutant survived — H0 holds.
 *   status=3 (Timedout): if mutation-report.txt shows ASan
 *                        diagnostic output, treat as status=4;
 *                        otherwise investigate. ASan symbolisation
 *                        before abort is the slow path the
 *                        --minimum-timeout 5000 commit addressed.
 *   status=1 (Failed):   the audit missed a signal path other
 *                        than ASan-induced abort; the result is
 *                        not interpretable, redesign before
 *                        re-running.
 *
 * Line 47's cxx_ge_to_gt mutant is equivalent on this test
 * surface (in_len = 5 and in_len = 64 both produce the same
 * branch outcome under either operator), so it will appear as a
 * second status=2 survivor regardless of H0. Not the H0 carrier.
 *
 * Build must use -fsanitize=address only, not address,undefined:
 * UBSan's bounds check fires on core[64] before ASan's red zone
 * and would produce status=4 from a non-ASan signal. The
 * workflow's per-file compile drops the 'undefined' component
 * for this run.
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
