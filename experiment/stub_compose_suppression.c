/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Throwaway stub for the mull+ASan stack-instrumentation
 * suppression investigation. Reproduces the shape of the line-55
 * mutant from src/util_validators.c::util_normalize_ip that
 * survived in mull+ASan compose despite being caught locally
 * under gcc+ASan and clang+ASan without mull's pass plugin.
 *
 * Not on main; experiment branch only. See
 * docs/MUTATION_ASAN_EXPERIMENT.md's post-experiment findings
 * section for the original observation and
 * docs/MUTATION_ASAN_INVESTIGATION_2.md (post-investigation) for
 * the bound the investigation produced.
 *
 * The faithful structure mirrors util_normalize_ip:
 *
 *   - Line A: an early bound check (`in_len >= out_sz`) that
 *     normal callers' out_sz makes redundant with line B.
 *   - A stack-allocated `core[64]` buffer.
 *   - Line B: the defensive check (`in_len >= sizeof(core)`)
 *     that is the mutation target. cxx_ge_to_gt rewrites this
 *     to `in_len > sizeof(core)`, letting in_len == 64 through.
 *   - The OOB write at `core[in_len] = '\0'` when in_len == 64.
 *   - A return path that doesn't depend on the buffer contents
 *     (so behavioural assertions can't see the difference; only
 *     ASan's red-zone check on the OOB write can).
 *
 * Line A is redundant with Line B in normal control flow;
 * preserved here to match util_normalize_ip's defensive
 * structure. The investigation tests whether the suppression
 * depends on this redundant-earlier-check structure (run 7,
 * minimal stub, only if H6 warranted).
 */

#include <stddef.h>
#include <string.h>

#define CORE_SIZE 64

int faithful_check(const char *in, char *out, size_t out_sz)
{
    char core[CORE_SIZE];
    size_t in_len = strlen(in);

    /* Line A: redundant with line B for normal callers (out_sz <=
     * CORE_SIZE) but defensive for callers passing larger buffers. */
    if (in_len >= out_sz)
        return -1;

    /* Line B: mutation target. cxx_ge_to_gt: `>=` → `>`. */
    if (in_len >= sizeof(core))
        return -1;

    memcpy(core, in, in_len);
    core[in_len] = '\0';  /* OOB write at core[64] when mutated */

    /* Return path doesn't propagate buffer contents — only ASan's
     * red-zone check on the OOB write differentiates original from
     * mutant. */
    if (out_sz > 0 && out)
        out[0] = '\0';
    return 0;
}
