/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2025 Avinash H. Duduskar
 *
 * Driver for the fragment include walk (issue #108).
 *
 * The unit tests in test_nft_validator.c cover the pure half: that the
 * validator reports include paths and that NFT_FRAG_INCLUDED relaxes the
 * shared-chain guard and nothing else. They cannot cover the half that
 * matters operationally, which is whether a real file on disk, reached
 * through a real `include` directive, is opened, permission-checked and
 * scanned. That needs a filesystem, so it needs a driver.
 *
 * Run by tests/include_walk_test.sh inside a private mount namespace with
 * a tmpfs bound over /etc/authnft, so the fixtures are real paths under
 * the only prefix the validator accepts and the host is untouched.
 *
 * Prints one PASS/FAIL line per case and exits non-zero on any failure.
 */

#include "nft_validator.h"

#include <stdio.h>
#include <string.h>

int authnft_validate_fragment_includes(pam_handle_t *pamh, const char *path,
                                       const char *buf, size_t buf_len);

static int failures;

static void expect(const char *name, const char *frag, int want)
{
    int got = authnft_validate_fragment_includes(NULL, "top.nft",
                                                 frag, strlen(frag));
    if (got == want) {
        printf("  [PASS] %s (rc=%d)\n", name, got);
    } else {
        printf("  [FAIL] %s: wanted rc=%d, got rc=%d\n", name, want, got);
        failures++;
    }
}

int main(void)
{
    /* The bug: this returned 0 and libnftables then executed the flush. */
    expect("included flush ruleset is rejected",
           "include \"/etc/authnft/groups/evil.nft\"\n", -1);

    /* INTEGRATIONS.txt 4.6's documented pattern must still work. */
    expect("included shared-chain rule is accepted",
           "include \"/etc/authnft/groups/good.nft\"\n", 0);

    /* Depth: a chain of includes is walked, and a bad verb at the bottom
     * is still caught. Without recursion this passes vacuously. */
    expect("bad verb three includes deep is rejected",
           "include \"/etc/authnft/groups/d1.nft\"\n", -1);

    /* A file that includes itself must terminate, not recurse. */
    expect("self-referential include is rejected",
           "include \"/etc/authnft/groups/loop.nft\"\n", -1);

    /* Permissions: an include the gated users could rewrite. */
    expect("world-writable include is rejected",
           "include \"/etc/authnft/groups/worldwrite.nft\"\n", -1);

    expect("non-root-owned include is rejected",
           "include \"/etc/authnft/groups/nonroot.nft\"\n", -1);

    expect("missing include is rejected",
           "include \"/etc/authnft/groups/absent.nft\"\n", -1);

    expect("directory as include is rejected",
           "include \"/etc/authnft/groups\"\n", -1);

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("include_walk: all cases passed\n");
    return 0;
}
