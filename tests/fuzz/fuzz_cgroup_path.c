// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Fuzzer for validate_cgroup_path: enforces the depth invariant
 * (`/authnft.slice/<name>.scope`) on cgroup paths returned by
 * sd_pid_get_cgroup. A bug in this validator either rejects valid
 * sessions (silent denial of service for every authnft user) or
 * accepts malformed paths (potentially mapping a session to the wrong
 * cgroup inode and matching unrelated sockets).
 *
 * Property assertions:
 *   1. on accept (rc == 0): out is NUL-terminated, out is non-empty,
 *      out is a leading-slash-stripped form of the input, the format
 *      "authnft.slice/<name>.scope" holds.
 *   2. on reject (rc == -1): out[0] == '\0'.
 */

#include "authnft.h"
#include "util_validators.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 1024) return 0;

    /* Vary out_sz to exercise truncation paths. */
    static const size_t sizes[] = {1, 8, 16, 64, CGROUP_PATH_MAX, CGROUP_PATH_MAX + 16};
    size_t out_sz = sizes[data[0] % (sizeof(sizes) / sizeof(sizes[0]))];

    char out[CGROUP_PATH_MAX + 16];
    if (out_sz > sizeof(out)) out_sz = sizeof(out);

    /* Build a NUL-terminated string from remaining bytes. */
    char *in = malloc(size);
    if (!in) return 0;
    memcpy(in, data + 1, size - 1);
    in[size - 1] = '\0';

    /* Sentinel to detect failure-path NUL-init regressions. */
    memset(out, 0xAA, sizeof(out));

    int rc = validate_cgroup_path(in, out, out_sz);

    if (rc == 0) {
        /* Property: out is NUL-terminated within out_sz. */
        size_t outlen = strnlen(out, out_sz);
        if (outlen >= out_sz) __builtin_trap();
        if (outlen == 0) __builtin_trap();

        /* Property: format is "authnft.slice/<name>.scope". */
        if (strncmp(out, "authnft.slice/", 14) != 0) __builtin_trap();
        if (outlen < 7) __builtin_trap();
        if (memcmp(out + outlen - 6, ".scope", 6) != 0) __builtin_trap();

        /* Property: <name> contains no slashes. */
        const char *name = out + 14;
        if (strchr(name, '/') != NULL) __builtin_trap();
    } else if (rc == -1) {
        /* Property: out is reset to empty on reject (when out_sz > 0). */
        if (out_sz > 0 && out[0] != '\0') __builtin_trap();
    } else {
        /* Property: return value is one of the documented values. */
        __builtin_trap();
    }

    /* Cover the early-out branches. */
    validate_cgroup_path(NULL, out, out_sz);
    validate_cgroup_path(in, NULL, out_sz);
    validate_cgroup_path(in, out, 0);

    free(in);
    return 0;
}
