// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Fuzzer for parse_socket_inode: extracts the inode number from a
 * /proc/<pid>/fd/<n> readlink target of the form "socket:[12345]".
 *
 * The current implementation delegates parsing to sscanf %lu — this
 * harness is primarily a regression guard for any future hand-rolled
 * replacement (e.g. one that strips embedded NULs differently or
 * tries to validate the prefix without sscanf). Cheap to run.
 *
 * Property assertion: return value is 0 or 1, never else.
 */

#include "authnft.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int parse_socket_inode(const char *target, unsigned long *out_inode);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 256) return 0;

    char *in = malloc(size + 1);
    if (!in) return 0;
    if (size) memcpy(in, data, size);
    in[size] = '\0';

    unsigned long ino = 0xdeadbeefUL;
    int rc = parse_socket_inode(in, &ino);

    if (rc != 0 && rc != 1) __builtin_trap();

    /* Cover the early-out branches. */
    parse_socket_inode(NULL, &ino);
    parse_socket_inode(in, NULL);

    free(in);
    return 0;
}
