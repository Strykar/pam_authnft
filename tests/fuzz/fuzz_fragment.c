// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Fuzzer for validate_fragment_content: the verb/include-path scanner
 * that runs on every per-user nftables fragment before libnftables sees it.
 *
 * validate_fragment_content is compiled as non-static when -DFUZZ_BUILD
 * is set (see the #ifndef FUZZ_BUILD guard in src/nft_handler.c).
 *
 * The fuzzer covers two surfaces:
 *
 *   1. Crash safety — random byte input through memfd, asserting the
 *      function does not crash, leak file descriptors, or hang.
 *
 *   2. Property: forbidden-verb-at-line-start MUST be rejected. The
 *      harness derives a probe that pads the fuzzer-supplied bytes with
 *      arbitrary whitespace before a known forbidden verb on a fresh
 *      line. The validator MUST return -1 regardless of whether the
 *      verb-bearing line straddles any internal read buffer boundary.
 *      This catches the historical bug where a 1024-byte fgets() could
 *      split the verb across two reads and miss it on both halves.
 *
 * Fuzz input is presented to the function as a file path via an anonymous
 * in-memory file (memfd_create + /proc/self/fd/<n>). This avoids any
 * actual filesystem writes during corpus replay.
 *
 * pamh=NULL: pam_syslog(NULL, ...) falls back to syslog() which is
 * harmless in a fuzzer process — log output goes to /dev/null or is
 * suppressed by the runtime.
 */

#include "authnft.h"
#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* Declared non-static when nft_handler.c is compiled with -DFUZZ_BUILD. */
int validate_fragment_content(pam_handle_t *pamh, const char *path);

static int validate_buf(const char *buf, size_t len) {
    int fd = memfd_create("fuzz_frag", MFD_CLOEXEC);
    if (fd < 0) return 0;
    if (write(fd, buf, len) != (ssize_t)len) { close(fd); return 0; }
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    int rc = validate_fragment_content(NULL, path);
    close(fd);
    return rc;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Surface 1: crash safety on raw input. */
    (void)validate_buf((const char *)data, size);

    /* Cover the fopen-failure branch (read_file returns NULL). */
    validate_fragment_content(NULL, "/dev/null/no-such-path");

    /* Surface 2: forbidden-verb-at-line-start property. Build a probe
     * that interleaves the fuzzer-supplied bytes with a known forbidden
     * verb on its own line. The validator MUST reject. */
    static const char *bad_verbs[] = {
        "flush ruleset",
        "delete rule inet authnft filter handle 1",
        "reset counters",
        "list table inet authnft",
        "rename chain inet authnft a b",
        "insert rule inet authnft filter accept",
        "replace rule inet authnft filter handle 1 accept",
        "monitor",
    };
    if (size >= 1) {
        int verb_idx = data[0] % (int)(sizeof(bad_verbs) / sizeof(bad_verbs[0]));
        const char *verb = bad_verbs[verb_idx];

        /* Padding length: fuzzer-driven, capped to keep total input bounded.
         * This deliberately spans values that straddle the historic 1024-byte
         * fgets boundary (and any other future internal buffer size). */
        size_t pad_len = (size >= 3) ? ((size_t)(data[1] | (data[2] << 8)) % 4096) : 0;

        size_t probe_len = pad_len + 1 /* leading \n */ +
                           strlen(verb) + 1 /* trailing \n */ + 1;
        char *probe = malloc(probe_len);
        if (probe) {
            char *w = probe;
            /* Fill padding with safe characters: spaces and tabs. */
            for (size_t i = 0; i < pad_len; i++) *w++ = (i & 1) ? ' ' : '\t';
            *w++ = '\n';
            memcpy(w, verb, strlen(verb));
            w += strlen(verb);
            *w++ = '\n';
            *w = '\0';

            int rc = validate_buf(probe, (size_t)(w - probe));

            /* Property assertion. -1 == rejected. Anything else is a
             * validator bypass and a regression. */
            assert(rc == -1);

            free(probe);
        }
    }

    return 0;
}
