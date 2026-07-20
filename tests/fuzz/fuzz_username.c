// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Fuzzer for util_is_valid_username and util_normalize_ip.
 *
 * Both functions accept arbitrary C strings and have no side effects:
 * no file I/O, no syslog, no PAM context required. They are the first
 * gatekeepers for every session open — username validation is the very
 * first thing pam_sm_open_session does before any privileged operation.
 */

#include "authnft.h"
#include "util_validators.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0)
        return 0;

    /* NUL-terminate — libFuzzer input bytes are not guaranteed to end with 0. */
    char buf[MAX_USER_LEN + 2];
    size_t n = size < sizeof(buf) - 1 ? size : sizeof(buf) - 1;
    memcpy(buf, data, n);
    buf[n] = '\0';

    util_is_valid_username(buf);

    char out[IP_STR_MAX];
    util_normalize_ip(buf, out, sizeof(out));

    /* Hit the early-out branches that the main call above skips. The
     * fixed-shape harness call always passes non-NULL pointers and a
     * fixed-size buffer, leaving the NULL/zero-size guards in
     * util_normalize_ip uncovered. These four extra calls are
     * negligible (each early-returns); they exist for branch coverage
     * not for fuzz signal. */
    util_normalize_ip(NULL, out, sizeof(out));
    util_normalize_ip(buf, NULL, sizeof(out));
    util_normalize_ip(buf, out, 0);
    util_normalize_ip(buf, out, 4);  /* small out_sz: hits core_len >= out_sz */

    return 0;
}
