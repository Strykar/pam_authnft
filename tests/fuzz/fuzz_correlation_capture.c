// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Fuzzer for corr_sanitize_copy: the AUTHNFT_CORRELATION PAM env
 * sanitizer. The token gets emitted into a journald structured field,
 * so any byte outside is_corr_safe() must be dropped — a stray '='
 * or '\n' would corrupt the field encoding.
 *
 * Property assertions:
 *   1. output is NUL-terminated within out_sz
 *   2. output length <= out_sz - 1
 *   3. every byte in the output is in is_corr_safe()
 */

#include "authnft.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

size_t corr_sanitize_copy(const char *in, char *out, size_t out_sz);

static int is_corr_safe(unsigned char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9'))
        return 1;
    return c == '_' || c == '-' || c == '.' || c == ':';
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    /* Vary out_sz via first byte to hit truncation paths. */
    static const size_t sizes[] = {1, 8, 16, CORRELATION_ID_MAX, 256};
    size_t out_sz = sizes[data[0] % (sizeof(sizes) / sizeof(sizes[0]))];

    char out[256];
    if (out_sz > sizeof(out)) out_sz = sizeof(out);

    /* Build a NUL-terminated input from the remaining bytes. The
     * function reads `in` as a C string; any embedded NUL truncates
     * the loop, which is part of the documented behaviour. */
    char *in = malloc(size);
    if (!in) return 0;
    memcpy(in, data + 1, size - 1);
    in[size - 1] = '\0';

    size_t w = corr_sanitize_copy(in, out, out_sz);

    /* Property checks. */
    size_t outlen = strnlen(out, out_sz);
    if (outlen >= out_sz) __builtin_trap();
    if (w != outlen) __builtin_trap();

    for (size_t i = 0; i < outlen; i++) {
        if (!is_corr_safe((unsigned char)out[i]))
            __builtin_trap();
    }

    /* Early-out branches. */
    corr_sanitize_copy(NULL, out, out_sz);
    corr_sanitize_copy(in, NULL, out_sz);
    corr_sanitize_copy(in, out, 0);

    free(in);
    return 0;
}
