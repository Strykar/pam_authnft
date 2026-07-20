// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Fuzzer for keyring_sanitize: the printable-ASCII filter that
 * scrubs a kernel-keyring payload before it lands in an nftables
 * comment field.
 *
 * Trust model: the producer (an upstream PAM module that sets a
 * keyring serial) is conventionally trusted, but if any process can
 * keyctl_link() a key into the session keyring then the sanitizer
 * becomes the trust boundary. A bad scrub allows quote / NUL /
 * control characters into the nft command stream.
 *
 * Property assertions:
 *   1. output length <= min(out_sz - 1, CLAIMS_TAG_MAX)
 *   2. output is NUL-terminated within the buffer
 *   3. every byte in the output is in the is_safe() character class
 *      OR exactly '_' (the substitution character)
 */

#include "authnft.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>

ssize_t keyring_sanitize(const char *in, size_t in_len,
                         char *out, size_t out_sz);

static int is_safe_for_assertion(unsigned char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9'))
        return 1;
    switch (c) {
        case '_': case '=': case ',': case '.': case ':':
        case ';': case '/': case '-':
            return 1;
        default:
            return 0;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Vary the output buffer size to exercise the truncation paths
     * (w + 1 < out_sz boundary). The first byte selects 1 of a few
     * sizes; remaining bytes are the keyring payload. */
    if (size == 0) return 0;

    static const size_t sizes[] = {1, 8, 32, CLAIMS_TAG_MAX, CLAIMS_TAG_MAX + 64};
    size_t out_sz = sizes[data[0] % (sizeof(sizes) / sizeof(sizes[0]))];

    char out[CLAIMS_TAG_MAX + 64];
    if (out_sz > sizeof(out)) out_sz = sizeof(out);

    const char *in = (const char *)(data + 1);
    size_t in_len = size - 1;

    ssize_t w = keyring_sanitize(in, in_len, out, out_sz);

    if (w < 0)
        return 0;  /* legitimate refusal: out NULL or out_sz == 0 */

    /* Property 1 + 2: NUL-terminated within bounds, length capped. */
    size_t outlen = strnlen(out, out_sz);
    if (outlen >= out_sz)
        __builtin_trap();
    if ((size_t)w != outlen)
        __builtin_trap();
    if (outlen > CLAIMS_TAG_MAX)
        __builtin_trap();

    /* Property 3: every output byte is in the allowlisted class. */
    for (size_t i = 0; i < outlen; i++) {
        unsigned char c = (unsigned char)out[i];
        if (!is_safe_for_assertion(c))
            __builtin_trap();
    }

    /* Cover the early-out branches. */
    keyring_sanitize(in, in_len, NULL, out_sz);
    keyring_sanitize(in, in_len, out, 0);

    return 0;
}
