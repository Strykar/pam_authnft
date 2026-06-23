// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar
//
// LD_PRELOAD libnftables-call interposer for the audit harness.
//
// Drives the two nft_handler_setup error returns that input/state faults
// can't reach (the call-1-success-then-fail paths): the jump-rule failure
// (call 2) and the handle-parse failure. Both are after call 1 commits the
// per-session chain/sets, so they also exercise nft_partial_cleanup.
//
//   AUTHNFT_NFT_FAIL_ON=<substr>   make nft_run_cmd_from_buffer fail (return
//                                  non-zero without running) for any command
//                                  whose buffer contains <substr>. Use "jump"
//                                  to fail call 2 only (call 1's buffer has
//                                  no "jump"; the test fragment has none).
//
//   AUTHNFT_NFT_CORRUPT_HANDLE=1   mangle the "# handle" marker in
//                                  nft_ctx_get_output_buffer output so the
//                                  handle parse fails (the handle-parse
//                                  return). The probe output has no
//                                  "# handle", so only the post-call-2 echo
//                                  is affected.
//
// Composes with the ASan-instrumented fault driver (it wraps libnftables
// symbols, not the allocator), so the leak verdict on these returns is
// still owned by LeakSanitizer.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int (*real_run)(void *, const char *);
static const char *(*real_getout)(void *);

int nft_run_cmd_from_buffer(void *ctx, const char *buf)
{
    if (!real_run)
        real_run = dlsym(RTLD_NEXT, "nft_run_cmd_from_buffer");
    const char *fail_on = getenv("AUTHNFT_NFT_FAIL_ON");
    if (fail_on && *fail_on && buf && strstr(buf, fail_on)) {
        if (getenv("AUTHNFT_NFT_FAIL_VERBOSE"))
            fprintf(stderr, "[nft_fail] failing command containing '%s'\n",
                    fail_on);
        return 1; /* libnftables returns non-zero on failure */
    }
    return real_run(ctx, buf);
}

const char *nft_ctx_get_output_buffer(void *ctx)
{
    if (!real_getout)
        real_getout = dlsym(RTLD_NEXT, "nft_ctx_get_output_buffer");
    const char *out = real_getout(ctx);
    if (out && getenv("AUTHNFT_NFT_CORRUPT_HANDLE")) {
        static char mangled[262144];
        snprintf(mangled, sizeof(mangled), "%s", out);
        char *h = strstr(mangled, "# handle");
        if (h)
            memcpy(h, "# xxxxxx", 8); /* break the parse, same length */
        return mangled;
    }
    return out;
}
