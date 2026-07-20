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
static const char *(*real_geterr)(void *);

/* AUTHNFT_NFT_FAIL_ONCE=1 drives the call-1 self-heal (PID recycle onto a
 * leaked session's names). It fails the FIRST call-1 command once and makes
 * the next error-buffer read report an "exists" collision, which is what a
 * leftover per-session chain/set from a killed session produces. The retry the
 * self-heal issues then passes through to the real libnftables and succeeds.
 *
 * This has to be forced: re-running nft_handler_setup by hand does NOT
 * reproduce the collision, because `add table` / `add chain` / `add set` are
 * idempotent in libnftables, so a second identical setup just succeeds. A
 * scenario built that way passes with the self-heal deleted (verified), i.e.
 * it proves nothing. */
static int fail_once_done;
static int fake_exists_err;

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
    /* Call 1 is the only command that creates the per-session sets. */
    const char *once = getenv("AUTHNFT_NFT_FAIL_ONCE");
    if (once && *once && !fail_once_done && buf && strstr(buf, "add set inet")) {
        fail_once_done = 1;
        fake_exists_err = 1;
        if (getenv("AUTHNFT_NFT_FAIL_VERBOSE"))
            fprintf(stderr, "[nft_fail] failing call 1 once as 'exists'\n");
        return 1;
    }
    return real_run(ctx, buf);
}

const char *nft_ctx_get_error_buffer(void *ctx)
{
    if (fake_exists_err) {
        fake_exists_err = 0;   /* one-shot: the retry sees the real buffer */
        return "Error: Could not process rule: File exists\n";
    }
    if (!real_geterr)
        real_geterr = dlsym(RTLD_NEXT, "nft_ctx_get_error_buffer");
    return real_geterr(ctx);
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
