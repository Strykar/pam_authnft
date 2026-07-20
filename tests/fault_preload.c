// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar
//
// LD_PRELOAD fault injector for the run_sandboxed_nft_setup error paths that
// real triggers (an allowlist gap, fd or process exhaustion) cannot reach
// deterministically. Same mechanism as tests/audit/nft_fail.c. Inert unless one of
// its env vars is set. Driven by tests/integration_test.sh stages 10.22-10.24.
//
//   AUTHNFT_FAULT_PIPE=1            pipe(2) returns EMFILE
//   AUTHNFT_FAULT_FORK=1            fork(2) returns EAGAIN
//   AUTHNFT_FAULT_DIE_AFTER_JUMP=1  the sandboxed setup child _exit(42)s right
//                                   after the jump rule commits, modelling a
//                                   SIGSYS-class death once per-session state
//                                   is in the kernel but before it is reported

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

int pipe(int pipefd[2]) {
    if (getenv("AUTHNFT_FAULT_PIPE")) { errno = EMFILE; return -1; }
    static int (*real)(int[2]);
    if (!real) real = dlsym(RTLD_NEXT, "pipe");
    return real(pipefd);
}

pid_t fork(void) {
    if (getenv("AUTHNFT_FAULT_FORK")) { errno = EAGAIN; return -1; }
    static pid_t (*real)(void);
    if (!real) real = dlsym(RTLD_NEXT, "fork");
    return real();
}

int nft_run_cmd_from_buffer(void *ctx, const char *buf) {
    static int (*real)(void *, const char *);
    if (!real) real = dlsym(RTLD_NEXT, "nft_run_cmd_from_buffer");
    int rc = real(ctx, buf);
    /* Die only in the sandboxed setup child (seccomp mode 2), right after the
     * jump rule commits. Gating on the filter keeps the unsandboxed parent's
     * orphan-cleanup nft calls — which also run through this wrapper — safe. */
    if (getenv("AUTHNFT_FAULT_DIE_AFTER_JUMP") && buf &&
        strstr(buf, "filter jump") && prctl(PR_GET_SECCOMP) == 2)
        _exit(42);
    return rc;
}
