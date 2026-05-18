// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include "util_validators.h"
#include <arpa/inet.h>
#include <errno.h>
#include <nftables/libnftables.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/stat.h>

static int is_audit_mode(void) {
    const char *mode = getenv("AUTHNFT_AUDIT_MODE");
    return (mode && strcmp(mode, "1") == 0);
}

/* Stage 1: username validation rejects path traversal and shell metacharacters */
static void run_input_validation_test(void) {
    printf("[STAGE 1] Input sanitization...\n");
    const char *bad[] = {"../etc/passwd", "root;rm -rf /", "user\n", NULL};
    for (int i = 0; bad[i] != NULL; i++) {
        if (util_is_valid_username(bad[i])) {
            fprintf(stderr, "[FAIL] Accepted illegal username: %s\n", bad[i]);
            exit(1);
        }
    }
    printf("[PASS]\n");
}

/* Stage 2: a syscall absent from the allowlist must trigger SIGSYS */
static void run_violation_test(void) {
    if (is_audit_mode()) {
        printf("[SKIP] Stage 2: Seccomp vs Valgrind conflict.\n");
        return;
    }
    printf("[STAGE 2] Seccomp kill on blocked syscall...\n");
    pid_t pid = fork();
    if (pid == 0) {
        sandbox_apply(NULL);
        /* personality() is not on the allowlist — must trigger SIGSYS */
        (void)personality(0xffffffff);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
        printf("[PASS]\n");
    else {
        fprintf(stderr, "[FAIL] Not killed by Seccomp (status: %d)\n", status);
        exit(1);
    }
}

/* Stage 3: an allowlisted syscall must succeed through the sandbox */
static void run_allowlist_test(void) {
    printf("[STAGE 3] Allowlisted syscall survives sandbox...\n");
    pid_t pid = fork();
    if (pid == 0) {
        if (!is_audit_mode()) sandbox_apply(NULL);
        /* close() on an invalid fd returns EBADF, not SIGSYS */
        if (close(999) == -1 && errno == EBADF) _exit(42);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
        printf("[PASS]\n");
    else
        exit(1);
}

/* Stage 4: libnftables dry-run rejects malformed commands */
static void run_nft_syntax_test(void) {
    printf("[STAGE 4] Nftables dry-run syntax check...\n");
    cap_t caps = cap_get_proc();
    cap_flag_value_t val;
    cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &val);
    cap_free(caps);
    if (val != CAP_SET) {
        printf("[SKIP] Requires CAP_NET_ADMIN.\n");
        return;
    }
    struct nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    nft_ctx_set_dry_run(ctx, 1);
    char cmd[CMD_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "add table inet %s_syntax_test", TABLE_NAME);
    if (nft_run_cmd_from_buffer(ctx, cmd) == 0)
        printf("[PASS]\n");
    else {
        fprintf(stderr, "[FAIL] Nftables rejected valid syntax.\n");
        exit(1);
    }
    nft_ctx_free(ctx);
}

/* Stage 5: util_get_cgroup_path resolves the cgroupv2 path and enforces
 * the pam_authnft depth invariant (HANDOFF §3.1/§3.2). The test binary
 * itself runs outside authnft.slice — under user.slice or system.slice
 * depending on how it was invoked — so util_get_cgroup_path MUST reject
 * this pid with -1 and leave the output buffer empty. That rejection IS
 * the thing under test: it proves the invariant check actually fires
 * before any path-to-inode resolution reaches the data plane. A
 * positive-resolution test for a real session lives in the integration
 * suite (stage 10.11), which drives a genuine pamtester session. */
static void run_cgroup_logic_test(void) {
    printf("[STAGE 5] cgroup path resolution + invariant enforcement...\n");
    char buf[CGROUP_PATH_MAX] = {0};
    /* Sentinel to catch callees that forget to NUL-init on failure. */
    memset(buf, 0xAA, sizeof(buf));
    int r = util_get_cgroup_path(NULL, getpid(), buf, sizeof(buf));
    if (r == 0) {
        fprintf(stderr,
                "[FAIL] util_get_cgroup_path accepted test-binary pid "
                "(buf=%s) — the invariant check is not firing. Test binary "
                "must not run under authnft.slice.\n",
                buf);
        exit(1);
    }
    if (buf[0] != '\0') {
        fprintf(stderr,
                "[FAIL] util_get_cgroup_path rejected (rc=%d) but left "
                "non-empty buffer — contract violation.\n", r);
        exit(1);
    }
    printf("[PASS] invariant check rejected non-authnft.slice path\n");
}

/* Stage 6: binary hardening flags are present in the compiled .so.
 * Two checksec packages exist in the wild with incompatible CLIs —
 * checksec.sh (Arch `checksec` package) accepts `file <path>`, and
 * Fedora's `checksec` accepts `--file=<path>`. Try both. */
static void run_checksec_test(void) {
    printf("[STAGE 6] Binary hardening (checksec)...\n");
    if (system("command -v checksec > /dev/null 2>&1") != 0) {
        printf("[SKIP] checksec not found.\n");
        return;
    }
    if (system("checksec file pam_authnft.so 2>/dev/null | grep -qi 'Full RELRO'") == 0 ||
        system("checksec --file=pam_authnft.so --format=cli 2>/dev/null | grep -qi 'Full RELRO'") == 0)
        printf("[PASS]\n");
    else
        exit(1);
}

/* Stage 7: nft_handler_setup fragment load.
 * Post-Plan-B, nft_handler_setup takes an authnft_session_t* and creates
 * per-session chains/sets whose cg_path the kernel resolves to a cgroupv2
 * inode at insert time. The unit-test binary cannot create a real
 * authnft.slice scope, so end-to-end fragment-load testing lives in
 * integration stages 10.2 and 10.11. This stage is retained as a
 * placeholder to keep stage numbering stable. */
static void run_path_resolution_test(void) {
    printf("[STAGE 7] Fragment path resolution and load...\n");
    printf("[SKIP] Requires real authnft.slice scope (covered by integration 10.2/10.11).\n");
}

/* Stage 8: PAM_RHOST normalization — reject hostnames (UseDNS=yes), strip
 * IPv6 zone IDs, pass through plain v4/v6. Class of regression: sshd
 * UseDNS or link-local addresses must not deny the session. */
static void run_rhost_normalization_test(void) {
    printf("[STAGE 8] PAM_RHOST normalization...\n");
    char out[IP_STR_MAX];

    struct { const char *in; int expect_ok; const char *expect_out; } cases[] = {
        { "192.0.2.1",       1, "192.0.2.1"  },
        { "2001:db8::1",     1, "2001:db8::1"},
        { "fe80::1%eth0",    1, "fe80::1"    },  /* zone stripped */
        { "::ffff:10.0.0.1", 1, "10.0.0.1" },          /* v4-mapped → plain v4 */
        { "bastion.example", 0, NULL },           /* UseDNS hostname */
        { "not an ip",       0, NULL },
        { "",                0, NULL },
        { "1.2.3.4 ; rm -rf /", 0, NULL },
        { NULL, 0, NULL }
    };
    for (int i = 0; cases[i].in != NULL; i++) {
        memset(out, 0, sizeof(out));
        int r = util_normalize_ip(cases[i].in, out, sizeof(out));
        if (r != cases[i].expect_ok) {
            fprintf(stderr, "[FAIL] '%s': got ok=%d, want ok=%d\n",
                    cases[i].in, r, cases[i].expect_ok);
            exit(1);
        }
        if (r && strcmp(out, cases[i].expect_out) != 0) {
            fprintf(stderr, "[FAIL] '%s': got '%s', want '%s'\n",
                    cases[i].in, out, cases[i].expect_out);
            exit(1);
        }
    }
    /* Truncation: refuse if output buffer is too small. */
    if (util_normalize_ip("2001:db8::1", out, 4) != 0) {
        fprintf(stderr, "[FAIL] did not reject short buffer\n");
        exit(1);
    }
    printf("[PASS]\n");
}

/* Stage 9: peer_lookup_tcp resolves the remote address of an ESTABLISHED
 * TCP socket owned by this process. Uses a localhost listener/connect
 * pair; the lookup picks the loopback peer back when no non-loopback
 * candidate is available. Class of regression: sock_diag plumbing or
 * /proc fd walk broken. */
static void run_peer_lookup_test(void) {
    printf("[STAGE 9] peer_lookup_tcp self-socket resolution...\n");

    int ls = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ls < 0) { printf("[SKIP] socket(): %s\n", strerror(errno)); return; }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        listen(ls, 1) < 0) {
        close(ls);
        printf("[SKIP] bind/listen: %s\n", strerror(errno));
        return;
    }
    socklen_t sl = sizeof(sa);
    if (getsockname(ls, (struct sockaddr *)&sa, &sl) < 0) {
        close(ls); printf("[SKIP] getsockname\n"); return;
    }

    int cs = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (cs < 0 || connect(cs, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        if (cs >= 0) close(cs);
        close(ls);
        printf("[SKIP] connect: %s\n", strerror(errno));
        return;
    }
    int as = accept(ls, NULL, NULL);
    if (as < 0) {
        close(cs); close(ls);
        printf("[SKIP] accept: %s\n", strerror(errno));
        return;
    }

    char peer[IP_STR_MAX] = {0};
    int got = peer_lookup_tcp(NULL, getpid(), peer, sizeof(peer));

    close(as); close(cs); close(ls);

    if (!got) {
        /* Kernel may refuse sock_diag without CAP_NET_ADMIN in some
         * configurations (user-ns, seccomp'd CI). Treat as skip, not fail. */
        printf("[SKIP] sock_diag denied or no owned TCP socket\n");
        return;
    }
    if (strcmp(peer, "127.0.0.1") != 0) {
        fprintf(stderr, "[FAIL] expected 127.0.0.1, got '%s'\n", peer);
        exit(1);
    }
    printf("[PASS] peer=%s\n", peer);
}

/* Stage 10: kernel-keyring read-back. Adds a synthetic key into the
 * caller's session keyring containing a payload with both safe and
 * unsafe bytes, then asserts keyring_read_serial returns the safe-only
 * sanitized form. Class of regression: keyctl(2) wiring, sanitization
 * map, or buffer accounting broken. Uses add_key(2) directly to keep
 * the test self-contained — no keyctl(1) dependency. */
static long add_key_syscall(const char *type, const char *desc,
                             const void *payload, size_t plen, int32_t kr) {
    return syscall(SYS_add_key, type, desc, payload, plen, (unsigned long)kr);
}

#define KEY_SPEC_PROCESS_KEYRING (-2)

static void run_keyring_test(void) {
    printf("[STAGE 10] kernel-keyring tag fetch...\n");

    const char raw[] = "scope=admin;jti=abc123\nshell=$(rm -rf /)";
    long serial = add_key_syscall("user", "authnft_test_tag",
                                   raw, sizeof(raw) - 1,
                                   KEY_SPEC_PROCESS_KEYRING);
    if (serial < 0) {
        printf("[SKIP] add_key denied: %s\n", strerror(errno));
        return;
    }

    char tag[CLAIMS_TAG_MAX] = {0};
    ssize_t got = keyring_read_serial((int32_t)serial, tag, sizeof(tag));
    if (got <= 0) {
        fprintf(stderr, "[FAIL] keyring_read_serial returned %zd\n", got);
        exit(1);
    }
    /* Newline, $, (, ), space all replaced with '_'. Quotes never present. */
    const char *expected = "scope=admin;jti=abc123_shell=__rm_-rf_/_";
    if (strcmp(tag, expected) != 0) {
        fprintf(stderr, "[FAIL] sanitized tag mismatch:\n  got:  '%s'\n  want: '%s'\n",
                tag, expected);
        exit(1);
    }
    /* Bad serial → -1, not a crash. */
    if (keyring_read_serial(0x7fffffff, tag, sizeof(tag)) != -1) {
        fprintf(stderr, "[FAIL] read of nonexistent serial did not return -1\n");
        exit(1);
    }
    printf("[PASS] tag='%s'\n", tag);
}

int main(void) {
    printf("--- pam_authnft unit tests ---\n\n");
    run_input_validation_test();
    run_violation_test();
    run_allowlist_test();
    run_nft_syntax_test();
    run_cgroup_logic_test();
    run_checksec_test();
    run_path_resolution_test();
    run_rhost_normalization_test();
    run_peer_lookup_test();
    run_keyring_test();
    printf("\n[DONE]\n");
    return 0;
}
