// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include <seccomp.h>
#include <sys/prctl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>

/*
 * Seccomp-BPF allowlist for the PAM module.
 *
 * Default action: SCMP_ACT_KILL (SIGSYS on violation).
 * PR_SET_NO_NEW_PRIVS is set before loading the filter.
 *
 * This list was derived empirically: strace was run across a complete
 * pamtester open_session + close_session cycle and only syscalls observed
 * after sandbox_apply() returns are included. execve(2) appears in the
 * trace but originates from pamtester's own startup before dlopen() loads
 * this module — it is intentionally excluded.
 *
 * Bypass policy: this function unconditionally installs the filter.
 * Bypass for debug/trace is the caller's decision — see
 * is_debug_bypass_requested() in pam_entry.c which checks
 * AUTHNFT_NO_SANDBOX (env or PAM arg) and logs the bypass at LOG_DEBUG.
 * Direct callers (e.g., the unit-test harness) get the sandbox applied
 * unconditionally; this is intentional so a stray AUTHNFT_NO_SANDBOX=1
 * in a developer's environment cannot silently turn the seccomp tests
 * into no-ops.
 */

int sandbox_apply(pam_handle_t *pamh) {
    (void)pamh;
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) return -1;

    /* Accumulate every rule's return. seccomp_rule_add returns 0 on
     * success and -errno on failure; OR-ing the results leaves rc
     * non-zero if any single registration failed, so a silently-dropped
     * rule (which would either trip an unintended SIGSYS at runtime or
     * leave a hole in the allowlist) is caught before the filter loads. */
    int rc = 0;

    /* Memory */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);

    /* File I/O — fragment reads, /proc/<pid>/cgroup, /etc/passwd, /etc/group */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    /* musl's fopen/open route through the legacy open(2) on x86_64 where glibc
     * goes via openat; the fragment read and NSS lookups hit it on a musl
     * build. Allowlist both so the module is portable across libcs. */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    /* musl routes stdio through the vectored read/write where glibc uses the
     * scalar pair: the fragment read (fopen + fread in read_file) lands on
     * readv on a musl build. Same I/O class as read/write; allowlisting both
     * keeps the module portable across libcs without a build flag. */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstatfs), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statx), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat2), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    /* Session-identity file is opened 0600, widened to 0640 with fchmod(2)
     * (umask-proof), then fchown'd to root:authnft so members of the authnft
     * group can read it without world-readable leakage of claims_tag. Both
     * act on an fd we opened ourselves — the minimum-surface form (no path
     * lookup, no race). See src/session_file.c. */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown), 0);

    /* Sockets — AF_NETLINK (libnftables/libmnl) + AF_UNIX (sd-bus) */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
    /* The cgroup-only binding (empty remote_ip from a non-IP PAM_RHOST under
     * the default policy) builds a `socket cgroupv2 level 0` set; libnftables
     * batches that path's netlink writes through sendmmsg where the IP-keyed
     * sets use plain sendmsg. Same security profile as sendmsg. */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmmsg), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 0);

    /* I/O multiplexing */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_pwait2), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6), 0);

    /* libsystemd event loop */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rseq), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_create), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);

    /* Kernel keyring — claims_env=NAME path reads one key via keyctl(2). */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(keyctl), 0);

    /* Process */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    /* libnftables reads the kernel release via uname(2) on the cgroup-only
     * set path (see sendmmsg above); read-only, same class as getpid. */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    /* Credential queries by libc/libsystemd — observed on Fedora's glibc
     * (not Arch's) during `make trace-container`. Same class as getpid. */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    /* Filesystem metadata query — libnftables or libsystemd on Fedora.
     * fstatfs is already allowlisted above; statfs is its path-based twin. */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs), 0);
    /* Session-identity file under /run/authnft/sessions/<scope_unit>.json.
     * Empirically on Arch glibc 2.43 + Linux 6.18, rename() and unlink()
     * both go through the *legacy* single-arg syscalls (SYS_rename,
     * SYS_unlink), not their newer *at variants. On other glibc / libc
     * versions they may route through renameat / renameat2 / unlinkat.
     * musl in particular routes rename(3) through renameat(AT_FDCWD, ...),
     * and glibc < 2.28 did the same. Allowlist every variant so the
     * module is portable without a distro-specific build flag. See
     * docs/INTEGRATIONS.txt §5.6. */
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(renameat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(renameat2), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlinkat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);

    /* A failed registration means the loaded filter would not match the
     * allowlist this code declares — fail closed rather than load a
     * filter with an unknown hole. */
    if (rc != 0) {
        seccomp_release(ctx);
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        seccomp_release(ctx);
        return -1;
    }
    int ret = seccomp_load(ctx);
    seccomp_release(ctx);
    return ret;
}
