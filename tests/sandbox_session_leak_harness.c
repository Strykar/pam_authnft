// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Regression harness for the seccomp-sandbox session leak.
 *
 * pam_authnft applies its seccomp filter inside pam_sm_open_session. PAM
 * drivers that fork a session-command process AFTER pam_open_session
 * returns — sshd's monitor is the canonical one — would have that child
 * inherit the filter. fork/clone and execve are not in the allowlist
 * (it was derived from a pamtester open+close cycle, which never forks a
 * command), so the session command is SIGSYS-killed. pamtester cannot
 * catch this because it never forks a command; this harness does.
 *
 * Sequence, mirroring sshd: pam_open_session, then fork()+exec a trivial
 * command, then report whether it ran. Built and run by
 * tests/sandbox_session_leak_test.sh.
 *
 *   bug present  -> fork()/clone() SIGSYS-kills this process; no
 *                   SESSION_FORK_EXEC_OK line, terminated by signal.
 *   bug fixed    -> the sandbox lives in a forked child of open_session,
 *                   this process is never filtered, the command runs,
 *                   SESSION_FORK_EXEC_OK=1.
 */

#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static int null_conv(int num, const struct pam_message **msg,
                     struct pam_response **resp, void *data) {
    (void)num; (void)msg; (void)data;
    *resp = NULL;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pam-service> <user> [rhost]\n", argv[0]);
        return 2;
    }
    const char *service = argv[1];
    const char *user = argv[2];
    const char *rhost = (argc > 3) ? argv[3] : "10.0.0.1";

    struct pam_conv conv = { null_conv, NULL };
    pam_handle_t *pamh = NULL;

    if (pam_start(service, user, &conv, &pamh) != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed\n");
        return 2;
    }
    (void)pam_set_item(pamh, PAM_RHOST, rhost);

    int rc = pam_open_session(pamh, 0);
    fprintf(stderr, "open_session rc=%d (%s)\n", rc, pam_strerror(pamh, rc));

    /* This is the line sshd's monitor reaches after do_pam_session: it
     * forks the process that becomes the user's session. If a filter was
     * left on us, the fork (glibc routes it through clone) SIGSYS-kills
     * the whole process right here, before any output below. */
    fprintf(stdout, "REACHED_SESSION_FORK\n");
    fflush(NULL);

    pid_t pid = fork();
    if (pid == 0) {
        execlp("/bin/true", "true", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    if (pid > 0)
        (void)waitpid(pid, &status, 0);

    int exec_ok = (pid > 0) && WIFEXITED(status) && WEXITSTATUS(status) == 0;

    (void)pam_close_session(pamh, 0);
    (void)pam_end(pamh, rc);

    printf("SESSION_FORK_EXEC_OK=%d\n", exec_ok);
    return exec_ok ? 0 : 1;
}
