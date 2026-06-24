// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Regression harness for the fragment-rejection message reaching the user.
 *
 * sshd's PAM conversation (sshpam_store_conv) appends PAM_ERROR_MSG text to a
 * process-global sshbuf (loginmsg) that the monitor later ships to the client.
 * pam_authnft runs nft_handler_setup in a forked child, so a pam_error emitted
 * there lands only in the child's copy of that global and never reaches the
 * user. This harness models that global: the conversation captures into a
 * static buffer, and main (the parent) checks whether the message arrived
 * after pam_open_session.
 *
 *   message lost (bug):  child emitted it -> parent's buffer empty -> exit 1.
 *   message delivered:   parent emitted it -> buffer holds it -> exit 0.
 *
 * Driven by tests/reject_message_test.sh with a deliberately world-writable
 * fragment, which the setup rejects on the perms check.
 */

#include <security/pam_appl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Stands in for sshd's process-global loginmsg. */
static char g_loginmsg[4096];

static int capture_conv(int num, const struct pam_message **msg,
                        struct pam_response **resp, void *data) {
    (void)data;
    for (int i = 0; i < num; i++) {
        if (msg[i] && msg[i]->msg &&
            (msg[i]->msg_style == PAM_ERROR_MSG ||
             msg[i]->msg_style == PAM_TEXT_INFO)) {
            size_t room = sizeof(g_loginmsg) - strlen(g_loginmsg) - 1;
            strncat(g_loginmsg, msg[i]->msg, room);
        }
    }
    *resp = calloc((size_t)num, sizeof(struct pam_response));
    return *resp ? PAM_SUCCESS : PAM_BUF_ERR;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pam-service> <user>\n", argv[0]);
        return 2;
    }
    /* On the reject path pam_authnft stops the transient scope, which SIGTERMs
     * its members — and this process is the session pid placed in that scope.
     * The reject message is emitted before that teardown, so ignore SIGTERM to
     * survive long enough to report what the conversation captured. */
    signal(SIGTERM, SIG_IGN);

    struct pam_conv conv = { capture_conv, NULL };
    pam_handle_t *pamh = NULL;
    if (pam_start(argv[1], argv[2], &conv, &pamh) != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed\n");
        return 2;
    }
    (void)pam_set_item(pamh, PAM_RHOST, "10.0.0.1");
    (void)pam_open_session(pamh, 0);
    (void)pam_close_session(pamh, 0);
    (void)pam_end(pamh, 0);

    printf("PARENT_LOGINMSG=[%s]\n", g_loginmsg);
    return g_loginmsg[0] ? 0 : 1;
}
