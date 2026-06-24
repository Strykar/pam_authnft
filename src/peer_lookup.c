// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Peer-IP resolution via NETLINK_SOCK_DIAG (see ss(8)). PAM_RHOST is
 * application-supplied and under sshd UseDNS=yes is a hostname, not an
 * IP; asking the kernel for the remote address of the session process's
 * own ESTABLISHED TCP socket is authoritative instead. Rationale in
 * docs/ARCHITECTURE.txt and pam_authnft(8).
 *
 * Uses only allowlisted syscalls (socket/sendmsg/recvmsg/close for
 * netlink, plus openat/getdents64/readlink for the /proc fd walk).
 * No additions to src/sandbox.c required.
 */

#define RECV_BUF   (8 * 1024)

/* Parse a /proc/<pid>/fd/<n> readlink target like "socket:[12345]" into
 * an inode number. Returns 1 on success, 0 if the target doesn't match
 * the expected format. Exposed (non-static) under FUZZ_BUILD so
 * fuzz_socket_inode can target it. */
#ifndef FUZZ_BUILD
static
#endif
int parse_socket_inode(const char *target, unsigned long *out_inode) {
    if (!target || !out_inode) return 0;
    unsigned long ino;
    if (sscanf(target, "socket:[%lu]", &ino) != 1) return 0;
    *out_inode = ino;
    return 1;
}

/* Collect socket inodes held by `pid` by readlink-ing each entry under
 * /proc/<pid>/fd. Returns the count or -1 on failure. On exit,
 * *truncated is set to 1 if at least one socket inode was observed
 * beyond `cap` and dropped. Non-static so the unit test (test_suite.c
 * STAGE 11) can pin the cap behavior; not exported from the .so. */
int collect_socket_inodes(pid_t pid, ino_t *inodes, size_t cap,
                          int *truncated) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/fd", (int)pid);

    DIR *d = opendir(path);
    if (!d) return -1;

    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (strlen(de->d_name) > 8) continue;  /* fd numbers, never long */

        char linkpath[96];
        char target[128];
        int k = snprintf(linkpath, sizeof(linkpath), "%s/%s", path, de->d_name);
        if (k < 0 || (size_t)k >= sizeof(linkpath)) continue;
        ssize_t n = readlink(linkpath, target, sizeof(target) - 1);
        if (n <= 0) continue;
        target[n] = '\0';

        unsigned long ino;
        if (!parse_socket_inode(target, &ino)) continue;

        if ((size_t)count >= cap) {
            *truncated = 1;
            break;
        }
        inodes[count++] = (ino_t)ino;
    }
    closedir(d);
    return count;
}

/* Send one SOCK_DIAG_BY_FAMILY request for `family`, filtering to
 * TCP_ESTABLISHED. Returns 0 on successful send. */
static int send_diag_request(int fd, int family) {
    struct {
        struct nlmsghdr       nlh;
        struct inet_diag_req_v2 req;
    } msg;
    memset(&msg, 0, sizeof(msg));

    msg.nlh.nlmsg_len   = sizeof(msg);
    msg.nlh.nlmsg_type  = SOCK_DIAG_BY_FAMILY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.nlh.nlmsg_seq   = 1;

    msg.req.sdiag_family   = (uint8_t)family;
    msg.req.sdiag_protocol = IPPROTO_TCP;
    msg.req.idiag_states   = 1U << TCP_ESTABLISHED;

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = &msg, .iov_len = sizeof(msg) };
    struct msghdr m = {
        .msg_name    = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };
    return sendmsg(fd, &m, 0) < 0 ? -1 : 0;
}

/*
 * Pure parser: walk one netlink response buffer and look for a match.
 * No I/O; takes bytes already in memory. Refactored out of
 * scan_diag_reply so that fuzz_netlink_diag can target it directly.
 *
 * Returns:
 *   1  non-loopback match written to out[out_sz]
 *   0  NLMSG_DONE seen, no match (pending may have been populated)
 *  -1  protocol error (NLMSG_ERROR or short payload)
 *   2  buffer exhausted without DONE; caller should recv more
 *
 * `pending` is in/out: a loopback IP is held back here; if a later
 * chunk produces a non-loopback match it wins, otherwise the caller
 * promotes pending to out on DONE.
 */
#ifndef FUZZ_BUILD
static
#endif
int peer_parse_diag_chunk(const void *buf, size_t len,
                          const ino_t *inodes, int n_inodes,
                          char *out, size_t out_sz,
                          char *pending, size_t pending_sz) {
    /* Manual walk rather than NLMSG_OK/NLMSG_NEXT: those macros use
     * NLMSG_ALIGN-aware advancement but NLMSG_OK only validates
     * nlmsg_len <= remaining (without alignment). A crafted nlmsg_len
     * whose 4-byte-aligned size exceeds `remaining` slips past
     * NLMSG_OK, then NLMSG_NEXT's `remaining -= align(nlmsg_len)`
     * underflows the size_t, and the next iteration dereferences `nlh`
     * past the buffer. Hand-rolled walk validates alignment too. */
    const char *cur = (const char *)buf;
    size_t remaining = len;

    while (remaining >= sizeof(struct nlmsghdr)) {
        const struct nlmsghdr *nlh = (const struct nlmsghdr *)cur;

        if (nlh->nlmsg_len < sizeof(struct nlmsghdr) ||
            nlh->nlmsg_len > remaining)
            return -1;

        if (nlh->nlmsg_type == NLMSG_DONE) {
            if (pending[0] && out_sz > strlen(pending)) {
                memcpy(out, pending, strlen(pending) + 1);
                return 1;
            }
            return 0;
        }
        if (nlh->nlmsg_type == NLMSG_ERROR) return -1;

        /* Payload must hold a full inet_diag_msg before we cast. */
        if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg)))
            return -1;

        const struct inet_diag_msg *dm =
            (const struct inet_diag_msg *)(cur + NLMSG_HDRLEN);

        int owned = 0;
        for (int i = 0; i < n_inodes; i++) {
            if ((ino_t)dm->idiag_inode == inodes[i]) { owned = 1; break; }
        }

        if (owned) {
            char tmp[IP_STR_MAX];
            int matched_family = 0;
            if (dm->idiag_family == AF_INET) {
                if (inet_ntop(AF_INET, &dm->id.idiag_dst, tmp, sizeof(tmp)))
                    matched_family = 1;
            } else if (dm->idiag_family == AF_INET6) {
                if (inet_ntop(AF_INET6, &dm->id.idiag_dst, tmp, sizeof(tmp)))
                    matched_family = 1;
            }

            if (matched_family) {
                int is_loop = (strncmp(tmp, "127.", 4) == 0) ||
                              (strcmp(tmp, "::1") == 0);
                if (is_loop) {
                    if (!pending[0]) {
                        size_t L = strlen(tmp);
                        if (L < pending_sz) memcpy(pending, tmp, L + 1);
                    }
                } else if (out_sz > strlen(tmp)) {
                    memcpy(out, tmp, strlen(tmp) + 1);
                    return 1;
                }
            }
        }

        size_t aligned = NLMSG_ALIGN(nlh->nlmsg_len);
        if (aligned > remaining) break;  /* clean exit on trailing padding */
        cur += aligned;
        remaining -= aligned;
    }
    return 2;
}

/* Scan dump responses, and when an entry's inode matches one we own,
 * format its remote address into out[out_sz]. Returns 1 on match, 0 if
 * the dump ended without a match, -1 on protocol error. Non-loopback
 * peers are preferred; a loopback match is held back and only emitted
 * if nothing better arrives. */
static int scan_diag_reply(int fd, const ino_t *inodes, int n_inodes,
                            char *out, size_t out_sz) {
    char buf[RECV_BUF];
    char pending[IP_STR_MAX] = {0};

    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return -1;

        int rc = peer_parse_diag_chunk(buf, (size_t)n,
                                        inodes, n_inodes,
                                        out, out_sz,
                                        pending, sizeof(pending));
        if (rc != 2) return rc;
    }
}

int peer_lookup_tcp(pam_handle_t *pamh, pid_t pid, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return 0;
    out[0] = '\0';

    ino_t inodes[INODES_CAP];
    int truncated = 0;
    int n = collect_socket_inodes(pid, inodes, INODES_CAP, &truncated);
    if (n <= 0) return 0;
    if (truncated && pamh) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: /proc/%d/fd has more than %d socket inodes — "
                   "peer lookup may miss the session's TCP socket",
                   (int)pid, INODES_CAP);
    }

    /* Fresh netlink socket per address family. Reusing a single socket
     * for back-to-back AF_INET6 then AF_INET queries can leave bytes from
     * the v6 response in the kernel queue when the v4 read starts; the
     * scan loop would consume v6 replies under the v4 query and miss the
     * actual v4 socket match. Two short-lived sockets are simpler and
     * avoid every flavor of buffered-leftover bug. */
    int found = 0;
    for (int i = 0; i < 2 && !found; i++) {
        int family = (i == 0) ? AF_INET6 : AF_INET;
        int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
        if (fd < 0) continue;
        if (send_diag_request(fd, family) == 0 &&
            scan_diag_reply(fd, inodes, n, out, out_sz) == 1) {
            found = 1;
        }
        close(fd);
    }
    return found;
}
