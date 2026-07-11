// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Unit tests for peer_parse_diag_chunk's listen-port filter — the
 * rhost_policy=kernel disambiguation that picks the inbound server socket
 * over an outbound one the same process holds (nss_ldap, krb5-over-TCP).
 *
 * Why this file exists: the filter had no test that could fail. Unit stage 9
 * drives peer_lookup_tcp against the harness's own socket and SKIPs when it
 * cannot resolve one; integration 10.25's only container-reachable arm asserts
 * the lookup *fails* (the socketless control arm). So a regression that
 * dropped the filter entirely would have gone green everywhere.
 *
 * The discriminator: the OUTBOUND socket is placed FIRST in the netlink
 * buffer. Without the filter, the walker returns the first owned non-loopback
 * socket, which is the wrong one. Only a working filter skips it and returns
 * the inbound peer. Delete the `if (owned && n_listen > 0)` block in
 * src/peer_lookup.c and test_listener_preferred() fails.
 *
 * Compiled with -DFUZZ_BUILD so peer_parse_diag_chunk loses `static`, the
 * same mechanism the libFuzzer harnesses use. No root, no network.
 */

#include "authnft.h"

#include <arpa/inet.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/* Declared non-static when src/peer_lookup.c is built with -DFUZZ_BUILD. */
int peer_parse_diag_chunk(const void *buf, size_t len,
                          const ino_t *inodes, int n_inodes,
                          char *out, size_t out_sz,
                          char *pending, size_t pending_sz,
                          const uint16_t *listen_ports, int n_listen);

static int failures;
#define FAIL(...) do { \
    fprintf(stderr, "[FAIL] " __VA_ARGS__); fputc('\n', stderr); failures++; \
} while (0)

/* Append one SOCK_DIAG_BY_FAMILY reply describing an ESTABLISHED v4 socket. */
static size_t put_sock(char *buf, size_t off, uint16_t sport,
                       const char *dst_ip, uint32_t inode)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + off);
    size_t len = NLMSG_LENGTH(sizeof(struct inet_diag_msg));

    memset(nlh, 0, NLMSG_ALIGN(len));
    nlh->nlmsg_len = (uint32_t)len;
    nlh->nlmsg_type = SOCK_DIAG_BY_FAMILY;

    struct inet_diag_msg *dm = (struct inet_diag_msg *)NLMSG_DATA(nlh);
    dm->idiag_family = AF_INET;
    dm->idiag_inode = inode;
    dm->id.idiag_sport = htons(sport);      /* local port: listener or not */
    inet_pton(AF_INET, dst_ip, &dm->id.idiag_dst);

    return off + NLMSG_ALIGN(len);
}

static size_t put_done(char *buf, size_t off)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + off);
    memset(nlh, 0, NLMSG_HDRLEN);
    nlh->nlmsg_len = NLMSG_LENGTH(0);
    nlh->nlmsg_type = NLMSG_DONE;
    return off + NLMSG_ALIGN(nlh->nlmsg_len);
}

/* Both sockets are owned by the session. The outbound one is FIRST. */
#define INO_OUTBOUND 4001u          /* e.g. nss_ldap, ephemeral local port */
#define INO_INBOUND  4002u          /* the ssh connection, local port 22   */
#define PORT_OUTBOUND 54321
#define PORT_INBOUND  22
#define IP_LDAP   "198.51.100.9"    /* peer of the outbound socket */
#define IP_CLIENT "203.0.113.5"     /* peer of the inbound socket — the truth */

static size_t build_two_sockets(char *buf)
{
    size_t off = 0;
    off = put_sock(buf, off, PORT_OUTBOUND, IP_LDAP,   INO_OUTBOUND);
    off = put_sock(buf, off, PORT_INBOUND,  IP_CLIENT, INO_INBOUND);
    off = put_done(buf, off);
    return off;
}

/* With the host's listen ports known, the outbound socket must be skipped
 * even though it comes first, and the inbound peer returned. */
static void test_listener_preferred(void)
{
    char buf[1024];
    size_t len = build_two_sockets(buf);
    const ino_t inodes[] = { INO_OUTBOUND, INO_INBOUND };
    const uint16_t listen_ports[] = { PORT_INBOUND };
    char out[IP_STR_MAX] = {0}, pending[IP_STR_MAX] = {0};

    int rc = peer_parse_diag_chunk(buf, len, inodes, 2,
                                   out, sizeof(out), pending, sizeof(pending),
                                   listen_ports, 1);
    if (rc != 1)
        FAIL("listener-preferred: rc=%d, expected 1 (a peer was resolved)", rc);
    else if (strcmp(out, IP_CLIENT) != 0)
        FAIL("listener-preferred: got '%s', expected '%s' — the outbound "
             "socket won, so the listen-port filter is not being applied",
             out, IP_CLIENT);
}

/* n_listen == 0 disables the filter (listen-port enumeration denied). The
 * documented fallback is the first owned non-loopback socket — which here is
 * the outbound one. This pins the fallback the man page promises. */
static void test_filter_disabled_falls_back_to_first(void)
{
    char buf[1024];
    size_t len = build_two_sockets(buf);
    const ino_t inodes[] = { INO_OUTBOUND, INO_INBOUND };
    char out[IP_STR_MAX] = {0}, pending[IP_STR_MAX] = {0};

    int rc = peer_parse_diag_chunk(buf, len, inodes, 2,
                                   out, sizeof(out), pending, sizeof(pending),
                                   NULL, 0);
    if (rc != 1)
        FAIL("filter-disabled: rc=%d, expected 1", rc);
    else if (strcmp(out, IP_LDAP) != 0)
        FAIL("filter-disabled: got '%s', expected '%s' (first owned socket)",
             out, IP_LDAP);
}

/* An owned socket whose local port is not a listener, with no inbound socket
 * present, must resolve nothing rather than reporting the outbound peer as
 * the session's rhost. */
static void test_outbound_only_resolves_nothing(void)
{
    char buf[1024];
    size_t off = put_sock(buf, 0, PORT_OUTBOUND, IP_LDAP, INO_OUTBOUND);
    off = put_done(buf, off);
    const ino_t inodes[] = { INO_OUTBOUND };
    const uint16_t listen_ports[] = { PORT_INBOUND };
    char out[IP_STR_MAX] = {0}, pending[IP_STR_MAX] = {0};

    int rc = peer_parse_diag_chunk(buf, off, inodes, 1,
                                   out, sizeof(out), pending, sizeof(pending),
                                   listen_ports, 1);
    if (rc != 0 || out[0] != '\0')
        FAIL("outbound-only: rc=%d out='%s', expected rc=0 and no peer "
             "(an outbound socket must not become the session rhost)",
             rc, out);
}

/* A socket the session does not own is ignored even on a listener port. */
static void test_unowned_socket_ignored(void)
{
    char buf[1024];
    size_t len = build_two_sockets(buf);
    const ino_t inodes[] = { 9999u };            /* owns neither socket */
    const uint16_t listen_ports[] = { PORT_INBOUND };
    char out[IP_STR_MAX] = {0}, pending[IP_STR_MAX] = {0};

    int rc = peer_parse_diag_chunk(buf, len, inodes, 1,
                                   out, sizeof(out), pending, sizeof(pending),
                                   listen_ports, 1);
    if (rc != 0 || out[0] != '\0')
        FAIL("unowned: rc=%d out='%s', expected rc=0 and no peer", rc, out);
}

int main(void)
{
    test_listener_preferred();
    test_filter_disabled_falls_back_to_first();
    test_outbound_only_resolves_nothing();
    test_unowned_socket_ignored();

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("peer_lookup: all tests passed\n");
    return 0;
}
