// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Pure input-validation utilities. Extracted from src/pam_entry.c
 * (util_is_valid_username, util_normalize_ip) and src/bus_handler.c
 * (validate_cgroup_path) so unit + mutation testing can exercise
 * them deterministically. See include/util_validators.h for the
 * visibility model.
 *
 * validate_cgroup_path was previously gated behind #ifndef FUZZ_BUILD
 * static #endif so the fuzz harness could call it across TU
 * boundaries. That conditional is gone now — the function is
 * unconditionally extern, hidden from the .so ABI by
 * pam_authnft.map's `local: *;` catch-all. Convention established
 * by #49; applied here.
 */

#include "authnft.h"
#include "util_validators.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

int util_is_valid_username(const char *user)
{
    if (!user || *user == '\0') return 0;
    size_t len = strlen(user);
    if (len > MAX_USER_LEN || user[0] == '-' || user[0] == '.') return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)user[i]) &&
            user[i] != '-' && user[i] != '_' && user[i] != '.')
            return 0;
    }
    return 1;
}

int util_normalize_ip(const char *in, char *out, size_t out_sz)
{
    if (!in || !out || out_sz == 0) return 0;
    unsigned char addr_buf[sizeof(struct in6_addr)];

    /* Strip an IPv6 zone suffix ("fe80::1%eth0" -> "fe80::1"). nftables
     * ip6 saddr does not accept zone identifiers; the zone is meaningful
     * only to the host's socket layer, and discarding it here lets the
     * kernel's normal scope rules handle routing. */
    const char *pct = strchr(in, '%');
    size_t core_len = pct ? (size_t)(pct - in) : strlen(in);
    if (core_len == 0 || core_len >= out_sz) return 0;

    char core[IP_STR_MAX];
    if (core_len >= sizeof(core)) return 0;
    memcpy(core, in, core_len);
    core[core_len] = '\0';

    if (inet_pton(AF_INET, core, addr_buf) == 1) {
        memcpy(out, core, core_len + 1);
        return 1;
    }

    if (inet_pton(AF_INET6, core, addr_buf) == 1) {
        /* v4-mapped v6 (::ffff:a.b.c.d) → extract as plain IPv4 so the
         * element lands in the per-session IPv4 set rather than the IPv6 set.
         * Common when sshd listens on :: with IPV6_V6ONLY=0. */
        const struct in6_addr *a6 = (const struct in6_addr *)addr_buf;
        if (IN6_IS_ADDR_V4MAPPED(a6)) {
            if (!inet_ntop(AF_INET, &a6->s6_addr[12], out, (socklen_t)out_sz))
                return 0;
            return 1;
        }
        memcpy(out, core, core_len + 1);
        return 1;
    }

    return 0;
}

int validate_cgroup_path(const char *cgroup_path, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return -1;
    out[0] = '\0';

    /* Must start with '/' */
    if (!cgroup_path || cgroup_path[0] != '/') return -1;

    const char *p = cgroup_path + 1; /* skip leading '/' */

    /* First component: "authnft.slice" (13 chars) followed by '/' */
    const char *slash = strchr(p, '/');
    if (!slash) return -1;
    size_t first_len = (size_t)(slash - p);
    if (first_len != 13 || memcmp(p, "authnft.slice", 13) != 0) return -1;

    /* Second component: "<name>.scope" with no further slashes */
    const char *second = slash + 1;
    if (second[0] == '\0') return -1;
    if (strchr(second, '/') != NULL) return -1;

    /* Must end with ".scope" */
    size_t slen = strlen(second);
    if (slen < 7 || memcmp(second + slen - 6, ".scope", 6) != 0) return -1;

    /* Strip leading '/' and copy */
    size_t total = strlen(p);
    if (total >= out_sz) return -1;
    memcpy(out, p, total + 1);
    return 0;
}
