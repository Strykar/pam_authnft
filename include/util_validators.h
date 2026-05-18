// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#ifndef UTIL_VALIDATORS_H
#define UTIL_VALIDATORS_H

/*
 * Internal header. NOT installed by `make install`. Declares pure
 * input-validation utilities extracted from src/pam_entry.c and
 * src/bus_handler.c into src/util_validators.c so unit tests and
 * mutation testing can target them deterministically.
 *
 * Visibility model: symbols are unconditionally extern in source.
 * pam_authnft.map's `local: *;` catch-all keeps them out of the .so
 * ABI. Test binaries and fuzz harnesses link against the .o files
 * directly. This is the same precedent established by #49's
 * include/nft_validator.h; the conditional-extern pattern
 * (`#ifndef FUZZ_BUILD static #endif`) that previously protected
 * validate_cgroup_path is retired here.
 *
 * Single-purpose: one header per _validator.c TU. No _count
 * companions because none of these functions has an enumerated
 * rejection list; the convention from #49 for arrays applies when
 * applicable, not as ritual.
 */

#include <stddef.h>
#include <sys/types.h>

/* Reject usernames that contain anything other than [A-Za-z0-9._-],
 * are empty, exceed MAX_USER_LEN, or start with '-' or '.'. Returns
 * 1 if valid, 0 if not. First-line defence against path traversal
 * and shell-metacharacter injection via PAM_USER. */
int util_is_valid_username(const char *user);

/* Normalize a remote-host string into a form the per-session nft
 * set can index. Strips IPv6 zone suffixes ("fe80::1%eth0" →
 * "fe80::1"); extracts the embedded IPv4 from v4-mapped v6
 * addresses (::ffff:a.b.c.d → "a.b.c.d") so the element lands in
 * the v4 set rather than the v6 set. Returns 1 on success, 0 on
 * any failure (NULL inputs, empty input, parse failure, or output
 * buffer too small — the function rejects insufficient size rather
 * than truncating). */
int util_normalize_ip(const char *in, char *out, size_t out_sz);

/* Enforce the depth invariant on a cgroup path returned by
 * sd_pid_get_cgroup. Accepts exactly the form
 * "/authnft.slice/<name>.scope" — two components under the root.
 * On accept, copies the leading-slash-stripped form into `out`.
 * On reject (any failure including NULL inputs and insufficient
 * out_sz), out[0] is set to '\0'. Returns 0 on accept, -1 on
 * reject. */
int validate_cgroup_path(const char *cgroup_path, char *out, size_t out_sz);

#endif /* UTIL_VALIDATORS_H */
