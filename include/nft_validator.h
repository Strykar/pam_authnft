// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#ifndef NFT_VALIDATOR_H
#define NFT_VALIDATOR_H

/*
 * Internal header. NOT installed by `make install`. Declares the pure
 * input-validation surface of the nft handler, extracted into its own
 * translation unit (src/nft_validator.c) so unit tests can exercise it
 * deterministically and mutation testing has a clean target.
 *
 * Visibility model: symbols are unconditionally extern in source.
 * pam_authnft.map's `local: *;` catch-all keeps them out of the .so
 * ABI. Test binaries link against the .o files directly, so they see
 * the symbols regardless of the .so version script. This header
 * encodes that boundary — anyone who #includes it is either nft
 * handler code or test code, never a downstream consumer of the .so.
 */

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

/* Rejection list for nft fragment verbs. Validated by
 * validate_fragment_buf(); each entry must be rejected on its own
 * line. Exposed externally for test-time structural iteration; the
 * companion `_count` is the canonical length (no NULL sentinel). */
extern const char *const nft_validator_bad_verbs[];
extern const size_t       nft_validator_bad_verbs_count;

/* Fragment validation against an in-memory buffer. Returns 0 on
 * accept, -1 on reject; on reject, the reason is logged via
 * pam_syslog and the caller may use the buffer for diagnostics.
 * `path` is used only for log messages — the validator never opens
 * or stats it. */
int validate_fragment_buf(pam_handle_t *pamh, const char *path,
                          const char *buf, size_t buf_len);

/* Token-aware placeholder substitution for nft fragments. Replaces
 * @session_v4, @session_v6, @session_cg, @session_chain with their
 * per-session expansions. Skips occurrences inside #-comments and
 * "..." quoted strings. Returns a new malloc'd buffer; caller must
 * free(). Returns NULL on allocation failure or on src_len * ratio
 * overflow. */
char *substitute_placeholders(const char *src, size_t src_len,
                              const char *placeholders[4],
                              const char *replacements[4]);

/* Pure membership predicate over getgrouplist(3)'s output. Extracted
 * from the inline loop in nft_handler_setup so the SSSD-naive
 * regression closed by the earlier getgrouplist switch has a
 * standalone test surface. */
bool user_in_group(gid_t target, const gid_t *groups, size_t ngroups);

#endif /* NFT_VALIDATOR_H */
