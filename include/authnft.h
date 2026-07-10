// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#ifndef AUTHNFT_H
#define AUTHNFT_H

#ifdef DEBUG
    #define DEBUG_PRINT(fmt, ...) \
        do { fprintf(stderr, "authnft [DEBUG]: " fmt "\n", ##__VA_ARGS__); } while (0)
#else
    #define DEBUG_PRINT(fmt, ...) do {} while (0)
#endif

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

/* --- Configuration Constants --- */
#define RULES_DIR "/etc/authnft/users"
#define TABLE_NAME "authnft"

/* --- Buffer Management --- */
#define CMD_BUF_SIZE 2048
#define UNIT_BUF_SIZE 128
#define MAX_USER_LEN 32
#define IP_STR_MAX   64   /* INET6_ADDRSTRLEN (46) + headroom */
#define CLAIMS_TAG_MAX 192 /* sanitized payload length cap */
#define CORRELATION_ID_MAX 64 /* journal/audit correlation token */
#define INODES_CAP 64      /* cap on /proc/<pid>/fd inode scan in peer_lookup */
#define CGROUP_PATH_MAX 192 /* "authnft.slice/authnft-<user>-<pid>.scope" + slack */
#define SET_NAME_MAX 80    /* "session_<user>_<pid>_v4" */
#define CHAIN_NAME_MAX 80  /* "session_<user>_<pid>" */

/*
 * Session data persisted via pam_set_data("authnft_cg_id", ...).
 * The key name predates this struct; it is kept for compatibility with the
 * documented lifecycle invariant. `remote_ip[0] == '\0'` marks the cg-only
 * fallback path, where no src_ip was bound.
 *
 * `cg_path` holds the session's cgroupv2 path (without leading slash),
 * e.g. "authnft.slice/authnft-alice-12345.scope". This is the value the
 * kernel resolves to a cgroupv2 inode at nft insert time via the
 * `socket cgroupv2 level 2` expression.
 *
 * `scope_unit` is the systemd transient-scope unit name,
 * "authnft-<user>-<pid>.scope". Used as the filename key for
 * /run/authnft/sessions/<scope_unit>.json and as an audit field.
 *
 * Per-session nftables state: each session gets its own chain
 * (`chain_name`) and three sets (`set_v4`, `set_v6`, `set_cg`).
 * A jump rule in the shared `filter` chain dispatches to the
 * per-session chain; `jump_handle` stores its nftables handle for
 * cleanup. This is the pf-anchor-equivalent isolation model.
 *
 * `correlation_id` is a short opaque token used to join the open and
 * close audit events for the same session across the systemd journal.
 * Captured from PAM env "AUTHNFT_CORRELATION" (sanitized) or synthesized
 * at open_session if the env var is absent.
 */
typedef struct {
    char     cg_path[CGROUP_PATH_MAX];
    char     scope_unit[UNIT_BUF_SIZE];
    char     remote_ip[IP_STR_MAX];
    char     claims_tag[CLAIMS_TAG_MAX];  /* "" if no keyring source configured */
    char     correlation_id[CORRELATION_ID_MAX];
    char     chain_name[CHAIN_NAME_MAX];
    char     set_v4[SET_NAME_MAX];
    char     set_v6[SET_NAME_MAX];
    char     set_cg[SET_NAME_MAX];
    uint64_t jump_handle;                 /* 0 = not captured */
} authnft_session_t;

/*
 * Why a fragment was rejected, for the user-facing message. nft_handler_setup
 * runs in a forked child (run_sandboxed_nft_setup), where a pam_error would
 * write to the child's copy of the PAM conversation state and never reach the
 * user. The child reports the reason instead, and the parent emits the
 * message; on the bypass path the parent emits it in-process the same way.
 */
typedef enum {
    AUTHNFT_REJECT_NONE = 0,
    AUTHNFT_REJECT_FRAGMENT_MISSING,
    AUTHNFT_REJECT_FRAGMENT_PERMS,
    AUTHNFT_REJECT_FRAGMENT_UNREADABLE,
    AUTHNFT_REJECT_FRAGMENT_CONTENT,
    AUTHNFT_REJECT_FRAGMENT_SYNTAX,
} authnft_reject_reason;

/*
 * nft_user_in_authnft_group:
 * Resolves whether `user` is a member of the 'authnft' group via
 * getgrouplist(3) (full NSS). Returns 1 for a member, 0 otherwise. Called in
 * the setup child BEFORE sandbox_apply, so NSS backends (sss, ldap, systemd)
 * run unsandboxed and cannot SIGSYS-kill the child; keeping it in the child
 * rather than the parent also avoids leaving NSS connection state in the sshd
 * monitor. Never call it after the seccomp filter is installed.
 */
int nft_user_in_authnft_group(pam_handle_t *pamh, const char *user);

/*
 * nft_handler_setup:
 * Validates the user's root-owned fragment (verb scan, include-path check),
 * creates the per-session chain and three
 * per-session sets, inserts the session element, captures the jump-rule
 * handle, and loads the fragment with nftables placeholders substituted
 * for the four per-session names (@session_v4, @session_v6, @session_cg,
 * @session_chain).
 *
 * On success, sd->jump_handle is populated. On failure, any partially
 * created nftables state is best-effort cleaned up.
 *
 * session_pid is the pid recorded in the per-session element comment for
 * operator diagnostics. It is passed explicitly rather than read from
 * getpid() because this runs in a short-lived forked child (see
 * run_sandboxed_nft_setup in src/pam_entry.c), where getpid() would be
 * the child's transient pid, not the session's.
 *
 * reason (may be NULL) is set to the fragment-rejection cause so the caller
 * can emit the user-facing message from the parent; it is left
 * AUTHNFT_REJECT_NONE on success and on non-fragment errors.
 */
int nft_handler_setup(pam_handle_t *pamh, const char *user,
                      int session_pid, authnft_session_t *sd,
                      authnft_reject_reason *reason);

/*
 * nft_handler_cleanup:
 * Tears down the per-session nftables state: deletes the jump rule by
 * handle, flushes and deletes the per-session chain, deletes the three
 * per-session sets. Best-effort; logs on failure, returns PAM_SUCCESS
 * so the session can always unwind.
 */
int nft_handler_cleanup(pam_handle_t *pamh, const char *user,
                        const authnft_session_t *sd);

/*
 * nft_handler_cleanup_orphan:
 * Best-effort teardown when the sandboxed setup child died before rolling
 * back its own partial nft state. Recovers the jump-rule handle by listing
 * the shared chain (the killed child never reported it), then deletes the
 * jump rule, the per-session chain, and the three sets. Tolerates absent
 * objects, so it is a no-op if the child committed nothing.
 */
int nft_handler_cleanup_orphan(pam_handle_t *pamh, const char *user,
                               const authnft_session_t *sd);

/*
 * bus_handler_start:
 * Connects to systemd via D-Bus and creates a transient .scope unit under
 * authnft.slice, placing the session process into a named cgroup.
 */
int bus_handler_start(pam_handle_t *pamh, const char *user, int session_pid);

/*
 * bus_handler_stop:
 * Best-effort StopUnit on the transient scope created by bus_handler_start.
 * Used to roll back the scope on error paths in pam_sm_open_session that
 * fire after bus_handler_start succeeded but before nft_handler_setup
 * completed. Tolerates a missing unit (returns 0; the scope may have been
 * reaped between the start and stop, which is fine). Returns -1 on bus
 * connection errors.
 */
int bus_handler_stop(pam_handle_t *pamh, const char *user, int session_pid);

/*
 * sandbox_apply:
 * Installs a seccomp-BPF allowlist with SCMP_ACT_KILL default and sets
 * PR_SET_NO_NEW_PRIVS before loading the filter.
 */
int sandbox_apply(pam_handle_t *pamh);

/*
 * authnft_audit_fragment_reject:
 * Emit a structured AUDIT_USER_ERR record via libaudit when a session
 * is denied because the per-user fragment failed validation. Parallel
 * channel to the existing pam_syslog/pam_error reporting; visible to
 * SIEM consumers that scrape /var/log/audit/audit.log.
 *
 * `reason` is a short fixed identifier (no spaces, no quotes):
 *   "missing"     stat() on the fragment failed
 *   "perms"       fragment not root-owned, or world-writable
 *   "content"     validate_fragment_content rejected (verb / include)
 *   "nft-syntax"  libnftables rejected the fragment at load
 *
 * Audit emission failure (subsystem disabled, missing capability) is
 * non-fatal: the function returns silently and the rejection still
 * propagates as PAM_AUTH_ERR.
 */
void authnft_audit_fragment_reject(const char *user,
                                    const char *reason,
                                    const char *path);

/* util_is_valid_username moved to include/util_validators.h.
 * Callers that need it should #include "util_validators.h". */

/*
 * util_get_cgroup_path:
 * Resolves the session PID's cgroupv2 path via sd_pid_get_cgroup(3), strips
 * the leading '/', and writes it to out[out_sz]. Validates the
 * pam_authnft depth invariant (HANDOFF §3.1, §3.2): the path MUST be
 * "/authnft.slice/<name>.scope" exactly — anything deeper, shallower, or
 * outside authnft.slice is a misconfiguration that would silently produce
 * packet-level match failures under `socket cgroupv2 level 2`. Rejects
 * with a pam_syslog line naming the offending path. Returns 0 on success,
 * -1 on any failure. Does NOT stat(2) the cgroupfs entry; the kernel
 * resolves path-to-inode at nft insert time.
 */
int util_get_cgroup_path(pam_handle_t *pamh, pid_t pid, char *out, size_t out_sz);

/*
 * keyring_fetch_tag:
 * Reads a kernel-keyring entry whose serial number is supplied as the value
 * of PAM env var `env_var`. The payload is sanitized to a printable ASCII
 * subset and copied into out[out_sz] (NUL-terminated, truncated if longer
 * than CLAIMS_TAG_MAX). Returns 1 on success, 0 if env var is absent,
 * malformed, names a missing/inaccessible key, or the payload sanitizes to
 * an empty string. Does not log on absence; logs LOG_WARNING on retrieval
 * failure.
 *
 * Reads a single key via keyctl(2); no other syscalls.
 */
int keyring_fetch_tag(pam_handle_t *pamh, const char *env_var,
                      char *out, size_t out_sz);

/*
 * keyring_read_serial:
 * Internal helper exposed for unit testing. Reads `serial` from the kernel
 * keyring and writes a sanitized payload to out[out_sz]. Returns the
 * sanitized length, or -1 on error.
 */
ssize_t keyring_read_serial(int32_t serial, char *out, size_t out_sz);

/*
 * peer_lookup_tcp:
 * Derives the remote IP of an ESTABLISHED TCP socket owned by `pid` by
 * issuing a SOCK_DIAG_BY_FAMILY query over NETLINK_SOCK_DIAG (AF_INET6
 * first, then AF_INET) and matching returned inodes against socket inodes
 * walked from /proc/<pid>/fd/. At most INODES_CAP inodes are scanned; if
 * more exist, a LOG_WARNING is emitted via pamh (NULL-safe for unit tests).
 * Writes a canonical IP literal (inet_ntop form) into out[out_sz].
 * Returns 1 on success (first match used when multiple sockets found),
 * 0 on any failure (no TCP socket, netlink denied, buffer too small).
 * Uses only syscalls in
 * the existing seccomp allowlist; safe to call post-sandbox as well but
 * currently invoked pre-sandbox in lockstep with PAM_RHOST parsing.
 */
int peer_lookup_tcp(pam_handle_t *pamh, pid_t pid, char *out, size_t out_sz);

/*
 * session_file_write:
 * Writes /run/authnft/sessions/<scope_unit>.json containing session metadata
 * for out-of-band observers (SIEM, schedulers, monitoring). JSON schema v=2
 * is documented in docs/INTEGRATIONS.txt §5.6. Atomic via tempfile + rename.
 * Returns 0 on success, -1 on any failure. Session establishment does NOT
 * fail on a write error — the session file is best-effort observability.
 */
int session_file_write(pam_handle_t *pamh, const authnft_session_t *sd,
                       const char *user, int session_pid);

/*
 * session_file_remove:
 * Removes /run/authnft/sessions/<scope_unit>.json at close_session. Silent
 * on ENOENT (write may have failed or systemd-tmpfiles may have already
 * reaped a stale entry). Returns 0 on success or ENOENT, -1 otherwise.
 */
int session_file_remove(pam_handle_t *pamh, const char *scope_unit);

/*
 * event_correlation_capture:
 * Populates `out` with a correlation token usable to join open and close
 * audit events for the same session. If PAM env "AUTHNFT_CORRELATION" is
 * set by an upstream producer (e.g., identity broker), its sanitized value
 * is used; otherwise a timestamp+pid+random token is synthesized. Output
 * is always NUL-terminated and always non-empty.
 *
 * Sanitization character class: [A-Za-z0-9_.:-]. Characters outside the
 * class are dropped (not substituted) to keep tokens short and avoid
 * journal-field confusion.
 */
void event_correlation_capture(pam_handle_t *pamh, char *out, size_t out_sz);

/*
 * event_open_emit / event_close_emit:
 * Emit a structured journal entry via sd_journal_send(3). Fields are
 * documented in docs/INTEGRATIONS.txt §6.2. On sd_journal_send failure
 * (e.g., /run/systemd/journal/socket unreachable), falls back to
 * pam_syslog(LOG_INFO) so the event still lands in a readable log stream.
 * Never fails the session.
 */
void event_open_emit(pam_handle_t *pamh, const authnft_session_t *sd,
                     const char *user, int session_pid);
void event_close_emit(pam_handle_t *pamh, const authnft_session_t *sd,
                      const char *user);

/* util_normalize_ip moved to include/util_validators.h.
 * Callers that need it should #include "util_validators.h". */

#endif /* AUTHNFT_H */
