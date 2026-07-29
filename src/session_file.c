// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Runtime session identity files under /run/authnft/sessions/<scope_unit>.json.
 *
 * Written on open_session after nft_handler_setup completes; removed on
 * close_session. Lets non-PAM observers (SIEM agents, workload schedulers,
 * container runtimes, operator dashboards) correlate a session scope back to
 * the pam_authnft session that created it without needing privileged access
 * to the PAM handle. The schema is versioned (v=2); future contract
 * revisions MUST be additive per docs/INTEGRATIONS.txt §5.6.
 *
 * File creation is atomic via a tempfile-plus-rename pattern. Directory is
 * created at boot by tmpfiles.d (data/authnft.tmpfiles); the module assumes
 * it exists and logs at LOG_WARNING if it does not — session establishment
 * is not failed on a session-file write error (observability is best-effort).
 */

#include "authnft.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define SESSION_DIR  "/run/authnft/sessions"
#define RUN_DIR      "/run/authnft"
#define MARK_COUNTER RUN_DIR "/session-mark-counter"
#define PATH_MAX_LEN 256
#define JSON_MAX     1024

/*
 * Session mark id allocation. See include/authnft.h for why the counter is
 * monotonic per boot and why 0 is reserved.
 *
 * Everything else in this file is best-effort observability. This is not: a
 * session with no id cannot be revoked at close, so every failure path
 * returns 0 and the caller denies the session rather than admitting one it
 * cannot later shut off.
 *
 * flock serialises concurrent open_sessions. Without it two logins racing
 * can read the same value and both take it, which is the id reuse that I4
 * shows resurrects revoked flows.
 */
uint32_t session_mark_alloc(pam_handle_t *pamh) {
    char buf[32];
    uint32_t cur = 0, next;
    int fd, len;
    ssize_t n;

    /* tmpfiles.d creates /run/authnft at boot, but the module can be
     * installed and a session opened before that has run. The session
     * identity file treats a missing directory as a warning and carries on,
     * because it is observability. This is not: without the counter no id
     * can be issued and every session is denied. Create it rather than
     * fail on an install-order accident. Mode matches data/authnft.tmpfiles. */
    if (mkdir(RUN_DIR, 0755) != 0 && errno != EEXIST) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: cannot create %s: %s", RUN_DIR, strerror(errno));
        return 0;
    }

    fd = open(MARK_COUNTER, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: cannot open %s: %s", MARK_COUNTER, strerror(errno));
        return 0;
    }
    if (flock(fd, LOCK_EX) != 0) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: cannot lock %s: %s", MARK_COUNTER, strerror(errno));
        close(fd);
        return 0;
    }

    n = pread(fd, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        char *end;
        unsigned long v;

        buf[n] = '\0';
        errno = 0;
        v = strtoul(buf, &end, 10);

        /* An absent or empty file is a legitimate fresh boot and starts at
         * 1. A file that exists but does not parse is not: strtoul yields 0
         * for garbage, which would restart the counter while conntrack still
         * holds entries carrying the ids already issued. That is the reuse
         * this counter exists to prevent, so refuse instead. */
        while (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')
            end++;
        if (end == buf || *end != '\0' || errno == ERANGE || v > AUTHNFT_MARK_MAX) {
            pam_syslog(pamh, LOG_ERR,
                       "authnft: %s is corrupt; refusing to reissue ids that "
                       "live conntrack entries may still carry. Remove it only "
                       "after flushing conntrack.", MARK_COUNTER);
            flock(fd, LOCK_UN);
            close(fd);
            return 0;
        }
        cur = (uint32_t)v;
    }

    /* Refuse rather than wrap. Wrapping hands a live session an id a stale
     * conntrack entry may still carry, which is precisely the failure the
     * counter exists to prevent. AUTHNFT_MARK_MAX is 16.7M ids per boot. */
    if (cur >= AUTHNFT_MARK_MAX) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: session mark space exhausted (%u ids this boot); "
                   "refusing rather than reusing an id a live conntrack entry "
                   "may still carry", cur);
        flock(fd, LOCK_UN);
        close(fd);
        return 0;
    }
    next = cur + 1;

    len = snprintf(buf, sizeof(buf), "%u\n", next);
    if (len < 0 || (size_t)len >= sizeof(buf) ||
        pwrite(fd, buf, (size_t)len, 0) != (ssize_t)len ||
        ftruncate(fd, (off_t)len) != 0) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: cannot persist session mark counter: %s",
                   strerror(errno));
        flock(fd, LOCK_UN);
        close(fd);
        return 0;
    }

    flock(fd, LOCK_UN);
    close(fd);
    return next;
}

static void session_file_path(char out[PATH_MAX_LEN], const char *scope_unit) {
    snprintf(out, PATH_MAX_LEN, SESSION_DIR "/%s.json", scope_unit);
}

static void session_file_tmp_path(char out[PATH_MAX_LEN], const char *scope_unit) {
    snprintf(out, PATH_MAX_LEN, SESSION_DIR "/.%s.tmp", scope_unit);
}

int session_file_write(pam_handle_t *pamh, const authnft_session_t *sd,
                       const char *user, int session_pid) {
    if (!sd || !user) return -1;
    if (sd->scope_unit[0] == '\0') return -1;

    char path[PATH_MAX_LEN];
    char tmp[PATH_MAX_LEN];
    session_file_path(path, sd->scope_unit);
    session_file_tmp_path(tmp, sd->scope_unit);

    /* ISO 8601 UTC timestamp. clock_gettime + gmtime_r are pure-userspace
     * after the vDSO path; already covered by the existing allowlist. */
    char when[32] = "";
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        struct tm gm;
        if (gmtime_r(&ts.tv_sec, &gm))
            strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%SZ", &gm);
    }

    /* All string fields are producer-validated upstream:
     *   user       — [A-Za-z0-9._-], max 32 (util_is_valid_username)
     *   remote_ip  — inet_ntop canonical form, no JSON-special chars
     *   claims_tag — sanitized to [A-Za-z0-9_=,.:;/-]
     *   cg_path    — "authnft.slice/<scope_unit>", charset constrained by
     *                util_is_valid_username + "%d"-formatted PID
     *   fragment   — derived from user, no escape needed
     *   scope_unit — built from user + pid, same charset
     * No JSON escaping required; the full format is ASCII-safe. */
    (void)session_pid;  /* already folded into sd->scope_unit */
    char fragment[PATH_MAX_LEN];
    snprintf(fragment, sizeof(fragment), RULES_DIR "/%s", user);

    char json[JSON_MAX];
    int n = snprintf(json, sizeof(json),
        "{\"v\":2,"
        "\"cg_path\":\"%s\","
        "\"user\":\"%s\","
        "\"remote_ip\":\"%s\","
        "\"fragment\":\"%s\","
        "\"claims_tag\":\"%s\","
        "\"scope_unit\":\"%s\","
        "\"opened_at\":\"%s\"}\n",
        sd->cg_path, user, sd->remote_ip, fragment,
        sd->claims_tag, sd->scope_unit, when);
    if (n < 0 || n >= (int)sizeof(json)) {
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file JSON overflow for %s",
                             sd->scope_unit);
        return -1;
    }

    /* Root-owned, root:root. The file carries claims_tag, which may hold
     * token-derived material (JTI, scope, session correlator) that is not
     * derivable from /proc, last, or utmp. An earlier version fchown'd the
     * file to the authnft group to let non-root observers read it — but
     * membership in the authnft group is exactly what nft_handler_setup
     * gates a session on, so the group IS the monitored-subject population.
     * Group-readable therefore let any managed user read every other
     * managed user's claims, defeating the keyring UID-lock the module
     * advertises (docs/ADMIN_GUIDE.md "no filesystem footprint"). So the file stays
     * root-only. A site that wants non-root observation should grant a
     * dedicated observer group distinct from authnft; the group-read bit
     * is retained (mode 0640) so that can be done with an fchown drop-in,
     * but by default the group is root and the file is root-only.
     *
     * open(2) honours the process umask, so a permissive ambient umask
     * could land 0600 even when 0640 was requested. Open at 0600 (always
     * strict enough) and widen to 0640 explicitly via fchmod(2), which
     * ignores umask. */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file open(%s) failed: %m", tmp);
        return -1;
    }
    if (fchmod(fd, 0640) < 0 && pamh) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: session file fchmod(0640) failed on %s: %m "
                   "— leaving mode 0600 (root-only readable)", tmp);
    }

    ssize_t w = write(fd, json, (size_t)n);
    if (w != n) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        (void)unlink(tmp);
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file write failed: %m");
        return -1;
    }
    /* close(2) can surface delayed write errors on NFS and other network
     * filesystems; if it fails the file may be incomplete on disk, so
     * unlink the tempfile rather than rename a possibly-corrupt record. */
    if (close(fd) < 0) {
        (void)unlink(tmp);
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file close(%s) failed: %m", tmp);
        return -1;
    }
    if (rename(tmp, path) < 0) {
        (void)unlink(tmp);
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file rename(%s -> %s) failed: %m",
                             tmp, path);
        return -1;
    }
    DEBUG_PRINT("session_file: wrote %s", path);
    return 0;
}

int session_file_remove(pam_handle_t *pamh, const char *scope_unit) {
    if (!scope_unit || scope_unit[0] == '\0') return -1;
    char path[PATH_MAX_LEN];
    session_file_path(path, scope_unit);
    if (unlink(path) < 0 && errno != ENOENT) {
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file unlink(%s) failed: %m", path);
        return -1;
    }
    DEBUG_PRINT("session_file: removed %s", path);
    return 0;
}
