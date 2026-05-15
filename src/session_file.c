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
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define SESSION_DIR  "/run/authnft/sessions"
#define PATH_MAX_LEN 256
#define JSON_MAX     1024

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

    /* 0640 root:authnft so the file is readable only by root and members
     * of the authnft group. claims_tag may carry token-derived material
     * (JTI, scope, session correlator) that is not derivable from /proc,
     * last, or utmp; world-readable would leak it. Other fields (user,
     * cg_path, remote_ip) are recoverable from the systemd scope and
     * /proc and so are not the privacy delta — but the conservative
     * default is to gate the whole record on authnft group membership.
     *
     * If the authnft group does not exist (package preinst hasn't run,
     * group was manually deleted, etc.) we still create the file with
     * mode 0640 owned by root:root — readable only by root, which is
     * stricter than the previous 0644 default. */
    /* open(2) honours the process umask, so a permissive ambient umask
     * could land 0600 even when 0640 was requested (and a malicious
     * caller of pam(8) could not lower it, but a misconfigured service
     * could). Open at 0600 (which is always strict enough) and widen
     * to 0640 explicitly via fchmod(2), which ignores umask. */
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

    struct group *grp = getgrnam("authnft");
    if (grp) {
        if (fchown(fd, 0 /* root */, grp->gr_gid) < 0 && pamh) {
            pam_syslog(pamh, LOG_WARNING,
                       "authnft: session file fchown(root:authnft) failed "
                       "on %s: %m — leaving owner as root:root", tmp);
        }
    } else if (pamh) {
        pam_syslog(pamh, LOG_DEBUG,
                   "authnft: 'authnft' group not present — session file %s "
                   "stays root:root mode 0640 (root-only readable)", tmp);
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
