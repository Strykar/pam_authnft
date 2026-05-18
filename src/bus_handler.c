// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include "util_validators.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>
#include <errno.h>

/* validate_cgroup_path lives in src/util_validators.c; declared in
 * util_validators.h. The previous #ifndef FUZZ_BUILD static #endif
 * conditional is retired — the function is unconditionally extern,
 * with pam_authnft.map's `local: *;` hiding it from the .so ABI.
 * Convention from #49 applied here. */

int util_get_cgroup_path(pam_handle_t *pamh, pid_t pid, char *out, size_t out_sz) {
    char *cgroup_path = NULL;

    if (sd_pid_get_cgroup(pid, &cgroup_path) < 0) {
        DEBUG_PRINT("sd_pid_get_cgroup failed for pid %d", pid);
        if (pamh)
            pam_syslog(pamh, LOG_ERR,
                       "authnft: sd_pid_get_cgroup failed for pid %d", (int)pid);
        return -1;
    }

    DEBUG_PRINT("cgroup_path: %s", cgroup_path);

    /*
     * Depth invariant (HANDOFF §3.1, §3.2): path MUST be exactly
     * "/authnft.slice/<name>.scope" — two components under the root.
     * Anything deeper, shallower, or outside authnft.slice is a
     * misconfiguration that would silently produce packet-level match
     * failures under `socket cgroupv2 level 2`.
     */
    int result = validate_cgroup_path(cgroup_path, out, out_sz);

    if (result < 0) {
        if (pamh)
            pam_syslog(pamh, LOG_ERR,
                       "authnft: cgroup path '%s' violates depth invariant "
                       "(expected /authnft.slice/<name>.scope)",
                       cgroup_path ? cgroup_path : "(null)");
        DEBUG_PRINT("cgroup path validation failed: %s",
                    cgroup_path ? cgroup_path : "(null)");
    }

    free(cgroup_path);
    return result;
}

int bus_handler_start(pam_handle_t *pamh, const char *user, int session_pid) {
    sd_bus *bus = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    char unit_name[UNIT_BUF_SIZE];
    int r;

    DEBUG_PRINT("bus: requesting transient scope for %s (pid %d)", user, session_pid);

    if (sd_bus_open_system(&bus) < 0) {
        pam_syslog(pamh, LOG_ERR, "authnft: failed to connect to system bus: %m");
        return -1;
    }

    snprintf(unit_name, sizeof(unit_name), "authnft-%s-%d.scope", user, session_pid);
    DEBUG_PRINT("bus: StartTransientUnit %s", unit_name);

    r = sd_bus_call_method(bus,
                           "org.freedesktop.systemd1",
                           "/org/freedesktop/systemd1",
                           "org.freedesktop.systemd1.Manager",
                           "StartTransientUnit",
                           &error,
                           NULL,
                           "ssa(sv)a(sa(sv))",
                           unit_name,
                           "fail",
                           2,
                           "PIDs",  "au", 1, (uint32_t)session_pid,
                           "Slice", "s",  "authnft.slice",
                           0);

    if (r < 0) {
        pam_syslog(pamh, LOG_ERR, "authnft: systemd handoff failed for %s: %s",
                   unit_name, error.message ? error.message : strerror(-r));
        DEBUG_PRINT("bus: rejected %s: %s", unit_name,
                    error.message ? error.message : "unknown");
        sd_bus_error_free(&error);
        sd_bus_unref(bus);
        return -1;
    }

    DEBUG_PRINT("bus: accepted %s", unit_name);
    sd_bus_error_free(&error);
    sd_bus_unref(bus);
    return 0;
}

int bus_handler_stop(pam_handle_t *pamh, const char *user, int session_pid) {
    sd_bus *bus = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    char unit_name[UNIT_BUF_SIZE];
    int r;

    if (sd_bus_open_system(&bus) < 0) {
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: bus_handler_stop: bus open failed: %m");
        return -1;
    }

    snprintf(unit_name, sizeof(unit_name),
             "authnft-%s-%d.scope", user, session_pid);
    DEBUG_PRINT("bus: StopUnit %s", unit_name);

    r = sd_bus_call_method(bus,
                           "org.freedesktop.systemd1",
                           "/org/freedesktop/systemd1",
                           "org.freedesktop.systemd1.Manager",
                           "StopUnit",
                           &error,
                           NULL,
                           "ss",
                           unit_name,
                           "fail");

    /* Tolerate "unit not found" — the scope may have been reaped between
     * the StartTransientUnit success and this rollback (e.g., the session
     * PID exited). Anything else is an unexpected error worth logging. */
    if (r < 0 && error.name &&
        (strcmp(error.name, "org.freedesktop.systemd1.NoSuchUnit") == 0 ||
         strcmp(error.name, "org.freedesktop.DBus.Error.UnitNotLoaded") == 0)) {
        DEBUG_PRINT("bus: scope %s already gone", unit_name);
        r = 0;
    } else if (r < 0 && pamh) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: bus_handler_stop(%s) failed: %s",
                   unit_name, error.message ? error.message : strerror(-r));
    }

    sd_bus_error_free(&error);
    sd_bus_unref(bus);
    return r < 0 ? -1 : 0;
}
