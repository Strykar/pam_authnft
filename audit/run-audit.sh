#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Local root-capable audit harness — tier 1 (fault matrix).
#
# Runs inside the rootful audit container (the Containerfile 'audit'
# workflow). Drives nft_handler_setup's error returns under a leak
# detector, which the happy-path integration suite never does. The
# detector — not the script — owns the leak verdict: the ASan binary
# exits non-zero if LeakSanitizer finds a definite leak, and valgrind
# exits non-zero on a definite leak in the real pamtester lifecycle.
#
# This is the harness that would have failed on CID 1659576 (frag_buf
# leak): the 'truncate' and 'nftfail' scenarios drive the exact
# pre-substitution error returns that leaked, under LSan.
set -uo pipefail

FAIL=0
note() { printf '\n=== %s ===\n' "$*"; }
ok()   { printf '[PASS] %s\n' "$*"; }
bad()  { printf '[FAIL] %s\n' "$*"; FAIL=1; }

USER_AUDIT=authnft-audit

# --- environment the module expects (group, user, fragment, pam stubs) ---
note "setup: authnft group, test user, fragment, pam.d stubs"
getent group authnft >/dev/null || groupadd -r authnft
id "$USER_AUDIT" >/dev/null 2>&1 || \
    useradd -r -s /usr/sbin/nologin -G authnft "$USER_AUDIT"
mkdir -p /etc/authnft/users
cat > /etc/authnft/users/"$USER_AUDIT" <<'NFT'
add rule inet authnft @session_chain socket cgroupv2 level 2 . ip saddr @session_v4 accept
NFT
chown root:root /etc/authnft/users/"$USER_AUDIT"
chmod 644 /etc/authnft/users/"$USER_AUDIT"

# pam_start stub for the fault driver (it calls nft_handler_setup
# directly; pam_start just needs the service to exist so it returns a
# usable handle for the module's pam_syslog/pam_error calls).
cat > /etc/pam.d/authnft_audit <<'PAM'
session required pam_permit.so
PAM
# pamtester service for the real-lifecycle valgrind pass. The module path
# is cwd-relative so this works both in the container (cwd=/build) and in
# the vng microVM (cwd=the repo's real path).
SO_PATH="$(pwd)/pam_authnft.so"
cat > /etc/pam.d/authnft_test <<PAM
auth     required  pam_permit.so
account  required  pam_permit.so
session  required  $SO_PATH
password required  pam_deny.so
PAM

# --- build: production .so + ASan/UBSan fault driver + preload ---
note "build: production .so, ASan fault driver, malloc-fail preload"
make pam_authnft.so          >/dev/null 2>/tmp/b1.log || { bad "build .so";          cat /tmp/b1.log; }
make audit/nft_fault_driver  >/dev/null 2>/tmp/b2.log || { bad "build fault driver"; cat /tmp/b2.log; }
make audit/malloc_fail.so    >/dev/null 2>/tmp/b3.log || { bad "build preload";      cat /tmp/b3.log; }
[ "$FAIL" -eq 0 ] || { note "AUDIT RESULT: FAIL (build)"; exit 1; }

# --- detector configuration ---
# LSan suppressions for library-internal still-reachable allocations
# (libnftables/libnftnl/systemd/dbus/NSS/PAM). These are not module
# leaks; the negative control (revert a free, see a 'definitely lost'
# in nft_handler_setup) proves real module leaks still surface through
# the suppressions.
cat > /tmp/lsan.supp <<'SUPP'
leak:libnftables
leak:libnftnl
leak:libmnl
leak:libjansson
leak:libsystemd
leak:libdbus
leak:libgmp
leak:libxtables
leak:/usr/lib64/libc.so
leak:_nss
leak:pam_start
leak:pam_modutil
SUPP
export ASAN_OPTIONS="detect_leaks=1:exitcode=1:halt_on_error=1:abort_on_error=0:print_summary=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:exitcode=1"
export LSAN_OPTIONS="suppressions=/tmp/lsan.supp:print_suppressions=0"
# The fault driver calls nft_handler_setup directly and never installs
# the seccomp sandbox; NO_SANDBOX also keeps the valgrind pass from
# fighting the filter (seccomp + valgrind syscall interception tangle).
export AUTHNFT_NO_SANDBOX=1

# Run a scenario under the sanitizer. `scope=yes` runs the driver inside a
# real transient scope at authnft.slice/authnft-audit.scope so the cgroupv2
# path the module references actually resolves and call 1 can reach the
# success path (exercising the post-call-1 returns and the success free
# under LSan). `scope=no` runs it bare, so call 1 fails on the missing
# cgroup — which is itself a useful error-path (the call-1-failure return,
# where CID 1659576's live sibling leak lived).
run_scen() {
    local scen="$1" scope="${2:-no}"
    nft delete table inet authnft 2>/dev/null || true
    note "fault scenario: $scen (scope=$scope)  (ASan + UBSan + LSan)"
    local rc=0
    if [ "$scope" = yes ]; then
        systemd-run --scope --quiet --slice=authnft.slice --unit=authnft-audit \
            --property=Delegate=yes \
            ./audit/nft_fault_driver "$scen" "$USER_AUDIT" || rc=$?
    else
        ./audit/nft_fault_driver "$scen" "$USER_AUDIT" || rc=$?
    fi
    if [ "$rc" -eq 0 ]; then
        ok "$scen: no leak, no UB"
    else
        bad "$scen: sanitizer flagged a leak or UB (exit $rc)"
    fi
    nft delete table inet authnft 2>/dev/null || true
}

# happy in a real scope -> reaches the success path + the 444 free.
# truncate/nftfail bare -> drive the error returns (truncate also reports
# whether the line-311 truncation path is reachable given the field caps).
run_scen happy yes
run_scen truncate no
run_scen nftfail no

# --- real lifecycle under valgrind (production .so via pamtester) ---
# The verdict is valgrind's leak report, NOT pamtester's own exit code:
# pamtester's open_session can return non-zero for environmental reasons
# that differ across substrates (e.g. the transient-scope setup under
# vng's degraded systemd), and valgrind propagates that child exit. Those
# are not leaks. Parse the leak summary instead.
note "real lifecycle: pamtester open+close under valgrind (definite leaks)"
nft delete table inet authnft 2>/dev/null || true
valgrind --leak-check=full --show-leak-kinds=definite \
        --errors-for-leak-kinds=definite --trace-children=yes \
        --log-file=/tmp/vg.log \
        pamtester -I rhost=127.0.0.1 authnft_test "$USER_AUDIT" \
        open_session close_session >/dev/null 2>&1 || true
if grep -q 'definitely lost:' /tmp/vg.log; then
    if grep -qE 'definitely lost: [1-9]' /tmp/vg.log; then
        bad "valgrind found a definite leak in the real lifecycle"
        grep -A12 'definitely lost' /tmp/vg.log | head -30
    else
        ok "pamtester lifecycle: no definite leak under valgrind"
    fi
else
    # No leak summary: pamtester did not complete under valgrind in this
    # substrate (vng's degraded systemd can refuse the transient scope).
    # Not a leak; the container tier is authoritative for this check and
    # the ASan fault scenarios already ran. Warn, do not fail the tier.
    note "valgrind: no leak summary (pamtester did not complete under " \
         "valgrind here) — lifecycle leak check skipped in this substrate"
fi
nft delete table inet authnft 2>/dev/null || true

# The fail-Nth-allocation interposer (audit/malloc_fail.so) is built above
# but deliberately NOT run as a blind automated sweep: failing arbitrary
# allocations across the whole process hits loader/libc/PAM startup
# allocations long before any module code, so a blind sweep reports
# process-startup failures, not module bugs. It is kept as a targeted
# manual tool — e.g. to confirm a specific allocation-failure return:
#
#   AUTHNFT_MALLOC_FAIL_AT=<n> AUTHNFT_MALLOC_FAIL_VERBOSE=1 \
#     LD_PRELOAD=$PWD/audit/malloc_fail.so \
#     pamtester -I rhost=127.0.0.1 authnft_test "$USER_AUDIT" open_session
#
# pick <n> from a run that prints each allocation index, find the one in
# the module path, and confirm it degrades to a PAM error (not a crash).

note "AUDIT RESULT: $([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)"
exit "$FAIL"
