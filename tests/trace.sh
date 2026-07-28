#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Audit aid for invariant #5 (seccomp allowlist provenance).
# Sets up a minimal test environment, runs ONE pamtester open+close cycle
# under `strace -f -c` with the sandbox bypassed, and writes the syscall
# summary to trace.log. Diff this list against SCMP_SYS(...) entries in
# src/sandbox.c before adding any new syscall to the allowlist.
#
# Two stages are run:
#
#   Stage 1 — default PAM config
#     session required pam_authnft.so
#     Captures the baseline syscall set and writes it to trace.log.
#
#   Stage 2 — feature-gated arguments
#     session required pam_trace_helper.so env=TRACE_KEY=<serial>
#     session required pam_authnft.so claims_env=TRACE_KEY
#     TRACE_KEY refers to a pre-seeded kernel keyring entry. Captures the
#     keyctl(KEYCTL_READ) call and any other syscalls reached only on the
#     claims_env code path. Writes to trace-claims.log.
#
# rhost_policy=kernel is NOT exercised here — pamtester does not create
# an ESTABLISHED TCP socket, so peer_lookup_tcp() would fail through to
# lax without reaching sock_diag. Use `make trace-features` instead; the
# unit suite's stage 9 exercises sock_diag on a real localhost TCP pair.
#
# Usage: sudo ./tests/trace.sh /path/to/pam_authnft.so
set -euo pipefail

SO_PATH="${1:-$(pwd)/pam_authnft.so}"
TEST_USER="${AUTHNFT_TEST_USER:-authnft-test}"
RULES_DIR="/etc/authnft/users"
PAM_TEST_CONF="/etc/pam.d/authnft_test"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

USER_CREATED=0 GROUP_CREATED=0
HELPER_SO=/tmp/pam_trace_helper.so
cleanup() {
    rm -f "$RULES_DIR/$TEST_USER" "$PAM_TEST_CONF" "$HELPER_SO"
    [[ $USER_CREATED -eq 1 ]] && userdel "$TEST_USER" 2>/dev/null || true
    [[ $GROUP_CREATED -eq 1 ]] && groupdel authnft 2>/dev/null || true
    nft list tables 2>/dev/null | grep -q "inet authnft" && nft delete table inet authnft || true
    # Revoke any keyring entry we added; best-effort.
    keyctl purge user authnft_trace_payload 2>/dev/null || true
}
trap cleanup EXIT

if ! getent group authnft > /dev/null 2>&1; then
    groupadd authnft; GROUP_CREATED=1
fi
if ! getent passwd "$TEST_USER" > /dev/null 2>&1; then
    if   [[ -x /usr/sbin/nologin ]]; then NOLOGIN_SHELL=/usr/sbin/nologin
    elif [[ -x /sbin/nologin     ]]; then NOLOGIN_SHELL=/sbin/nologin
    else                                   NOLOGIN_SHELL=/bin/false
    fi
    useradd -r -s "$NOLOGIN_SHELL" -G authnft "$TEST_USER"; USER_CREATED=1
fi

mkdir -p "$RULES_DIR"
chmod 700 /etc/authnft "$RULES_DIR"
echo 'add rule inet authnft @session_chain socket cgroupv2 level 2 . ip saddr @session_v4 accept' \
    > "$RULES_DIR/$TEST_USER"
chown root:root "$RULES_DIR/$TEST_USER"
chmod 644 "$RULES_DIR/$TEST_USER"

# Stage 1 — default PAM config (no module arguments).
cat > "$PAM_TEST_CONF" <<EOF
auth     required  pam_permit.so
account  required  pam_permit.so
session  required  $SO_PATH
password required  pam_deny.so
EOF

# pamtester's own stdout chatter ("successfully opened a session", etc.) is
# not relevant to the syscall audit; drop it. strace writes the summary to
# -o, so stderr does not need redirecting.
AUTHNFT_NO_SANDBOX=1 strace -f -c -o trace.log \
    pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
    open_session close_session > /dev/null

echo "=== Stage 1 (default path) — trace.log ==="
cat trace.log
echo ""

# Stage 2 — feature-gated path (claims_env). Requires a helper PAM module
# that stages a PAM environment variable via pam_putenv before pam_authnft
# reads it, plus a pre-seeded kernel keyring entry that pam_authnft will
# fetch via keyctl(KEYCTL_READ).
HELPER_SRC="$(dirname "$0")/pam_trace_helper.c"
if command -v keyctl >/dev/null 2>&1 && [[ -f "$HELPER_SRC" ]]; then
    gcc -fPIC -shared -O2 -Wall -o "$HELPER_SO" "$HELPER_SRC" -lpam

    # Seed a key in the session keyring. We write a deterministic payload
    # so the trace is reproducible; only the syscall footprint matters.
    SERIAL=$(keyctl add user authnft_trace_payload \
             "tag=audit-session:trace01;role=maintainer" @s)

    cat > "$PAM_TEST_CONF" <<EOF
auth     required  pam_permit.so
account  required  pam_permit.so
session  required  $HELPER_SO env=TRACE_KEY=$SERIAL
session  required  $SO_PATH claims_env=TRACE_KEY
password required  pam_deny.so
EOF

    AUTHNFT_NO_SANDBOX=1 strace -f -c -o trace-claims.log \
        pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
        open_session close_session > /dev/null

    echo "=== Stage 2 (claims_env path) — trace-claims.log ==="
    cat trace-claims.log
    echo ""

    # Highlight keyctl if it appears; absence in stage 2 is a red flag
    # because it means the claims_env path did not actually reach keyctl.
    if grep -qE '\bkeyctl\b' trace-claims.log; then
        echo "keyctl: observed on the claims_env path — SCMP_SYS(keyctl)"
        echo "        in src/sandbox.c is required."
    else
        echo "WARNING: keyctl NOT observed on the claims_env path. Either"
        echo "the helper failed to populate PAM env, the keyring entry"
        echo "was inaccessible, or the feature code path is broken."
    fi
    echo ""
else
    echo "=== Stage 2 skipped (keyctl(1) missing or helper src absent) ==="
    echo ""
fi

echo "Compare trace.log and trace-claims.log against SCMP_SYS(...) entries"
echo "in src/sandbox.c. Syscalls that legitimately run before dlopen (e.g."
echo "execve) should be excluded per the explanatory comment at the top"
echo "of src/sandbox.c. Any syscall observed on the feature path but"
echo "absent from stage 1 is evidence that a feature-specific allowlist"
echo "entry is required."
