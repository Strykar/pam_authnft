#!/bin/bash
# Regression test for the seccomp-sandbox session leak.
#
# Builds the module fresh and drives it through a harness that forks a
# session command after pam_open_session, the way sshd's monitor does.
#
#   FAIL (bug present): the harness is SIGSYS-killed at the session fork;
#                       no SESSION_FORK_EXEC_OK=1.
#   PASS (bug fixed):   the sandbox lives in a child of open_session, the
#                       harness is never filtered, the command runs.
#
# A NO_SANDBOX control arm proves the harness and setup are sound and
# isolates the sandbox as the only variable. Safe on any host: the test
# user is not in the authnft group, so no nftables state is created (the
# transient scope self-reaps when the harness exits).
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SO="$REPO/pam_authnft.so"
HARNESS="$REPO/tests/.sandbox_leak_harness"
SVC=authnft_seccomp_regress
SVCFILE="/etc/pam.d/$SVC"
U=anftleak
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO=sudo

cleanup() {
    $SUDO rm -f "$SVCFILE"
    $SUDO userdel "$U" 2>/dev/null
    rm -f "$HARNESS"
}
trap cleanup EXIT

# 1. build the module + harness
( cd "$REPO" && make >/dev/null 2>&1 ) || { echo "FAIL: module build"; exit 1; }
[ -f "$SO" ] || { echo "FAIL: no $SO"; exit 1; }
cc -O2 -Wall -o "$HARNESS" "$REPO/tests/sandbox_session_leak_harness.c" -lpam || { echo "FAIL: harness build"; exit 1; }

# 2. minimal session stack referencing the built module by absolute path. The
# PAM module dir differs by distro (/usr/lib/security vs /usr/lib64/security),
# so point pam.d straight at $SO the way integration_test.sh does.
printf 'auth     required  pam_permit.so\naccount  required  pam_permit.so\nsession  optional  %s\n' "$SO" \
    | $SUDO tee "$SVCFILE" >/dev/null
$SUDO useradd -m -s /bin/sh "$U" 2>/dev/null || true

run_arm() {
    local label="$1" envset="$2"
    local out rc
    out=$($SUDO env $envset "$HARNESS" "$SVC" "$U" 10.0.0.1 2>/dev/null)
    rc=$?
    if echo "$out" | grep -q 'SESSION_FORK_EXEC_OK=1'; then
        echo "  [$label] PASS — session command ran after open_session"
        return 0
    fi
    echo "  [$label] FAIL — session command did NOT run (harness rc=$rc, $(
        if [ $rc -gt 128 ]; then echo "killed by signal $((rc-128))"; else echo "exit $rc"; fi))"
    echo "$out" | sed 's/^/      /'
    return 1
}

echo "=== seccomp sandbox session-leak regression ==="
ok=1
run_arm "NO_SANDBOX control" "AUTHNFT_NO_SANDBOX=1" || ok=0
run_arm "sandbox active"     "" || ok=0

if [ "$ok" -eq 1 ]; then
    echo "RESULT: PASS (sandbox does not leak into the session fork)"
    exit 0
else
    echo "RESULT: FAIL (sandbox leaks into the session fork — pam_open_session filters the caller)"
    exit 1
fi
