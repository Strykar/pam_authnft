#!/bin/bash
# Verifies a fragment-rejection message reaches the connecting user.
#
# nft_handler_setup runs in a forked child; if it called pam_error itself the
# message would land in the child's copy of sshd's process-global loginmsg and
# never reach the user. The setup reports a reason instead and the parent emits
# the message. The harness models sshd's global conversation buffer and checks
# the parent captured it.
#
# Uses a world-writable fragment, which the perms check rejects, for a member
# of the authnft group (so setup reaches the fragment checks). Needs systemd
# for the scope handoff that precedes setup, so it runs against the host bus.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SO="$REPO/pam_authnft.so"
HARNESS="$REPO/tests/.reject_message_harness"
SVC=authnft_rmsg
SVCFILE="/etc/pam.d/$SVC"
U=anftrmsg
FRAG="/etc/authnft/users/$U"
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO=sudo

cleanup() {
    $SUDO nft delete table inet authnft 2>/dev/null
    $SUDO rm -f "$SVCFILE" "$FRAG"
    $SUDO userdel "$U" 2>/dev/null
    rm -f "$HARNESS"
}
trap cleanup EXIT

( cd "$REPO" && make >/dev/null 2>&1 ) || { echo "FAIL: module build"; exit 1; }
cc -O2 -Wall -o "$HARNESS" "$REPO/tests/reject_message_harness.c" -lpam \
    || { echo "FAIL: harness build"; exit 1; }

# Reference the built module by absolute path (PAM module dir differs by distro:
# /usr/lib/security vs /usr/lib64/security), as integration_test.sh does.
printf 'auth     required  pam_permit.so\naccount  required  pam_permit.so\nsession  optional  %s\n' "$SO" \
    | $SUDO tee "$SVCFILE" >/dev/null
$SUDO groupadd authnft 2>/dev/null || true
$SUDO useradd -M -s /usr/sbin/nologin -G authnft "$U" 2>/dev/null || true
$SUDO mkdir -p /etc/authnft/users
echo 'add rule inet authnft @session_chain socket cgroupv2 level 2 . ip saddr @session_v4 accept' \
    | $SUDO tee "$FRAG" >/dev/null
$SUDO chown root:root "$FRAG"
$SUDO chmod 666 "$FRAG"   # world-writable -> perms reject

out=$($SUDO "$HARNESS" "$SVC" "$U" 2>/dev/null); rc=$?
echo "$out"
if echo "$out" | grep -q 'must be root-owned and not world-writable'; then
    echo "RESULT: PASS (parent delivered the fragment-reject message to the user)"
    exit 0
fi
echo "RESULT: FAIL (the message did not reach the parent's conversation; harness rc=$rc)"
exit 1
