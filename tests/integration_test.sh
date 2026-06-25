#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Integration tests for pam_authnft using pamtester.
# Must be run as root. Usage: sudo ./tests/integration_test.sh /path/to/pam_authnft.so
set -euo pipefail

SO_PATH="${1:-$(pwd)/pam_authnft.so}"
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_USER="${AUTHNFT_TEST_USER:-authnft-test}"
RULES_DIR="/etc/authnft/users"
PAM_TEST_CONF="/etc/pam.d/authnft_test"
RED='\033[1;31m' BLUE='\033[1;34m' YELLOW='\033[1;33m' CYAN='\033[36m' RESET='\033[0m'

# nologin location differs across distros: /usr/sbin on Arch/Debian, /sbin on
# RHEL family. Fall back to /bin/false if neither exists.
if [[ -x /usr/sbin/nologin ]]; then
    NOLOGIN_SHELL="/usr/sbin/nologin"
elif [[ -x /sbin/nologin ]]; then
    NOLOGIN_SHELL="/sbin/nologin"
else
    NOLOGIN_SHELL="/bin/false"
fi
pass() { printf "${BLUE}[PASS]${RESET} %s\n" "$1"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$1"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

# --- Setup ---
# Create the authnft group if absent, create a transient system user for
# testing, and add it to the group. All of this is undone in the cleanup trap.

USER_CREATED=0
GROUP_CREATED=0

# Flush any leftover `inet authnft` table from prior runs. Residue can
# come from: (a) unit test stage 7 inserting {12345 . 127.0.0.1} without
# cleanup, or (b) a previous integration run where 10.2's close_session
# ran in a separate PAM handle and correctly no-opped (per invariant #6),
# leaving the element behind until its 24-hour timeout. 10.6 checks for
# "any element present" and would false-positive on such residue.
if nft list tables 2>/dev/null | grep -q "inet authnft"; then
    nft delete table inet authnft
fi

GROUP_FRAG_10_8=""
S1011_PIDS=()
cleanup() {
    rm -f "$RULES_DIR/$TEST_USER" "$PAM_TEST_CONF" /etc/pam.d/authnft_strict
    [[ -n "$GROUP_FRAG_10_8" ]] && rm -f "$GROUP_FRAG_10_8"
    if (( ${#S1011_PIDS[@]} > 0 )); then
        kill "${S1011_PIDS[@]}" 2>/dev/null || true
    fi
    if [[ $USER_CREATED -eq 1 ]]; then
        userdel "$TEST_USER" 2>/dev/null || true
    fi
    if [[ $GROUP_CREATED -eq 1 ]]; then
        groupdel authnft 2>/dev/null || true
    fi
}
trap cleanup EXIT

if ! getent group authnft > /dev/null 2>&1; then
    groupadd authnft
    GROUP_CREATED=1
fi

if ! getent passwd "$TEST_USER" > /dev/null 2>&1; then
    useradd -r -s "$NOLOGIN_SHELL" -G authnft "$TEST_USER"
    USER_CREATED=1
else
    usermod -aG authnft "$TEST_USER"
fi

mkdir -p "$RULES_DIR"

# Runtime session-file directory. Normally created at boot by
# /usr/lib/tmpfiles.d/authnft.conf; test harness creates it on demand so
# `make test-integration` works even before `sudo make install-tmpfiles`.
mkdir -p /run/authnft/sessions
# Wipe any residue from earlier runs — lingering files from invariant-#6
# close_session no-ops would confuse the session-file lifecycle assertion.
rm -f /run/authnft/sessions/*.json /run/authnft/sessions/.*.tmp 2>/dev/null || true

# Write a minimal PAM config for testing
printf "auth     required  pam_permit.so\n" > "$PAM_TEST_CONF"
printf "account  required  pam_permit.so\n" >> "$PAM_TEST_CONF"
printf "session  required  %s\n" "$SO_PATH" >> "$PAM_TEST_CONF"
printf "password required  pam_deny.so\n"   >> "$PAM_TEST_CONF"

printf "${BLUE}>>> STAGE 10: PAMTESTER INTEGRATION${RESET}\n"

# 10.1: Group member denied when fragment is missing
printf "${YELLOW}10.1: Denial for '$TEST_USER' (no fragment)${RESET}\n"
rm -f "$RULES_DIR/$TEST_USER"
if pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "Group member was not denied with missing fragment"
fi
pass "Group member correctly denied"

# 10.2: Group member allowed when fragment exists and is valid
printf "${YELLOW}10.2: Success for '$TEST_USER' (valid fragment)${RESET}\n"
echo 'add rule inet authnft @session_chain socket cgroupv2 level 2 . ip saddr @session_v4 accept' \
    > "$RULES_DIR/$TEST_USER"
chown root:root "$RULES_DIR/$TEST_USER"
chmod 644 "$RULES_DIR/$TEST_USER"
if ! pamtester -v -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session; then
    fail "Session open failed — check journalctl -t authnft"
fi
printf "${CYAN}Ruleset state after open:${RESET}\n"
nft list table inet authnft
pamtester authnft_test "$TEST_USER" close_session
pass "Session opened and closed cleanly"

# 10.3: Root bypasses the module entirely
printf "${YELLOW}10.3: Root pass-through${RESET}\n"
if ! pamtester -v -I rhost=127.0.0.1 authnft_test root open_session; then
    fail "Root session open failed"
fi
pamtester authnft_test root close_session
pass "Root pass-through verified"

# Write a clean valid fragment for subsequent stages
FRAGMENT="$RULES_DIR/$TEST_USER"
valid_fragment() {
    echo 'add rule inet authnft @session_chain socket cgroupv2 level 2 . ip saddr @session_v4 accept' \
        > "$FRAGMENT"
    chown root:root "$FRAGMENT"
    chmod 644 "$FRAGMENT"
}

# 10.4: Invariant #4 — fragment must be root-owned.
printf "${YELLOW}10.4: Fragment rejected when not root-owned${RESET}\n"
valid_fragment
chown "$TEST_USER:$TEST_USER" "$FRAGMENT"
if pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "Non-root-owned fragment was accepted"
fi
pass "Non-root-owned fragment correctly rejected"

# 10.5: Invariant #4 — fragment must not be world-writable.
printf "${YELLOW}10.5: Fragment rejected when world-writable${RESET}\n"
valid_fragment
chmod 666 "$FRAGMENT"
if pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "World-writable fragment was accepted"
fi
pass "World-writable fragment correctly rejected"

# 10.6: Invariant #1 — session data persisted via PAM data must survive
# into close_session so the per-session chain, sets, and jump rule are
# torn down cleanly. Running open_session and close_session in one
# pamtester invocation keeps the PAM handle alive; if the close path
# regresses, per-session state persists in the nft table.
# Flush residual per-session state from 10.2 (whose close ran in a
# separate handle and no-opped per invariant #6).
nft delete table inet authnft 2>/dev/null || true
printf "${YELLOW}10.6: Per-session cleanup via persisted session data${RESET}\n"
valid_fragment
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
        open_session close_session > /dev/null 2>&1; then
    fail "open+close in a single PAM handle failed"
fi
TABLE_STATE=$(nft list table inet authnft 2>/dev/null || true)
if echo "$TABLE_STATE" | grep -qE '(chain|set) session_'; then
    echo "$TABLE_STATE" >&2
    fail "Per-session chain/sets persisted after close_session"
fi
pass "Per-session state cleaned up at close_session"

# 10.7: Invariant #6 — close_session is best-effort. A close with no prior
# open (no stored session data in PAM) must still return PAM_SUCCESS so
# the session can always unwind.
printf "${YELLOW}10.7: close_session best-effort when state missing${RESET}\n"
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" close_session > /dev/null 2>&1; then
    fail "close_session without prior open did not return PAM_SUCCESS"
fi
pass "close_session best-effort semantics preserved"

# 10.8: Multi-fragment composition via nftables `include` directive.
# libnftables resolves `include` transitively when processing a fragment;
# a user fragment that includes a group-level fragment gets both files'
# rules loaded into the filter chain. No pam_authnft code change enables
# this — the test exists to catch a future libnftables parser regression.
printf "${YELLOW}10.8: Multi-fragment composition (transitive include)${RESET}\n"
GROUP_FRAG_10_8="/etc/authnft/composed-10-8.nft"
# Included group fragment does NOT receive placeholder substitution
# (only the top-level fragment does). It uses the shared filter chain
# with a non-placeholder rule — testing that include composition works
# through the buffer-mode loading pipeline.
cat > "$GROUP_FRAG_10_8" <<'NFT'
add rule inet authnft filter counter accept comment "AUTHNFT-IT-GROUP"
NFT
chown root:root "$GROUP_FRAG_10_8"
chmod 644 "$GROUP_FRAG_10_8"
cat > "$FRAGMENT" <<NFT
include "$GROUP_FRAG_10_8"
add rule inet authnft @session_chain counter accept comment "AUTHNFT-IT-USER"
NFT
chown root:root "$FRAGMENT"
chmod 644 "$FRAGMENT"
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "Composed-fragment open_session failed — check journalctl -t authnft"
fi
TABLE_STATE=$(nft list table inet authnft 2>&1)
if ! echo "$TABLE_STATE" | grep -q "AUTHNFT-IT-GROUP"; then
    fail "Transitive include did not land the group fragment's rule (define vars not propagated)"
fi
if ! echo "$TABLE_STATE" | grep -q "AUTHNFT-IT-USER"; then
    fail "User fragment's own rule did not land alongside the include"
fi
# Close in a new handle; per invariant #6 this no-ops. Residual set
# element is flushed by the top-of-script nft delete on the next run.
pamtester authnft_test "$TEST_USER" close_session > /dev/null 2>&1 || true
pass "Composition via include resolved: group and user rules both applied"

# 10.9: /run/authnft/sessions/<scope_unit>.json session-identity file contract.
# Verifies that pam_authnft writes a JSON observability file at open_session
# and removes it at close_session. Permissions, JSON schema fields, and the
# open/close lifecycle are all checked. See docs/INTEGRATIONS.txt §5.6.
printf "${YELLOW}10.9: Session identity file (open creates, close removes)${RESET}\n"
valid_fragment
rm -f /run/authnft/sessions/*.json /run/authnft/sessions/.*.tmp 2>/dev/null || true
# Half 1: open in a single handle (separate from the later close so the
# file is left behind for inspection — close_session in a new handle
# no-ops per invariant #6 and does not remove the file).
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "Session file test: open_session failed"
fi
SESSION_FILE=$(ls /run/authnft/sessions/*.json 2>/dev/null | head -1 || true)
if [[ -z "$SESSION_FILE" ]]; then
    fail "No session file created at open_session under /run/authnft/sessions/"
fi
for FIELD in '"v":2' '"cg_path":"authnft.slice/authnft-' "\"user\":\"$TEST_USER\"" \
             '"remote_ip":"127.0.0.1"' "\"fragment\":\"$RULES_DIR/$TEST_USER\"" \
             "\"scope_unit\":\"authnft-$TEST_USER-" '"opened_at":"'; do
    if ! grep -q "$FIELD" "$SESSION_FILE"; then
        cat "$SESSION_FILE"
        fail "Session file missing field: $FIELD"
    fi
done
PERMS=$(stat -c '%a %U:%G' "$SESSION_FILE")
if [[ "$PERMS" != "640 root:authnft" ]]; then
    fail "Session file wrong permissions: got '$PERMS', expected '640 root:authnft'"
fi
rm -f "$SESSION_FILE"
# Half 2: open+close in the SAME handle. close_session must remove the file.
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
        open_session close_session > /dev/null 2>&1; then
    fail "Session file test: open+close same-handle run failed"
fi
if ls /run/authnft/sessions/*.json 2>/dev/null | grep -q .; then
    fail "Session file persisted after close_session in the same handle"
fi
pass "Session file lifecycle: created on open, correct schema and perms, removed on close"

# 10.10: Structured journald audit events.
# Verifies pam_authnft emits AUTHNFT_EVENT=open on open_session and
# AUTHNFT_EVENT=close on close_session, with a consistent
# AUTHNFT_CORRELATION token joining the two. See docs/INTEGRATIONS.txt §6.2.
printf "${YELLOW}10.10: Audit events (journald + correlation token)${RESET}\n"
valid_fragment
# Mark the journal cursor so we only read events from this test.
CURSOR=$(journalctl -n 0 --show-cursor 2>&1 | grep -oP 'cursor: \K.*')
if [[ -z "$CURSOR" ]]; then
    fail "could not capture journal cursor"
fi
# Single-handle open+close so the same session_pid (and correlation) covers
# both events.
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
        open_session close_session > /dev/null 2>&1; then
    fail "open+close failed during audit-event test"
fi
# Give the journal a moment to flush (sd_journal_send returns before the
# reader sees the entry under some journald backlog conditions).
sync
sleep 1
OPEN_LINE=$(journalctl --after-cursor="$CURSOR" -t pam_authnft \
            --output=json --no-pager 2>/dev/null | \
            grep '"AUTHNFT_EVENT":"open"' | head -1 || true)
CLOSE_LINE=$(journalctl --after-cursor="$CURSOR" -t pam_authnft \
             --output=json --no-pager 2>/dev/null | \
             grep '"AUTHNFT_EVENT":"close"' | head -1 || true)
[[ -n "$OPEN_LINE"  ]] || fail "no AUTHNFT_EVENT=open entry after open_session"
[[ -n "$CLOSE_LINE" ]] || fail "no AUTHNFT_EVENT=close entry after close_session"
for FIELD in '"AUTHNFT_USER":"'"$TEST_USER"'"' \
             '"AUTHNFT_CG_PATH":"authnft.slice/authnft-' '"AUTHNFT_REMOTE_IP":"127.0.0.1"' \
             "\"AUTHNFT_FRAGMENT\":\"$RULES_DIR/$TEST_USER\"" \
             "\"AUTHNFT_SCOPE_UNIT\":\"authnft-$TEST_USER-" \
             '"AUTHNFT_CORRELATION":"authnft-'; do
    if ! echo "$OPEN_LINE" | grep -q "$FIELD"; then
        echo "open event: $OPEN_LINE"
        fail "open event missing field: $FIELD"
    fi
done
CORR_OPEN=$(echo "$OPEN_LINE"  | grep -oP '"AUTHNFT_CORRELATION":"\K[^"]+')
CORR_CLOSE=$(echo "$CLOSE_LINE" | grep -oP '"AUTHNFT_CORRELATION":"\K[^"]+')
if [[ -z "$CORR_OPEN" || "$CORR_OPEN" != "$CORR_CLOSE" ]]; then
    fail "correlation mismatch: open='$CORR_OPEN' close='$CORR_CLOSE'"
fi
pass "Audit events: open + close emitted, shared correlation='$CORR_OPEN'"

# 10.11: Adversarial packet classification (ingress).
#
# Verifies that `socket cgroupv2 level 2 . ip saddr @<per-session set>`
# on the INPUT-hooked chain actually accepts packets from allowed
# sources and drops packets from disallowed sources. This is the test
# that would have caught the K1 bug: every prior stage verified positive
# state (element present, session opens, event fires) rather than
# end-to-end packet classification with an explicit drop.
#
# Architecture: pam_authnft's chain hooks INPUT. On INPUT, the nftables
# `socket` expression resolves the DESTINATION socket (the listener).
# For ingress filtering — "only this source can reach the session's
# listener" — that is correct. Egress filtering would require an
# OUTPUT-hooked chain, which is a separate concern not tested here.
#
# Implementation: pamtester exits after open_session, so the transient
# scope is reaped by systemd before probes can run. To work around this,
# we create a persistent test scope via systemd-run, open a pamtester
# session to build the nft table/chain/rules, then manually insert an
# element for the persistent scope. This cleanly separates the PAM
# lifecycle (10.1–10.10) from the packet-classification test (10.11).
#
# Peer addresses 127.0.0.2 (allowed) and 127.0.0.3 (disallowed) are
# loopback aliases. The kernel code path is identical for loopback and
# real interfaces; loopback is preferred for hermetic container testing.
#
# `ct state established,related accept` precedes the cgroup match so
# the initial SYN (which arrives before request_sock promotion) is
# handled via conntrack — the standard nftables stateful-chain idiom.
#
# Ordering: this stage runs last due to catch-all drop rules.
printf "${YELLOW}10.11: Adversarial packet classification${RESET}\n"

# Uses its OWN nft table to avoid earlier stages' accept rules
# (which match probe traffic and accept it before the counter rule).
# Kernel namespace fix (commit 7f3287db6543) makes socket cgroupv2
# level 2 work inside containers — verified by RCA counter sweep.

s1011_scope_path="/authnft.slice/authnft-1011-probe.scope"
systemd-run --scope --slice=authnft.slice --unit=authnft-1011-probe \
    sleep 60 >/dev/null 2>&1 &
S1011_PIDS+=($!)
sleep 0.5
if [[ ! -d "/sys/fs/cgroup$s1011_scope_path" ]]; then
    fail "10.11: could not create probe scope"
fi

# Own table, own set, own chain — isolated from accumulated 10.1-10.10 state.
nft add table inet authnft_1011
nft add set inet authnft_1011 probe_set \
    '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }'
nft add chain inet authnft_1011 input \
    '{ type filter hook input priority 10; policy accept; }'
nft add rule inet authnft_1011 input \
    tcp dport 18081 socket cgroupv2 level 2 . ip saddr @probe_set \
    counter comment '"cg-match"'
nft add rule inet authnft_1011 input \
    tcp dport 18081 counter comment '"all-18081"'

nft add element inet authnft_1011 probe_set \
    '{ "authnft.slice/authnft-1011-probe.scope" . 127.0.0.2 timeout 1h }'

# Probe 1: allowed source. Listener in probe scope, connect from 127.0.0.2.
sh -c '
    echo $$ > /sys/fs/cgroup'"${s1011_scope_path}"'/cgroup.procs
    echo OK | exec ncat -l 127.0.0.1 18081
' &
S1011_PIDS+=($!)
sleep 0.5

timeout 5 ncat -w3 127.0.0.1 18081 --source 127.0.0.2 </dev/null >/dev/null 2>&1 || true
CG_PKTS=$(nft list chain inet authnft_1011 input 2>/dev/null \
    | grep 'cg-match' | grep -oP 'packets \K[0-9]+')
if [[ -z "$CG_PKTS" || "$CG_PKTS" -eq 0 ]]; then
    nft list table inet authnft_1011 >&2 2>/dev/null || true
    fail "10.11: cgroup match counter=0 after allowed-source probe"
fi
pass "10.11: cgroup match fired for allowed source ($CG_PKTS packets)"

# Probe 2: disallowed source (127.0.0.3, not in set). Counter should not increase.
PREV_PKTS="$CG_PKTS"
sh -c '
    echo $$ > /sys/fs/cgroup'"${s1011_scope_path}"'/cgroup.procs
    echo OK | exec ncat -l 127.0.0.1 18081
' &
S1011_PIDS+=($!)
sleep 0.5

timeout 5 ncat -w3 127.0.0.1 18081 --source 127.0.0.3 </dev/null >/dev/null 2>&1 || true
CG_PKTS=$(nft list chain inet authnft_1011 input 2>/dev/null \
    | grep 'cg-match' | grep -oP 'packets \K[0-9]+')
if [[ -n "$CG_PKTS" && "$CG_PKTS" -gt "$PREV_PKTS" ]]; then
    nft list table inet authnft_1011 >&2 2>/dev/null || true
    fail "10.11: cgroup match counter increased ($PREV_PKTS→$CG_PKTS) on disallowed source"
fi
pass "10.11: cgroup match did NOT fire for disallowed source (counter stable at $CG_PKTS)"

nft delete table inet authnft_1011 2>/dev/null
pass "10.11: adversarial packet classification verified"

# 10.12: Class A/B socket-scope invariant (K10).
#
# The kernel sets sk->sk_cgrp_data at socket creation (sk_alloc →
# cgroup_sk_alloc) and never updates it on task migration. A socket
# created BEFORE the owning task moves into the session scope carries
# the original cgroup (Class B). socket cgroupv2 level 2 will NOT
# match it — the SSH TCP connection is the canonical example.
#
# This test creates a listener OUTSIDE the probe scope, then moves the
# owning process INTO the scope, and verifies the counter does NOT fire.
# This proves the alloc-time invariant and grounds the README's caveat
# that ct state established,related accept handles pre-scope sockets.
#
# Host-only: same cgroup-namespace skip as 10.11.
printf "${YELLOW}10.12: Class A/B socket-scope invariant${RESET}\n"

# Reuse 10.11's probe scope (still alive from the sleep 60 keeper).
if [[ ! -d "/sys/fs/cgroup${s1011_scope_path}" ]]; then
    pass "10.12: [SKIP] probe scope from 10.11 no longer available"
    printf "\n${BLUE}>>> INTEGRATION TESTS COMPLETE${RESET}\n"
    exit 0
fi

# Own table — isolated from 10.11 and earlier stages.
nft add table inet authnft_1012
nft add set inet authnft_1012 probe_set \
    '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }'
nft add chain inet authnft_1012 input \
    '{ type filter hook input priority 11; policy accept; }'
nft add rule inet authnft_1012 input \
    tcp dport 18082 socket cgroupv2 level 2 . ip saddr @probe_set \
    counter comment '"classb-match"'

nft add element inet authnft_1012 probe_set \
    '{ "authnft.slice/authnft-1011-probe.scope" . 127.0.0.4 timeout 1h }'

# Start a listener OUTSIDE the scope, THEN move the owning process in.
# The socket was created before the cgroup migration → Class B.
ncat -l 127.0.0.1 18082 </dev/null &
S1012_LISTEN=$!
S1011_PIDS+=($S1012_LISTEN)
sleep 0.3
echo $S1012_LISTEN > /sys/fs/cgroup${s1011_scope_path}/cgroup.procs 2>/dev/null || {
    kill $S1012_LISTEN 2>/dev/null
    nft delete table inet authnft_1012 2>/dev/null
    pass "10.12: [SKIP] could not move listener into probe scope"
    printf "\n${BLUE}>>> INTEGRATION TESTS COMPLETE${RESET}\n"
    exit 0
}

# Connect. If sk_cgrp_data were migrate-time, the counter would fire.
# Since it's alloc-time, the socket still carries the harness cgroup.
timeout 5 ncat -w3 127.0.0.1 18082 --source 127.0.0.4 </dev/null >/dev/null 2>&1 || true

CG_PKTS=$(nft list chain inet authnft_1012 input 2>/dev/null \
    | grep 'classb-match' | grep -oP 'packets \K[0-9]+')
if [[ -n "$CG_PKTS" && "$CG_PKTS" -gt 0 ]]; then
    nft list table inet authnft_1012 >&2 2>/dev/null || true
    fail "10.12: cgroup match fired ($CG_PKTS packets) on pre-scope socket — alloc-time invariant broken"
fi
nft delete table inet authnft_1012 2>/dev/null
pass "10.12: pre-scope socket did NOT match (alloc-time cgroup inheritance confirmed)"

# 10.13: Cross-session isolation (per-session sets).
#
# Verifies that alice's deny rule does NOT affect bob's traffic under
# the per-session set model. Each session's set contains only its own
# element; alice's drop rule matching @alice_set cannot match bob's
# cgroup because bob's element is in @bob_set, not @alice_set.
#
# Contrast with the pre-Plan-B shared-set model where this test
# proved interference (bob's element was in the shared set and matched
# alice's drop rule). The per-session architecture eliminates this.
printf "${YELLOW}10.13: Cross-session isolation (per-session sets)${RESET}\n"

s1013_alice="/authnft.slice/authnft-1013-alice.scope"
s1013_bob="/authnft.slice/authnft-1013-bob.scope"

systemd-run --scope --slice=authnft.slice --unit=authnft-1013-alice \
    sleep 60 >/dev/null 2>&1 &
S1011_PIDS+=($!)
systemd-run --scope --slice=authnft.slice --unit=authnft-1013-bob \
    sleep 60 >/dev/null 2>&1 &
S1011_PIDS+=($!)
sleep 0.5

if [[ ! -d "/sys/fs/cgroup${s1013_alice}" ]] || \
   [[ ! -d "/sys/fs/cgroup${s1013_bob}" ]]; then
    pass "10.13: [SKIP] could not create both probe scopes"
    printf "\n${BLUE}>>> INTEGRATION TESTS COMPLETE${RESET}\n"
    exit 0
fi

# Two per-session sets (alice and bob), each with its own element.
# alice's chain has a deny-by-default rule matching only alice's set.
nft add table inet authnft_1013
nft add set inet authnft_1013 alice_set \
    '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }'
nft add set inet authnft_1013 bob_set \
    '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }'
nft add chain inet authnft_1013 input \
    '{ type filter hook input priority 12; policy accept; }'

# alice's deny-default: allow port 22, count everything else.
# Matches ONLY @alice_set — bob's element is NOT in this set.
nft add rule inet authnft_1013 input \
    socket cgroupv2 level 2 . ip saddr @alice_set \
    tcp dport 22 accept
nft add rule inet authnft_1013 input \
    socket cgroupv2 level 2 . ip saddr @alice_set \
    counter comment '"alice-deny"'

# bob's accept: matches @bob_set, counts hits.
nft add rule inet authnft_1013 input \
    socket cgroupv2 level 2 . ip saddr @bob_set \
    counter comment '"bob-match"'

nft add element inet authnft_1013 alice_set \
    '{ "authnft.slice/authnft-1013-alice.scope" . 127.0.0.5 timeout 1h }'
nft add element inet authnft_1013 bob_set \
    '{ "authnft.slice/authnft-1013-bob.scope" . 127.0.0.6 timeout 1h }'

# Listener in bob's scope on port 18083.
sh -c '
    echo $$ > /sys/fs/cgroup'"${s1013_bob}"'/cgroup.procs
    echo OK | exec ncat -l 127.0.0.1 18083
' &
S1011_PIDS+=($!)
sleep 0.5

# Probe from bob's source — NOT port 22. Under the old shared-set
# model, alice's deny counter would fire. With per-session sets,
# alice's deny counter should NOT fire (bob's element is in bob_set,
# not alice_set). bob's own counter SHOULD fire.
timeout 5 ncat -w3 127.0.0.1 18083 --source 127.0.0.6 </dev/null >/dev/null 2>&1 || true

ALICE_PKTS=$(nft list chain inet authnft_1013 input 2>/dev/null \
    | grep 'alice-deny' | grep -oP 'packets \K[0-9]+')
BOB_PKTS=$(nft list chain inet authnft_1013 input 2>/dev/null \
    | grep 'bob-match' | grep -oP 'packets \K[0-9]+')

if [[ -n "$ALICE_PKTS" && "$ALICE_PKTS" -gt 0 ]]; then
    nft list table inet authnft_1013 >&2 2>/dev/null || true
    fail "10.13: alice's deny counter fired ($ALICE_PKTS) on bob's traffic — isolation broken"
fi
if [[ -z "$BOB_PKTS" || "$BOB_PKTS" -eq 0 ]]; then
    nft list table inet authnft_1013 >&2 2>/dev/null || true
    fail "10.13: bob's own counter=0 — set match not firing at all"
fi
pass "10.13: per-session isolation verified (alice=0, bob=$BOB_PKTS — no cross-session interference)"

nft delete table inet authnft_1013 2>/dev/null

# 10.14: Failure-path rollback — when nft_handler_setup fails partway
# through (e.g., the fragment has a libnftables syntax error), neither
# the per-session nft chain/sets NOR the systemd transient scope must
# survive the failed open_session. Without the rollback, every failed
# auth attempt leaks a chain + 3 sets in the shared `authnft` table
# and a transient scope under authnft.slice — observable but harmless,
# until enough accumulate to make `nft list table inet authnft` and
# `systemctl list-units 'authnft-*.scope'` unreadable.
#
# Audit findings A1 (nft state rollback) + A2 (scope rollback).
nft delete table inet authnft 2>/dev/null || true
printf "${YELLOW}10.14: Failure-path rollback (no leftover nft state or scope)${RESET}\n"

# A fragment that's syntactically wrong: nft will reject "garbage_token"
# at call 3, AFTER call 1 has created the per-session chain + sets and
# call 2 has installed the jump rule.
cat > "$FRAGMENT" <<'NFT'
add rule inet authnft @session_chain garbage_token_no_such_keyword accept
NFT
chown root:root "$FRAGMENT"
chmod 644 "$FRAGMENT"

# This open_session MUST fail (PAM_AUTH_ERR from call 3).
if pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "10.14: open_session with broken fragment unexpectedly succeeded"
fi

# Assert no per-session chain or set survives.
TABLE_STATE=$(nft list table inet authnft 2>/dev/null || true)
if echo "$TABLE_STATE" | grep -qE '(chain|set) session_'; then
    echo "$TABLE_STATE" >&2
    fail "10.14: per-session nft state leaked after failed open_session (A1 regression)"
fi

# Assert the module's own transient scope is rolled back. Two things to
# get right: (1) scope the glob to THIS user's unit name
# (authnft-<user>-<pid>.scope) so the persistent probe scopes that
# 10.11-10.13 stand up as scaffolding are not counted as a module leak;
# (2) bus_handler_stop issues StopUnit, which systemd runs asynchronously,
# so poll briefly for the scope to clear rather than reading it once.
LEAKED_SCOPES=""
for _ in $(seq 1 25); do
    LEAKED_SCOPES=$(systemctl list-units --all --no-legend --type=scope \
        "authnft-${TEST_USER}-*.scope" 2>/dev/null \
        | awk '{print $1}' | grep -v '^$' || true)
    [[ -z "$LEAKED_SCOPES" ]] && break
    sleep 0.2
done
if [[ -n "$LEAKED_SCOPES" ]]; then
    echo "leaked scopes: $LEAKED_SCOPES" >&2
    fail "10.14: systemd scope leaked after failed open_session (A2 regression)"
fi

pass "10.14: failed open_session rolled back nft state and scope cleanly"
nft delete table inet authnft 2>/dev/null || true

# 10.15: real sshd loopback coverage. pamtester is single-process, so
# 10.2/10.6/10.14 cannot exercise an actual sshd session lifecycle.
# This stage drives a real sshd loopback session and asserts the
# per-session nft state and the systemd transient scope are both absent
# after the client disconnects.
#
# Historical note: this stage was added under the (incorrect) hypothesis
# that pam_open_session and pam_close_session ran in different processes
# under sshd's privsep model. In current OpenSSH (sshd-session.c at
# V_10_3_P1, do_pam_session called at line 1280 before privsep_postauth
# at line 1288), both run in the monitor — the same process. The
# pam_set_data path is sufficient; the env carry that originally
# motivated this stage has been removed. The test still earns its keep
# as the only stage that drives real sshd through the project, so a
# future regression that breaks cleanup specifically under sshd (rather
# than under pamtester) would still surface here.
nft delete table inet authnft 2>/dev/null || true
printf "${YELLOW}10.15: Privsep close_session boundary (real sshd loopback)${RESET}\n"

if ! command -v sshd >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1 || \
   ! command -v ssh >/dev/null 2>&1; then
    pass "10.15: [SKIP] sshd / ssh-keygen / ssh not available on this host"
elif ! grep -rqsE 'pam_authnft' /etc/pam.d/sshd; then
    # sshd uses PAM service "sshd"; without pam_authnft wired into
    # /etc/pam.d/sshd this stage drives a session that never loads the
    # module and would pass vacuously. Skip rather than mislead. A test
    # does not rewrite the system sshd PAM config.
    pass "10.15: [SKIP] sshd present but /etc/pam.d/sshd does not load pam_authnft"
else
    # Stage 10.15 needs the test user to be able to exec something across
    # the SSH session. The default test user has nologin/false as shell;
    # swap to /bin/sh for the duration of this stage and restore at the end.
    SAVED_SHELL=$(getent passwd "$TEST_USER" | cut -d: -f7)
    usermod -s /bin/sh "$TEST_USER" 2>/dev/null || true

    # Restore the shell on any path out of this stage. The outer EXIT trap
    # already handles userdel; this nested trap chains a shell-restore in
    # front of it. Also kill any lingering sshd we started.
    SSH_DIR=$(mktemp -d)
    SSHD_PID_FILE="$SSH_DIR/sshd.pid"
    s1015_cleanup() {
        if [[ -f "$SSHD_PID_FILE" ]]; then
            kill "$(cat "$SSHD_PID_FILE")" 2>/dev/null || true
            wait "$(cat "$SSHD_PID_FILE")" 2>/dev/null || true
        fi
        usermod -s "$SAVED_SHELL" "$TEST_USER" 2>/dev/null || true
        rm -rf "$SSH_DIR"
    }
    trap 's1015_cleanup; cleanup' EXIT

    SSHD_PORT=22222
    HOST_KEY="$SSH_DIR/host_ed25519"
    CLIENT_KEY="$SSH_DIR/client_ed25519"
    AUTHKEYS_DIR=$(getent passwd "$TEST_USER" | cut -d: -f6)/.ssh

    ssh-keygen -t ed25519 -N '' -f "$HOST_KEY" -q
    ssh-keygen -t ed25519 -N '' -f "$CLIENT_KEY" -q
    mkdir -p "$AUTHKEYS_DIR"
    cat "$CLIENT_KEY.pub" > "$AUTHKEYS_DIR/authorized_keys"
    chown -R "$TEST_USER:$TEST_USER" "$AUTHKEYS_DIR"
    chmod 700 "$AUTHKEYS_DIR"
    chmod 600 "$AUTHKEYS_DIR/authorized_keys"

    # Per-test sshd config. Uses the existing test PAM service so
    # pam_authnft is in the session stack.
    cat > "$SSH_DIR/sshd_config" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $HOST_KEY
PidFile $SSHD_PID_FILE
UsePAM yes
PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitUserEnvironment no
StrictModes no
LogLevel DEBUG3
EOF

    # Reinstall a valid fragment (10.14 set a deliberately broken one).
    cat > "$FRAGMENT" <<'NFT'
add rule inet authnft @session_chain socket cgroupv2 level 2 . ip saddr @session_v4 accept
NFT
    chown root:root "$FRAGMENT"
    chmod 644 "$FRAGMENT"

    SSHD_BIN=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
    "$SSHD_BIN" -f "$SSH_DIR/sshd_config" -E "$SSH_DIR/sshd.log"
    sleep 0.4

    if [[ ! -s "$SSHD_PID_FILE" ]]; then
        echo "sshd failed to start; log tail:" >&2
        tail -20 "$SSH_DIR/sshd.log" >&2
        pass "10.15: [SKIP] sshd refused to start (port in use? selinux?)"
    else
        # Drive a real command (not `true`) and read the session's cgroup.
        # The old `true` could not tell a working session from a broken
        # one; this asserts the negative controls it lacked. The marker
        # returning proves the seccomp sandbox does NOT kill the
        # post-open_session exec (the user command runs in a child that does
        # not inherit the monitor's filter). The cgroup proves pam_authnft
        # actually ran: only it creates authnft.slice/<scope>. The privsep
        # close teardown is asserted below.
        SSH_OUT=$(ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o BatchMode=yes \
            -o ConnectTimeout=5 \
            -i "$CLIENT_KEY" -p "$SSHD_PORT" \
            "$TEST_USER@127.0.0.1" 'echo AUTHNFT_EXEC_OK; cat /proc/self/cgroup' \
            2>"$SSH_DIR/ssh.err" || true)
        if ! printf '%s' "$SSH_OUT" | grep -q AUTHNFT_EXEC_OK; then
            echo "ssh output: [$SSH_OUT]" >&2
            echo "ssh stderr:" >&2; cat "$SSH_DIR/ssh.err" >&2
            tail -40 "$SSH_DIR/sshd.log" >&2
            fail "10.15: session command did not execute under the sandbox (exec killed by seccomp?)"
        fi
        if ! printf '%s' "$SSH_OUT" | grep -q 'authnft\.slice/authnft-'; then
            echo "session cgroup: [$SSH_OUT]" >&2
            fail "10.15: sshd session not pinned to an authnft scope (pam_authnft did not run)"
        fi

        # Give sshd a moment to run its postauth teardown (mm_answer_term
        # → sshpam_cleanup → pam_close_session).
        sleep 0.5

        # Inspect state. If close_session ran the cleanup correctly,
        # there should be no per-session chain or set in the table.
        TABLE_STATE=$(nft list table inet authnft 2>/dev/null || true)
        if echo "$TABLE_STATE" | grep -qE '(chain|set) session_'; then
            echo "$TABLE_STATE" >&2
            echo "sshd log tail:" >&2
            tail -50 "$SSH_DIR/sshd.log" >&2
            fail "10.15: per-session nft state leaked after sshd disconnect (privsep close_session boundary, issue #35)"
        fi

        # And no transient scope under authnft.slice.
        # grep -v '^$' exits 1 on empty input (the no-leak success case);
        # under pipefail that would trip set -e and kill the script before
        # the pass below. The || true keeps the success case from aborting.
        LEAKED_SCOPE=$(systemctl --no-legend list-units --all --type=scope \
            "authnft-$TEST_USER-*.scope" 2>/dev/null \
            | awk '{print $1}' | grep -v '^$' | head -1 || true)
        if [[ -n "$LEAKED_SCOPE" ]]; then
            echo "leaked scope: $LEAKED_SCOPE" >&2
            systemctl stop "$LEAKED_SCOPE" 2>/dev/null || true
            fail "10.15: systemd scope leaked after sshd disconnect (privsep close_session boundary, issue #35)"
        fi

        pass "10.15: per-session state cleaned up across sshd privsep boundary"
    fi
fi
nft delete table inet authnft 2>/dev/null || true

# 10.16: Fragment dense in @session_v4 exercises the ratio-based
# max_expand bound (PR #40). The old src_len*2+1 over-allocation
# would reject a fragment where the cumulative replacement length
# exceeds twice the placeholder length, even though malloc could
# have served it. With eight rules each using @session_chain and
# @session_v4, this stage forces substitute_placeholders to walk
# the full expansion budget.
printf "${YELLOW}10.16: Placeholder-dense fragment loads under new bound${RESET}\n"
{
    for _ in 1 2 3 4 5 6 7 8; do
        echo 'add rule inet authnft @session_chain socket cgroupv2 level 2 . ip saddr @session_v4 counter accept'
    done
} > "$FRAGMENT"
chown root:root "$FRAGMENT"
chmod 644 "$FRAGMENT"

if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "10.16: open_session failed on placeholder-dense fragment (max_expand regression?)"
fi

# Confirm all eight rules were committed to the per-session chain.
# awk exits on the first match, closing the pipe early; nft then takes a
# SIGPIPE that pipefail+set -e would turn into a silent abort, so guard the
# substitution with || true and let the [[ -z ]] check below do the
# validation. Same reason grep -c (0 matches -> exit 1) needs the guard.
SESSION_CHAIN=$(nft list table inet authnft 2>/dev/null | \
    awk '/chain session_/ {gsub(/[{}]/,"",$2); print $2; exit}' || true)
if [[ -z "$SESSION_CHAIN" ]]; then
    fail "10.16: per-session chain not found after open_session"
fi
RULE_COUNT=$(nft list chain inet authnft "$SESSION_CHAIN" 2>/dev/null | \
    grep -c 'socket cgroupv2' || true)
if [[ "$RULE_COUNT" -ne 8 ]]; then
    fail "10.16: expected 8 substituted rules in $SESSION_CHAIN, found $RULE_COUNT"
fi

pamtester authnft_test "$TEST_USER" close_session > /dev/null 2>&1 || true
nft delete table inet authnft 2>/dev/null || true
pass "10.16: placeholder-dense fragment substituted and loaded ($RULE_COUNT rules)"

# 10.17: rhost_policy=strict denies a non-IP PAM_RHOST. The negative control
# is the same input under the default (lax) policy, which binds cgroup-only
# and succeeds — proving the denial is strict-specific, not just the
# hostname being rejected. The strict path returns PAM_SESSION_ERR before
# any nft/scope state is created (pam_entry.c).
nft delete table inet authnft 2>/dev/null || true
printf "${YELLOW}10.17: rhost_policy=strict denies a non-IP PAM_RHOST${RESET}\n"
cat > "$FRAGMENT" <<'NFT'
add rule inet authnft @session_chain socket cgroupv2 level 2 . ip saddr @session_v4 accept
NFT
chown root:root "$FRAGMENT"; chmod 644 "$FRAGMENT"
printf 'auth     required  pam_permit.so\naccount  required  pam_permit.so\nsession  required  %s rhost_policy=strict\npassword required  pam_deny.so\n' "$SO_PATH" > /etc/pam.d/authnft_strict
if pamtester -I rhost=client.example.invalid authnft_strict "$TEST_USER" open_session > /dev/null 2>&1; then
    pamtester authnft_strict "$TEST_USER" close_session > /dev/null 2>&1 || true
    rm -f /etc/pam.d/authnft_strict; nft delete table inet authnft 2>/dev/null || true
    fail "10.17: rhost_policy=strict did NOT deny a non-IP PAM_RHOST"
fi
if ! pamtester -I rhost=client.example.invalid authnft_test "$TEST_USER" \
        open_session close_session > /dev/null 2>&1; then
    rm -f /etc/pam.d/authnft_strict; nft delete table inet authnft 2>/dev/null || true
    fail "10.17: lax policy should bind cgroup-only on a non-IP rhost but failed (denial is not strict-specific)"
fi
rm -f /etc/pam.d/authnft_strict
nft delete table inet authnft 2>/dev/null || true
pass "10.17: rhost_policy=strict denies non-IP PAM_RHOST; lax binds cgroup-only"

# 10.18: the jump rule's kernel handle is parsed at open and the rule is
# deleted by that handle at close. open+close in ONE pamtester handle (so
# the stored handle survives to close) must leave NO jump rule in the shared
# filter chain. The documented residual leak — call 2 commits the jump but
# the echo/handle parse fails, leaving jump_handle 0 — would leave it behind.
nft delete table inet authnft 2>/dev/null || true
printf "${YELLOW}10.18: jump-rule handle captured and cleaned up${RESET}\n"
cat > "$FRAGMENT" <<'NFT'
add rule inet authnft @session_chain socket cgroupv2 level 2 . ip saddr @session_v4 accept
NFT
chown root:root "$FRAGMENT"; chmod 644 "$FRAGMENT"
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
        open_session close_session > /dev/null 2>&1; then
    fail "10.18: open+close lifecycle failed"
fi
JUMPS=$(nft list chain inet authnft filter 2>/dev/null | grep -c 'jump session_' || true)
if [[ "$JUMPS" -ne 0 ]]; then
    nft list chain inet authnft filter >&2 2>/dev/null || true
    fail "10.18: jump rule leaked after close ($JUMPS present) — handle not captured/deleted"
fi
nft delete table inet authnft 2>/dev/null || true
pass "10.18: jump rule captured at open and deleted at close (no leak)"

# 10.19-10.21: the fork-child sandbox fix's behavioral regressions. They need
# root, nft, systemd, and the sandbox ACTIVE, so they belong in this tier — not
# the pre-commit fault matrix (which runs AUTHNFT_NO_SANDBOX=1 to coexist with
# ASan/valgrind) and not the unprivileged GitHub runners. Each is a
# self-contained script under tests/; run it and surface its verdict.
printf "${YELLOW}10.19: seccomp sandbox does not leak into the session fork${RESET}\n"
if bash "$TESTS_DIR/sandbox_session_leak_test.sh" >/tmp/it-10.19.log 2>&1; then
    pass "10.19: sandbox stays in the setup child; the session fork survives"
else
    sed 's/^/    /' /tmp/it-10.19.log; fail "10.19: sandbox session-leak regression failed"
fi

printf "${YELLOW}10.20: orphaned nft state is reaped when the setup child dies${RESET}\n"
if AUTHNFT_TEST_FORCE=1 bash "$TESTS_DIR/orphan_cleanup_test.sh" >/tmp/it-10.20.log 2>&1; then
    pass "10.20: orphan cleanup reaps the chain, sets, and jump rule by name"
else
    sed 's/^/    /' /tmp/it-10.20.log; fail "10.20: orphan-cleanup regression failed"
fi

printf "${YELLOW}10.21: fragment-reject message reaches the user from the parent${RESET}\n"
if bash "$TESTS_DIR/reject_message_test.sh" >/tmp/it-10.21.log 2>&1; then
    pass "10.21: parent delivers the fragment-reject message"
else
    sed 's/^/    /' /tmp/it-10.21.log; fail "10.21: reject-message regression failed"
fi

# 10.22-10.24: run_sandboxed_nft_setup's error branches, reached with an
# LD_PRELOAD fault injector (the way audit/nft_fail.c injects libnftables
# failures). A real allowlist gap (SIGSYS) or fd/process exhaustion would hit
# these in the field but can't be triggered deterministically; the preload can.
FAULT_PRELOAD=/tmp/fault_preload.so
cc -shared -fPIC -O2 -o "$FAULT_PRELOAD" "$TESTS_DIR/fault_preload.c" -ldl \
    || fail "10.22: fault preload build failed"
SAFE_USER=$(printf '%s' "$TEST_USER" | tr '.-' '_')

printf "${YELLOW}10.22: setup child death is denied and the nft state reaped${RESET}\n"
if LD_PRELOAD="$FAULT_PRELOAD" AUTHNFT_FAULT_DIE_AFTER_JUMP=1 \
       pamtester authnft_test "$TEST_USER" open_session >/dev/null 2>&1; then
    fail "10.22: open_session succeeded despite the setup child being killed"
fi
if nft list table inet authnft 2>/dev/null | grep -q "session_${SAFE_USER}_"; then
    nft list table inet authnft 2>/dev/null | grep "session_${SAFE_USER}_" >&2
    fail "10.22: per-session nft state leaked after the child died mid-setup"
fi
pass "10.22: child death after the jump rule -> session denied, state reaped"

printf "${YELLOW}10.23: pipe() failure fails the session closed${RESET}\n"
if LD_PRELOAD="$FAULT_PRELOAD" AUTHNFT_FAULT_PIPE=1 \
       pamtester authnft_test "$TEST_USER" open_session >/dev/null 2>&1; then
    fail "10.23: open_session succeeded despite pipe() failure"
fi
pass "10.23: pipe() failure -> session denied (fail-closed)"

printf "${YELLOW}10.24: fork() failure fails the session closed${RESET}\n"
if LD_PRELOAD="$FAULT_PRELOAD" AUTHNFT_FAULT_FORK=1 \
       pamtester authnft_test "$TEST_USER" open_session >/dev/null 2>&1; then
    fail "10.24: open_session succeeded despite fork() failure"
fi
pass "10.24: fork() failure -> session denied (fail-closed)"

printf "\n${BLUE}>>> INTEGRATION TESTS COMPLETE${RESET}\n"
