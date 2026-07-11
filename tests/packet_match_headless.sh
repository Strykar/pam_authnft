#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Does this kernel actually work? Run it here: `sudo make test-packet-match`.
#
# pam_authnft needs `socket cgroupv2` to match on an INPUT-hooked chain. That
# is a patch, not a version: commit 05ae2fba821c ("netfilter: nft_socket: make
# cgroup match work in input too"). A kernel in [5.13, 5.18) without it — and
# the fix is Fixes-tagged, so stable branches DO carry it while the frozen
# mainline tags do not — will happily accept the rule and then never match on
# it. The session's rules silently never apply. No version check can tell you
# that; only driving the real match can, which is what this does.
#
# Proves the three kernel invariants the module relies on, with no PAM module,
# no sshd, no NSS and no pamtester in the loop — only systemd, nftables, ncat
# and ss:
#
#   PM1  allowed source matches, disallowed source does not   (10.11)
#   PM2  a socket created before cgroup migration never matches (10.12, K10)
#   PM3  per-session sets keep one session's rule off another's traffic (10.13)
#
# Every negative assertion (counter must NOT fire) is paired with a
# traffic-arrival control (an unconditional per-port counter that MUST
# fire), so a probe that never generated traffic reads as FAIL, not as a
# vacuous pass.
#
# Exit codes: 0 all invariants verified, 1 an invariant broke (this is what the
# silently-broken kernels above produce — loudly), 77 the kernel/nft rejected
# the socket-cgroupv2 set or rule outright, i.e. the feature is absent (< 5.13).
set -euo pipefail

RED='\033[1;31m' BLUE='\033[1;34m' YELLOW='\033[1;33m' RESET='\033[0m'
pass() { printf "${BLUE}[PASS]${RESET} %s\n" "$1"; }
note() { printf "${YELLOW}%s${RESET}\n" "$1"; }
RC=0
stage_fail() { printf "${RED}[FAIL]${RESET} %s\n" "$1"; RC=1; }

if [[ $EUID -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

for t in systemd-run systemctl nft ncat ss; do
    command -v "$t" >/dev/null 2>&1 || { echo "missing required tool: $t" >&2; exit 1; }
done

if [[ ! -e /sys/fs/cgroup/cgroup.controllers ]]; then
    echo "cgroupv2 unified hierarchy not mounted at /sys/fs/cgroup" >&2
    exit 1
fi

printf "${BLUE}>>> HEADLESS PACKET-MATCH HARNESS (kernel %s)${RESET}\n" "$(uname -r)"

# --- Feature probe -----------------------------------------------------
# Probe both the set type and a rule using the expression: old kernels or
# an nft built without socket-cgroup support reject one of the two. Treat
# rejection as "unsupported" (77), not a failure. A kernel that ACCEPTS
# the rule but never matches (5.13..5.17, missing 05ae2fba821c) is below
# the documented floor and fails PM1 loudly instead.
if ! nft add table inet authnft_pm_probe 2>/dev/null; then
    echo "cannot create nft tables (no CAP_NET_ADMIN?)" >&2
    exit 1
fi
probe_ok=1
nft add set inet authnft_pm_probe s \
    '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }' 2>/dev/null || probe_ok=0
if [[ $probe_ok -eq 1 ]]; then
    nft add chain inet authnft_pm_probe input \
        '{ type filter hook input priority 9; policy accept; }' 2>/dev/null || probe_ok=0
fi
if [[ $probe_ok -eq 1 ]]; then
    nft add rule inet authnft_pm_probe input \
        tcp dport 18080 socket cgroupv2 level 2 . ip saddr @s counter 2>/dev/null || probe_ok=0
fi
nft delete table inet authnft_pm_probe 2>/dev/null || true
if [[ $probe_ok -eq 0 ]]; then
    echo "kernel/nft lacks 'socket cgroupv2 level 2 . ip saddr' support" >&2
    exit 77
fi

# --- Shared teardown ---------------------------------------------------
PIDS=()
SCOPES=()
TABLES=()
cleanup() {
    (( ${#PIDS[@]} > 0 )) && kill "${PIDS[@]}" 2>/dev/null || true
    for s in "${SCOPES[@]}"; do
        systemctl stop "$s" 2>/dev/null || true
    done
    for t in "${TABLES[@]}"; do
        nft delete table inet "$t" 2>/dev/null || true
    done
}
trap cleanup EXIT

# Stand up a persistent scope and return its cgroupv2 path. systemd reaps a
# transient scope the moment its main process exits, so a `sleep` keeper
# holds it open for the duration of the probe.
make_scope() { # <unit>
    local unit="$1"
    systemd-run --scope --slice=authnft.slice --unit="$unit" sleep 120 \
        >/dev/null 2>&1 &
    PIDS+=($!)
    SCOPES+=("$unit.scope")
    local i
    for i in $(seq 1 25); do
        [[ -d "/sys/fs/cgroup/authnft.slice/$unit.scope" ]] && return 0
        sleep 0.2
    done
    return 1
}

# Poll until a TCP listener is up on 127.0.0.1:<port>. Replaces fixed
# sleeps: on a slow (TCG or cold-cache) guest a fixed delay under-waits
# and the probe would blame the kernel invariant for a setup race.
wait_listen() { # <port>
    local port="$1" i
    for i in $(seq 1 50); do
        ss -Hltn "sport = :$port" 2>/dev/null | grep -q . && return 0
        sleep 0.1
    done
    return 1
}

# Read a rule counter by comment. Never fails (grep miss returns empty),
# so `set -e` cannot abort mid-invariant; callers treat empty as 0/absent.
cg_pkts() { # <table> <comment>
    nft list chain inet "$1" input 2>/dev/null \
        | grep "$2" | grep -oP 'packets \K[0-9]+' || true
}

# --- PM1: allowed source matches, disallowed source does not (10.11) ----
pm1() {
    note "PM1: allowed source matches, disallowed does not"
    local unit="authnft-pmatch-11" tbl="authnft_pm11"
    local path="/authnft.slice/$unit.scope"
    if ! make_scope "$unit"; then
        stage_fail "PM1: could not create probe scope"; return
    fi

    nft add table inet "$tbl"; TABLES+=("$tbl")
    nft add set inet "$tbl" probe_set \
        '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }'
    nft add chain inet "$tbl" input \
        '{ type filter hook input priority 10; policy accept; }'
    nft add rule inet "$tbl" input \
        tcp dport 18081 socket cgroupv2 level 2 . ip saddr @probe_set \
        counter comment '"cg-match"'
    # Traffic-arrival control: counts every 18081 packet regardless of
    # cgroup, so the disallowed-source assertion below cannot pass
    # vacuously when no traffic flowed at all.
    nft add rule inet "$tbl" input \
        tcp dport 18081 counter comment '"all-18081"'
    nft add element inet "$tbl" probe_set \
        "{ \"authnft.slice/$unit.scope\" . 127.0.0.2 timeout 1h }"

    # Probe 1: allowed source. Listener runs inside the probe scope.
    sh -c 'echo $$ > /sys/fs/cgroup'"$path"'/cgroup.procs
           echo OK | exec ncat -l 127.0.0.1 18081' &
    PIDS+=($!)
    if ! wait_listen 18081; then
        stage_fail "PM1: listener never came up"; return
    fi
    timeout 5 ncat -w3 127.0.0.1 18081 --source 127.0.0.2 </dev/null >/dev/null 2>&1 || true
    local hit; hit="$(cg_pkts "$tbl" cg-match)"
    if [[ -z "$hit" || "$hit" -eq 0 ]]; then
        stage_fail "PM1: counter=0 after allowed-source probe"; return
    fi
    pass "PM1: cgroup match fired for allowed source ($hit packets)"

    # Probe 2: disallowed source (not in the set). The cgroup counter must
    # not move while the arrival control proves the probe's packets flowed.
    local prev="$hit" prev_all
    prev_all="$(cg_pkts "$tbl" all-18081)"
    sh -c 'echo $$ > /sys/fs/cgroup'"$path"'/cgroup.procs
           echo OK | exec ncat -l 127.0.0.1 18081' &
    PIDS+=($!)
    if ! wait_listen 18081; then
        stage_fail "PM1: probe-2 listener never came up"; return
    fi
    timeout 5 ncat -w3 127.0.0.1 18081 --source 127.0.0.3 </dev/null >/dev/null 2>&1 || true
    local all; all="$(cg_pkts "$tbl" all-18081)"
    if [[ -z "$all" || "$all" -le "${prev_all:-0}" ]]; then
        stage_fail "PM1: probe-2 traffic never arrived (arrival control static at ${all:-0})"; return
    fi
    hit="$(cg_pkts "$tbl" cg-match)"
    if [[ -n "$hit" && "$hit" -gt "$prev" ]]; then
        stage_fail "PM1: counter moved ($prev->$hit) on disallowed source"; return
    fi
    pass "PM1: no match for disallowed source (counter stable at $hit, traffic proven by arrival control)"
}

# --- PM2: alloc-time cgroup invariant, K10 (10.12) ----------------------
# A socket created BEFORE its owning task moves into the scope keeps its
# original cgroup (sk_cgrp_data is set at sk_alloc, never on migration), so
# `socket cgroupv2 level 2` must NOT match it. This is why the SSH TCP
# connection itself is never caught and ct state handles it.
pm2() {
    note "PM2: pre-scope socket does not match (alloc-time invariant)"
    local unit="authnft-pmatch-12" tbl="authnft_pm12"
    local path="/authnft.slice/$unit.scope"
    if ! make_scope "$unit"; then
        stage_fail "PM2: could not create probe scope"; return
    fi

    nft add table inet "$tbl"; TABLES+=("$tbl")
    nft add set inet "$tbl" probe_set \
        '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }'
    nft add chain inet "$tbl" input \
        '{ type filter hook input priority 11; policy accept; }'
    nft add rule inet "$tbl" input \
        tcp dport 18082 socket cgroupv2 level 2 . ip saddr @probe_set \
        counter comment '"classb-match"'
    # Arrival control for the negative assertion below.
    nft add rule inet "$tbl" input \
        tcp dport 18082 counter comment '"all-18082"'
    nft add element inet "$tbl" probe_set \
        "{ \"authnft.slice/$unit.scope\" . 127.0.0.4 timeout 1h }"

    # Listener created OUTSIDE the scope, then its process moved in.
    # wait_listen guarantees the socket exists before the migration, which
    # is the ordering the invariant is about.
    ncat -l 127.0.0.1 18082 </dev/null &
    local listen=$!; PIDS+=($listen)
    if ! wait_listen 18082; then
        stage_fail "PM2: listener never came up"; return
    fi
    if ! echo "$listen" > "/sys/fs/cgroup$path/cgroup.procs" 2>/dev/null; then
        stage_fail "PM2: could not move listener into probe scope"; return
    fi
    timeout 5 ncat -w3 127.0.0.1 18082 --source 127.0.0.4 </dev/null >/dev/null 2>&1 || true
    local all; all="$(cg_pkts "$tbl" all-18082)"
    if [[ -z "$all" || "$all" -eq 0 ]]; then
        stage_fail "PM2: probe traffic never arrived (arrival control at 0)"; return
    fi
    local hit; hit="$(cg_pkts "$tbl" classb-match)"
    if [[ -n "$hit" && "$hit" -gt 0 ]]; then
        stage_fail "PM2: match fired ($hit) on pre-scope socket — alloc-time invariant broken"; return
    fi
    pass "PM2: pre-scope socket did not match ($all packets arrived, 0 matched)"
}

# --- PM3: cross-session isolation via per-session sets (10.13) ----------
pm3() {
    note "PM3: per-session sets isolate one session's rule from another's"
    local alice="authnft-pmatch-13-alice" bob="authnft-pmatch-13-bob"
    local tbl="authnft_pm13"
    local bob_path="/authnft.slice/$bob.scope"
    if ! make_scope "$alice" || ! make_scope "$bob"; then
        stage_fail "PM3: could not create both probe scopes"; return
    fi

    nft add table inet "$tbl"; TABLES+=("$tbl")
    nft add set inet "$tbl" alice_set \
        '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }'
    nft add set inet "$tbl" bob_set \
        '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }'
    nft add chain inet "$tbl" input \
        '{ type filter hook input priority 12; policy accept; }'
    # alice's deny-default matches ONLY @alice_set; bob's element is elsewhere.
    nft add rule inet "$tbl" input \
        socket cgroupv2 level 2 . ip saddr @alice_set tcp dport 22 accept
    nft add rule inet "$tbl" input \
        socket cgroupv2 level 2 . ip saddr @alice_set counter comment '"alice-deny"'
    nft add rule inet "$tbl" input \
        socket cgroupv2 level 2 . ip saddr @bob_set counter comment '"bob-match"'
    nft add element inet "$tbl" alice_set \
        "{ \"authnft.slice/$alice.scope\" . 127.0.0.5 timeout 1h }"
    nft add element inet "$tbl" bob_set \
        "{ \"authnft.slice/$bob.scope\" . 127.0.0.6 timeout 1h }"

    # Listener in bob's scope; probe from bob's source on a non-22 port.
    # bob-match > 0 doubles as the arrival control for the alice-deny==0
    # assertion: both counters see the same probe.
    sh -c 'echo $$ > /sys/fs/cgroup'"$bob_path"'/cgroup.procs
           echo OK | exec ncat -l 127.0.0.1 18083' &
    PIDS+=($!)
    if ! wait_listen 18083; then
        stage_fail "PM3: listener never came up"; return
    fi
    timeout 5 ncat -w3 127.0.0.1 18083 --source 127.0.0.6 </dev/null >/dev/null 2>&1 || true

    local alice_hit bob_hit
    alice_hit="$(cg_pkts "$tbl" alice-deny)"
    bob_hit="$(cg_pkts "$tbl" bob-match)"
    if [[ -n "$alice_hit" && "$alice_hit" -gt 0 ]]; then
        stage_fail "PM3: alice's deny counter fired ($alice_hit) on bob's traffic — isolation broken"; return
    fi
    if [[ -z "$bob_hit" || "$bob_hit" -eq 0 ]]; then
        stage_fail "PM3: bob's own counter=0 — set match not firing at all"; return
    fi
    pass "PM3: per-session isolation verified (alice=0, bob=$bob_hit)"
}

pm1
pm2
pm3

if [[ $RC -eq 0 ]]; then
    printf "\n${BLUE}>>> ALL PACKET-MATCH INVARIANTS VERIFIED (kernel %s)${RESET}\n" "$(uname -r)"
else
    printf "\n${RED}>>> PACKET-MATCH HARNESS FAILED (kernel %s)${RESET}\n" "$(uname -r)"
fi
exit $RC
