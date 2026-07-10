#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Headless kernel packet-match harness for the multi-kernel matrix.
#
# Proves the three kernel invariants pam_authnft relies on, with no PAM
# module, no sshd, no NSS and no pamtester in the loop — only systemd,
# nftables and ncat. That decoupling lets a microVM run this once per
# guest kernel to confirm `socket cgroupv2 level 2 . ip saddr` behaves,
# which is the property that actually varies across kernel versions.
#
#   PM1  allowed source matches, disallowed source does not   (10.11)
#   PM2  a socket created before cgroup migration never matches (10.12, K10)
#   PM3  per-session sets keep one session's rule off another's traffic (10.13)
#
# Exit codes: 0 all invariants verified, 1 an invariant broke, 77 the
# kernel/nft build lacks the `socket cgroupv2 level 2` concat-set support
# so the matrix can tell "feature absent" from "feature broken".
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

for t in systemd-run systemctl nft ncat; do
    command -v "$t" >/dev/null 2>&1 || { echo "missing required tool: $t" >&2; exit 1; }
done

if [[ ! -e /sys/fs/cgroup/cgroup.controllers ]]; then
    echo "cgroupv2 unified hierarchy not mounted at /sys/fs/cgroup" >&2
    exit 1
fi

printf "${BLUE}>>> HEADLESS PACKET-MATCH HARNESS (kernel %s)${RESET}\n" "$(uname -r)"

# --- Feature probe -----------------------------------------------------
# Old kernels or an nft built without the socket-cgroup concat type reject
# the set typeof outright. Treat that as "unsupported" (77), not a failure.
if ! nft add table inet authnft_pm_probe 2>/dev/null; then
    echo "cannot create nft tables (no CAP_NET_ADMIN?)" >&2
    exit 1
fi
if ! nft add set inet authnft_pm_probe s \
    '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }' 2>/dev/null; then
    nft delete table inet authnft_pm_probe 2>/dev/null || true
    echo "kernel/nft lacks 'socket cgroupv2 level 2 . ip saddr' support" >&2
    exit 77
fi
nft delete table inet authnft_pm_probe 2>/dev/null || true

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

cg_pkts() { # <table> <comment>
    nft list chain inet "$1" input 2>/dev/null \
        | grep "$2" | grep -oP 'packets \K[0-9]+'
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
    nft add element inet "$tbl" probe_set \
        "{ \"authnft.slice/$unit.scope\" . 127.0.0.2 timeout 1h }"

    # Probe 1: allowed source. Listener runs inside the probe scope.
    sh -c 'echo $$ > /sys/fs/cgroup'"$path"'/cgroup.procs
           echo OK | exec ncat -l 127.0.0.1 18081' &
    PIDS+=($!)
    sleep 0.5
    timeout 5 ncat -w3 127.0.0.1 18081 --source 127.0.0.2 </dev/null >/dev/null 2>&1 || true
    local hit; hit="$(cg_pkts "$tbl" cg-match)"
    if [[ -z "$hit" || "$hit" -eq 0 ]]; then
        stage_fail "PM1: counter=0 after allowed-source probe"; return
    fi
    pass "PM1: cgroup match fired for allowed source ($hit packets)"

    # Probe 2: disallowed source (not in the set). Counter must not move.
    local prev="$hit"
    sh -c 'echo $$ > /sys/fs/cgroup'"$path"'/cgroup.procs
           echo OK | exec ncat -l 127.0.0.1 18081' &
    PIDS+=($!)
    sleep 0.5
    timeout 5 ncat -w3 127.0.0.1 18081 --source 127.0.0.3 </dev/null >/dev/null 2>&1 || true
    hit="$(cg_pkts "$tbl" cg-match)"
    if [[ -n "$hit" && "$hit" -gt "$prev" ]]; then
        stage_fail "PM1: counter moved ($prev->$hit) on disallowed source"; return
    fi
    pass "PM1: no match for disallowed source (counter stable at $hit)"
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
    nft add element inet "$tbl" probe_set \
        "{ \"authnft.slice/$unit.scope\" . 127.0.0.4 timeout 1h }"

    # Listener created OUTSIDE the scope, then its process moved in.
    ncat -l 127.0.0.1 18082 </dev/null &
    local listen=$!; PIDS+=($listen)
    sleep 0.3
    if ! echo "$listen" > "/sys/fs/cgroup$path/cgroup.procs" 2>/dev/null; then
        stage_fail "PM2: could not move listener into probe scope"; return
    fi
    timeout 5 ncat -w3 127.0.0.1 18082 --source 127.0.0.4 </dev/null >/dev/null 2>&1 || true
    local hit; hit="$(cg_pkts "$tbl" classb-match)"
    if [[ -n "$hit" && "$hit" -gt 0 ]]; then
        stage_fail "PM2: match fired ($hit) on pre-scope socket — alloc-time invariant broken"; return
    fi
    pass "PM2: pre-scope socket did not match (alloc-time inheritance confirmed)"
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
    sh -c 'echo $$ > /sys/fs/cgroup'"$bob_path"'/cgroup.procs
           echo OK | exec ncat -l 127.0.0.1 18083' &
    PIDS+=($!)
    sleep 0.5
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
