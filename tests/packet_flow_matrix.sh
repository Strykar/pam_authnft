#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# What actually happens to a packet? Run it here: `sudo make test-packet-flow`.
#
# The rest of the suite proves that rules MATCH. Every packet-level test in
# this repo builds a `policy accept` chain, hangs a `counter` off it, and
# asserts the counter moved or did not. None of them ever put a packet in
# front of a deny, so none of them can tell you whether a session admits
# traffic, whether teardown revokes it, or whether the ct rule the docs call
# load-bearing is load-bearing. Issue #103 and #105 both lived in that gap.
#
# This harness answers the wire question instead: for each configuration,
# does a real TCP payload round-trip, yes or no. Every case states its
# expected verdict up front and fails if the wire disagrees, so the matrix
# it prints is evidence rather than description.
#
# Everything runs in a throwaway netns, so the deny rules this needs cannot
# touch the host's connectivity. The cgroup scopes are real, on the host
# hierarchy, because cgroup and network namespaces are orthogonal and the
# module's match key is a cgroup path.
#
# Exit codes: 0 every case matched its expected verdict, 1 at least one did
# not, 77 the kernel/nft lacks `socket cgroupv2` (below the documented floor).
set -u

RED='\033[1;31m' BLUE='\033[1;34m' YELLOW='\033[1;33m' GREEN='\033[1;32m' RESET='\033[0m'

NS=authnft_flow
SVC=19100          # port the session fragment allows
ALT=19101          # port the fragment does not mention
OK_SRC=127.0.0.1   # source address in the session's set
BAD_SRC=127.0.0.2  # source address not in any set
SCOPE_A=authnft-flow-alice
SCOPE_B=authnft-flow-bob

# ---------------------------------------------------------------- outer
if [[ "${1:-}" != "--inner" ]]; then
    [[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
    # conntrack(8) is required, not optional: D3 is the only case that
    # shows the flush revoking an established flow, and ASSURANCE_CASE
    # C3 and CONCEPTS both cite D1 to D3 as the pin for the revocation
    # bound. Skipping it while still reporting success would leave two
    # shipped docs citing an arm that never ran.
    for t in ip nft socat ss systemd-run systemctl conntrack; do
        command -v "$t" >/dev/null 2>&1 || { echo "missing required tool: $t" >&2; exit 1; }
    done
    [[ -e /sys/fs/cgroup/cgroup.controllers ]] || {
        echo "cgroupv2 unified hierarchy not mounted at /sys/fs/cgroup" >&2; exit 1; }

    # Feature probe, same contract as packet_match_headless.sh: a kernel
    # without socket-cgroupv2 support is "unsupported" (77), not a failure.
    nft add table inet authnft_flow_probe 2>/dev/null || {
        echo "cannot create nft tables (no CAP_NET_ADMIN?)" >&2; exit 1; }
    probe=1
    nft add set inet authnft_flow_probe s \
        '{ typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }' 2>/dev/null || probe=0
    nft delete table inet authnft_flow_probe 2>/dev/null
    [[ $probe -eq 1 ]] || {
        echo "kernel/nft lacks 'socket cgroupv2 level 2 . ip saddr' support" >&2; exit 77; }

    KEEPERS=()
    outer_cleanup() {
        (( ${#KEEPERS[@]} > 0 )) && kill "${KEEPERS[@]}" 2>/dev/null
        systemctl stop "$SCOPE_A.scope" "$SCOPE_B.scope" 2>/dev/null
        ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null
        ip netns del $NS 2>/dev/null
        return 0
    }
    trap outer_cleanup EXIT

    make_scope() { # <unit>
        systemd-run --scope --slice=authnft.slice --unit="$1" sleep 300 >/dev/null 2>&1 &
        KEEPERS+=($!)
        for _ in $(seq 1 25); do
            [[ -d "/sys/fs/cgroup/authnft.slice/$1.scope" ]] && return 0
            sleep 0.2
        done
        return 1
    }
    make_scope "$SCOPE_A" || { echo "could not create probe scope $SCOPE_A" >&2; exit 1; }
    make_scope "$SCOPE_B" || { echo "could not create probe scope $SCOPE_B" >&2; exit 1; }

    ip netns del $NS 2>/dev/null
    ip netns add $NS || exit 1
    ip -n $NS link set lo up

    printf "${BLUE}>>> PACKET-FLOW MATRIX (kernel %s)${RESET}\n" "$(uname -r)"
    ip netns exec $NS "$0" --inner
    exit $?
fi

# ---------------------------------------------------------------- inner
# `ip netns exec` unshares the mount namespace and mounts a fresh sysfs so
# /sys/class/net reflects the new netns. That hides the cgroup2 mount
# underneath it, so both the element insert (nft resolves the path) and the
# scope migration (writing cgroup.procs) fail with ENOENT. Mount cgroup2
# again: it is a single hierarchy, so this is the same tree the host sees,
# not a new one.
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
[[ -d /sys/fs/cgroup/authnft.slice ]] || {
    echo "cgroup2 not visible inside the netns; cannot run" >&2; exit 1; }

CG_A="authnft.slice/$SCOPE_A.scope"
CG_B="authnft.slice/$SCOPE_B.scope"
RC=0
ROWS=()
SRV_PIDS=()

inner_cleanup() { (( ${#SRV_PIDS[@]} > 0 )) && kill "${SRV_PIDS[@]}" 2>/dev/null; return 0; }
trap inner_cleanup EXIT

note() { printf "\n${YELLOW}%s${RESET}\n" "$*"; }

# Start an echo server on <port>, inside <cgroup path> so that
# `socket cgroupv2 level 2` sees the session scope. The cgroup write happens
# before exec, so the listening socket is allocated inside the scope: that is
# the Class A case, and PM2 already proves the alloc-time invariant it rests on.
serve() { # <port> <cgroup-relative-path>
    local port="$1" cg="$2"
    bash -c "echo \$\$ > /sys/fs/cgroup/$cg/cgroup.procs
             exec socat TCP-LISTEN:$port,reuseaddr,fork EXEC:/bin/cat" &
    SRV_PIDS+=($!)
    for _ in $(seq 1 50); do
        ss -Hltn "sport = :$port" 2>/dev/null | grep -q . && return 0
        sleep 0.1
    done
    return 1
}

# The wire observable: does a payload round-trip? Not "did a counter move",
# not "did the SYN leave". Returns 0 for PASS, 1 for BLOCK.
flow() { # <src-addr> <port>
    local out
    out=$(printf 'ping\n' | timeout 4 socat -T2 - \
          "TCP:127.0.0.1:$2,bind=$1,connect-timeout=2" 2>/dev/null)
    [[ "$out" == "ping" ]]
}

verdict() { flow "$1" "$2" && echo PASS || echo BLOCK; }

# Record a case. Fails the run when the wire disagrees with the claim.
check() { # <case-id> <expected PASS|BLOCK> <observed> <what this pins>
    local id="$1" want="$2" got="$3" desc="$4"
    if [[ "$want" == "$got" ]]; then
        printf "${GREEN}[ OK ]${RESET} %-6s %-5s  %s\n" "$id" "$got" "$desc"
        ROWS+=("$id|$want|$got|ok|$desc")
    else
        printf "${RED}[FAIL]${RESET} %-6s %-5s  %s (expected %s)\n" "$id" "$got" "$desc" "$want"
        ROWS+=("$id|$want|$got|MISMATCH|$desc")
        RC=1
    fi
}

# ---- the module's own state, built as nft_handler_setup builds it -------
# Call 1 order: table, shared chain, ct rule, per-session chain, three sets,
# element. Call 2 appends the jump. The trailing site deny is placement C
# from issue #105, the only one that admits traffic; every functional case
# below therefore runs on the arrangement that actually works.
# Setup failures are fatal, never observations. A half-built table has an
# accept policy and no deny, so every BLOCK case would report PASS and the
# run would look like a fleet of real findings. Die instead.
# Writes to stdout as well as stderr. The inner script runs under
# `ip netns exec`, and a die that only reached stderr came out empty at
# the caller, so the run aborted with no stated reason. A harness that
# stops without saying why is barely better than one that lies.
die() { printf "${RED}>>> SETUP FAILED: %s${RESET}\n" "$*" | tee /dev/stderr; exit 1; }

module_up() { # <session-tag> <cgroup path> <src addr>
    local tag="$1" cg="$2" src="$3"
    nft -f - <<RULES || die "could not build session state for $tag"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add chain inet authnft session_$tag
add set inet authnft session_${tag}_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add set inet authnft session_${tag}_v6 { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }
add set inet authnft session_${tag}_cg { typeof socket cgroupv2 level 2; flags timeout; }
add element inet authnft session_${tag}_v4 { "$cg" . $src timeout 1d }
add rule inet authnft session_$tag socket cgroupv2 level 2 . ip saddr @session_${tag}_v4 tcp dport $SVC counter accept comment "sess-$tag"
RULES
    session_built "$tag"
}

# Every object module_down will later delete has to exist now. A session
# that builds partially makes module_down's transaction fail atomically,
# which leaves the jump rule in place; the arm then measures a session that
# never closed and reports it as one that did. Cost an hour in section I.
session_built() { # <session-tag>
    local tag="$1" t
    t=$(nft list table inet authnft 2>/dev/null) || t=""
    for obj in "chain session_$tag" "set session_${tag}_v4" \
               "set session_${tag}_v6" "set session_${tag}_cg"; do
        printf '%s' "$t" | grep -q "${obj#* } " || die "session $tag: missing $obj"
    done
}

ct_rule() { nft add rule inet authnft filter ct state established,related counter accept comment '"ct-accept"' || die "ct rule"; }
# Plain append. In a chain that holds only the ct rule this lands the jump
# in the same place the module puts it, which is why the sections that just
# need a working session use it. Where the placement itself is the thing
# under test, the E arms use jump_rule_after_ct and say so.
jump_rule() { nft add rule inet authnft filter jump "session_$1" || die "jump rule for $1"; }
# The placement the module actually uses: immediately after the ct rule.
# `add` alone appends, which puts a later session behind an already-placed
# site deny (E4). Positioning after the ct rule keeps every jump ahead of
# that deny while leaving the established-accept first, so established
# traffic short-circuits instead of walking every live session chain.
jump_rule_after_ct() { # <session-tag>
    local h
    h=$(nft -a list chain inet authnft filter | awk '/ct-accept/{print $NF}')
    [[ -n "$h" ]] || die "no ct rule to position after (session $1)"
    nft add rule inet authnft filter position "$h" jump "session_$1" \
        || die "positioned jump for $1"
}
site_deny() { nft add rule inet authnft filter tcp dport "$1" counter drop comment "\"deny-$1\"" || die "site deny for $1"; }
table_down() { nft delete table inet authnft 2>/dev/null; return 0; }

# close_session, exactly as nft_handler_cleanup issues it.
# Teardown is one atomic transaction: if any object is missing the whole
# batch fails and the session is still up. That failed silently once and a
# revocation case passed for the wrong reason (the session had never closed),
# so this helper now proves its own postcondition instead of trusting nft's
# exit status alone. Every section inherits the check.
module_down() { # <session-tag>
    local tag="$1" h
    h=$(nft -a list chain inet authnft filter | awk "/jump session_$tag/{print \$NF}")
    [[ -n "$h" ]] || die "module_down $tag: no jump rule to delete (session was never up?)"
    nft -f - <<RULES || die "module_down $tag: teardown transaction failed"
delete rule inet authnft filter handle $h
flush chain inet authnft session_$tag
delete chain inet authnft session_$tag
delete set inet authnft session_${tag}_v4
delete set inet authnft session_${tag}_v6
delete set inet authnft session_${tag}_cg
RULES
    nft list chain inet authnft "session_$tag" >/dev/null 2>&1 && \
        die "module_down $tag: chain still present after teardown"
    return 0
}

# A PASS says a payload round-tripped. It does not say which rule let it
# through, and on a policy-accept chain "nothing was enforcing" produces the
# same PASS as "the intended rule fired". admitted_by asserts the counter on
# the rule that was supposed to admit it actually moved.
admitted_by() { # <case-id> <rule-comment> <count before>
    local id="$1" comment="$2" before="$3" after
    after=$(cnt "$comment"); after=${after:-0}; before=${before:-0}
    if [[ "$after" -gt "$before" ]]; then
        printf "       %s admitted by '%s' (%s -> %s)\n" "$id" "$comment" "$before" "$after"
    else
        printf "${RED}[FAIL]${RESET} %s: traffic passed but '%s' never counted (%s -> %s) — nothing was enforcing\n" \
            "$id" "$comment" "$before" "$after" >&2
        RC=1
    fi
}

cnt() { nft list table inet authnft 2>/dev/null | grep "$1" | grep -oP 'packets \K[0-9]+' | head -1; }

serve "$SVC" "$CG_A" || { echo "listener on $SVC never came up" >&2; exit 1; }
serve "$ALT" "$CG_A" || { echo "listener on $ALT never came up" >&2; exit 1; }
serve 19102 "$CG_B" || { echo "listener on 19102 never came up" >&2; exit 1; }

# ======================================================================
note "A. Admission: does an open session actually let traffic through?"
# ======================================================================
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny "$SVC"; site_deny "$ALT"
check A1 PASS  "$(verdict $OK_SRC $SVC)"  "in-session socket, allowed source, allowed port"
check A2 BLOCK "$(verdict $OK_SRC $ALT)"  "same session, port the fragment does not name"
check A3 BLOCK "$(verdict $BAD_SRC $SVC)" "allowed port, source not in the session set"

# The negative cases above must not pass vacuously: the deny counters prove
# the packets arrived and were dropped rather than never being sent.
D_ALT=$(cnt "deny-$ALT"); D_SVC=$(cnt "deny-$SVC")
if [[ -z "$D_ALT" || "$D_ALT" -eq 0 ]]; then
    printf "${RED}[FAIL]${RESET} A2 arrival control: deny counter for %s never moved\n" "$ALT"; RC=1
fi
if [[ -z "$D_SVC" || "$D_SVC" -eq 0 ]]; then
    printf "${RED}[FAIL]${RESET} A3 arrival control: deny counter for %s never moved\n" "$SVC"; RC=1
fi
printf "       arrival controls: deny-%s=%s deny-%s=%s sess-a=%s\n" \
    "$ALT" "${D_ALT:-0}" "$SVC" "${D_SVC:-0}" "$(cnt sess-a)"

# ======================================================================
note "B. Isolation: one session's rules must not admit another's traffic"
# ======================================================================
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny 19102
# alice's session is open; bob's listener is in a different scope and has no
# session of its own. Nothing should admit traffic to it.
check B1 BLOCK "$(verdict $OK_SRC 19102)" "bob's socket, only alice's session open"

# Now with bob's session open too. Built from scratch rather than by adding
# bob's jump to the ruleset above: an appended jump would land after the site
# deny and be shadowed, which is #105 and which this harness tripped over
# while it was being written. Session order is alice, bob, then the deny.
table_down; module_up a "$CG_A" "$OK_SRC"
nft -f - <<RULES || die "bob's session state"
add chain inet authnft session_b
add set inet authnft session_b_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add element inet authnft session_b_v4 { "$CG_B" . $OK_SRC timeout 1d }
add rule inet authnft session_b socket cgroupv2 level 2 . ip saddr @session_b_v4 tcp dport 19102 counter accept comment "sess-b"
RULES
ct_rule; jump_rule a; jump_rule b; site_deny 19102
check B2 PASS  "$(verdict $OK_SRC 19102)" "bob's socket once bob's own session is open"
check B3 BLOCK "$(verdict $BAD_SRC 19102)" "bob's port from a source in neither session's set"

# ======================================================================
note "C. The ct rule: the docs call it load-bearing, so prove it bears load"
# ======================================================================
# Class B, the SSH control connection: a flow that established BEFORE the
# session existed, so no session rule covers it. The ct rule has to carry it.
# The rule is in place before the flow opens, which is the real deployment
# ordering (a previous session, or the site's own stateful ruleset, put it
# there) and it matters: see C3.
table_down
nft -f - <<RULES || die "C setup"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add rule inet authnft filter ct state established,related counter accept comment "ct-accept"
RULES
exec 3<>/dev/tcp/127.0.0.1/$ALT || die "could not open the pre-session flow"
printf 'one\n' >&3; read -t 3 -r _ <&3 || die "pre-session flow never worked"
module_up a "$CG_A" "$OK_SRC"; jump_rule a; site_deny "$ALT"
printf 'two\n' >&3
if read -t 3 -r _ <&3; then C1=PASS; else C1=BLOCK; fi
check C1 PASS "$C1" "pre-session (Class B) flow survives, ct rule present"

# Same flow, ct rule removed. If this still passes, the ct rule is not the
# thing carrying Class B traffic and ARCHITECTURE.txt is wrong.
H=$(nft -a list chain inet authnft filter | awk '/ct-accept/{print $NF}')
nft delete rule inet authnft filter handle "$H" || die "could not delete ct rule"
printf 'three\n' >&3
if read -t 3 -r _ <&3; then C2=PASS; else C2=BLOCK; fi
check C2 BLOCK "$C2" "same flow with the ct rule deleted"
exec 3<&- 2>/dev/null

# The precondition nobody wrote down. Conntrack only tracks a flow it saw
# from the start. If the module's ct rule is the first ct rule on the host,
# conntrack was not tracking when the pre-session flow opened, and adding
# the rule later does not retroactively rescue it: the entry conntrack
# creates mid-stream never satisfies `ct state established` (the accept
# counter stays at 0), so the deny takes every packet. The SSH connection
# that carried the session in is exactly such a flow.
table_down
nft -f - <<RULES || die "C3 setup"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
RULES
exec 5<>/dev/tcp/127.0.0.1/$ALT || die "could not open the untracked flow"
printf 'one\n' >&5; read -t 3 -r _ <&5 || die "untracked flow never worked"
module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny "$ALT"
printf 'two\n' >&5
if read -t 3 -r _ <&5; then C3=PASS; else C3=BLOCK; fi
printf 'three\n' >&5
if read -t 3 -r _ <&5; then C3=PASS; fi
check C3 BLOCK "$C3" "flow that predates conntrack tracking, ct rule added after"
# The ct counter is not zero here: conntrack picks the flow up mid-stream and
# the reply direction matches established. The client-to-server data packets
# still land in the deny. Report both numbers rather than a story about why.
printf "       ct-accept=%s deny-%s=%s (rule present, data packets still dropped)\n" \
    "$(cnt ct-accept)" "$ALT" "$(cnt "deny-$ALT")"
exec 5<&- 2>/dev/null

# ======================================================================
note "D. Teardown: what close_session does and does not revoke (#103)"
# ======================================================================
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny "$SVC"
exec 4<>/dev/tcp/127.0.0.1/$SVC || { echo "session flow would not open" >&2; exit 1; }
printf 'one\n' >&4; read -t 3 -r _ <&4 || { echo "session flow never worked" >&2; exit 1; }
CT_BEFORE_D1=$(cnt ct-accept); CT_BEFORE_D1=${CT_BEFORE_D1:-0}
module_down a
printf 'two\n' >&4
if read -t 3 -r _ <&4; then D1=PASS; else D1=BLOCK; fi
# PASS is the documented bound, not a bug: teardown removes the admission
# path for new flows and leaves conntrack alone. If this ever flips to
# BLOCK, revocation semantics changed and the docs need to change with it.
CT_BEFORE_D1=${CT_BEFORE_D1:-0}
check D1 PASS  "$D1" "flow admitted during the session, after close_session"
admitted_by D1 ct-accept "$CT_BEFORE_D1"
check D2 BLOCK "$(verdict $OK_SRC $SVC)" "new flow after close_session"

conntrack -D -s "$OK_SRC" >/dev/null 2>&1
printf 'three\n' >&4
if read -t 3 -r _ <&4; then D3=PASS; else D3=BLOCK; fi
check D3 BLOCK "$D3" "same flow after a conntrack flush by source address"
exec 4<&- 2>/dev/null

# ======================================================================
note "E. Enforcement placement: where the site deny has to go (#105)"
# ======================================================================
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny "$SVC"
check E1 PASS  "$(verdict $OK_SRC $SVC)" "deny appended to the shared chain AFTER the jump"

table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; site_deny "$SVC"; jump_rule a
check E2 BLOCK "$(verdict $OK_SRC $SVC)" "deny added BEFORE the jump: session chain shadowed"
printf "       shadow control: sess-a=%s (0 proves the jump was never reached)\n" "$(cnt sess-a)"

table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a
nft add chain inet authnft sitedeny '{ type filter hook input priority filter; policy drop; }'
nft add rule inet authnft sitedeny ct state established,related counter accept
check E3 BLOCK "$(verdict $OK_SRC $SVC)" "site deny as a separate base chain at priority filter"
printf "       shadow control: sess-a=%s (>0 proves the module accepted and was overruled)\n" "$(cnt sess-a)"

# E1 is only true until the next login. The module APPENDS its jump rule, so
# a session opened after the site deny lands behind it and is never reached.
# That makes "append the deny after the jumps" unworkable as advice: it is
# correct for the sessions that already exist and silently wrong for every
# one that follows, including after a reboot when the deny is restored from
# the site ruleset before anyone logs in.
#
# The insidious part is that this is not a clean failure. alice, whose jump
# predates the deny, keeps working. bob does not. Same module, same fragment
# shape, same host, opposite outcomes decided by login order.
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny 19102
nft -f - <<RULES || die "bob's session state for E4"
add chain inet authnft session_b
add set inet authnft session_b_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add element inet authnft session_b_v4 { "$CG_B" . $OK_SRC timeout 1d }
add rule inet authnft session_b socket cgroupv2 level 2 . ip saddr @session_b_v4 tcp dport 19102 counter accept comment "sess-b"
RULES
jump_rule b     # appended, so it lands AFTER the deny
check E4 BLOCK "$(verdict $OK_SRC 19102)" "session opened after the site deny: its jump is shadowed"
printf "       shadow control: sess-b=%s (0 proves bob's jump was never reached)\n" "$(cnt sess-b)"
# The control that makes E4 mean something: alice, whose jump predates the
# deny, is unaffected. Without this the run cannot tell "bob is shadowed"
# from "the whole table is broken".
check E5 PASS "$(verdict $OK_SRC $SVC)" "the session that predates the deny still works (E4 control)"

# E4 with the placement changed and nothing else: same order of
# operations, same deny already in place, same fragment. Positioning after
# the ct rule puts bob's jump ahead of the deny instead of behind it.
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule_after_ct a; site_deny 19102
nft -f - <<RULES || die "bob's session state for E6"
add chain inet authnft session_b
add set inet authnft session_b_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add element inet authnft session_b_v4 { "$CG_B" . $OK_SRC timeout 1d }
add rule inet authnft session_b socket cgroupv2 level 2 . ip saddr @session_b_v4 tcp dport 19102 counter accept comment "sess-b"
RULES
jump_rule_after_ct b
check E6 PASS "$(verdict $OK_SRC 19102)" "same session, jump positioned after the ct rule (#105 fix)"
printf "       sess-b=%s (>0 proves bob's jump was reached this time)\n" "$(cnt sess-b)"
# And the deny still denies: a source in nobody's set must not ride in on
# the reordering. Without this E6 could pass by breaking enforcement.
check E7 BLOCK "$(verdict $BAD_SRC 19102)" "deny still denies with the jump positioned (E6 control)"

# E2 with the jump inserted. E2 is the admin who puts the deny in the shared
# chain before any session has ever opened, which is the normal case after a
# reboot: the deny is restored from the site ruleset, then people log in.
# Appending shadowed every one of them. Positioning after the ct rule means
# where the admin puts the deny stops mattering, which is what the
# deployment contract in ADMIN_GUIDE is allowed to claim.
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; site_deny "$SVC"; jump_rule_after_ct a
check E8 PASS "$(verdict $OK_SRC $SVC)" "deny placed BEFORE any session, jump positioned after the ct rule"
printf "       sess-a=%s (>0 proves the jump ran ahead of a deny that predates it)\n" "$(cnt sess-a)"

# Why the jump goes after the ct rule and not at the head of the chain.
# With jumps first, every packet of every established flow walks every live
# session chain before reaching the established-accept, a per-packet cost
# that grows with the number of logged-in users. This arm pins that it does
# not: once a flow is established, the ct rule takes it and the session
# chain never sees it again.
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule_after_ct a
nft insert rule inet authnft session_a counter comment '"entered-a"' || die "traversal counter"
exec 9<>/dev/tcp/127.0.0.1/$SVC || die "E9: flow would not open"
printf 'one\n' >&9; read -t 3 -r _ <&9 || die "E9: flow never worked"
E9_ENTERED=$(cnt entered-a); E9_ENTERED=${E9_ENTERED:-0}
E9_CT=$(cnt ct-accept); E9_CT=${E9_CT:-0}
for _ in 1 2 3; do drain 9; printf 'more\n' >&9; read -t 3 -r _ <&9 || true; done
E9_ENTERED2=$(cnt entered-a); E9_ENTERED2=${E9_ENTERED2:-0}
E9_CT2=$(cnt ct-accept); E9_CT2=${E9_CT2:-0}
check E9 PASS "$([[ "$E9_ENTERED2" -eq "$E9_ENTERED" && "$E9_CT2" -gt "$E9_CT" ]] && echo PASS || echo BLOCK)" \
    "established traffic short-circuits at the ct rule, never entering a session chain"
printf "       session-chain entries %s -> %s (must not move), ct-accept %s -> %s (must move)\n" \
    "$E9_ENTERED" "$E9_ENTERED2" "$E9_CT" "$E9_CT2"
exec 9<&- 2>/dev/null

# ======================================================================
note "F. Complex fragments: a session chain that denies as well as allows"
# ======================================================================
# The restriction model: the fragment narrows what the session may reach.
# Denies live in the per-session chain, so they die with the session.
table_down; module_up a "$CG_A" "$OK_SRC"
nft add rule inet authnft session_a socket cgroupv2 level 2 @session_a_cg tcp dport $ALT counter drop comment '"sess-a-deny"'
nft add element inet authnft session_a_cg "{ \"$CG_A\" timeout 1d }"
ct_rule; jump_rule a
F1_BEFORE=$(cnt sess-a); F1_BEFORE=${F1_BEFORE:-0}
check F1 PASS  "$(verdict $OK_SRC $SVC)" "fragment allow rule, no site deny in play"
admitted_by F1 sess-a "$F1_BEFORE"
check F2 BLOCK "$(verdict $OK_SRC $ALT)" "fragment deny rule inside the session chain"
printf "       fragment deny counter: %s\n" "$(cnt sess-a-deny)"

# And the same denied port once the session closes: the deny goes with it.
module_down a
# F3 passes because the deny went with the session, not because the traffic
# was never sent or the table vanished. The rule's counter is unreachable
# once its chain is gone, which is the proof; G2 separately pins that the
# shared chain survived, so "everything vanished" cannot produce this pass.
check F3 PASS "$(verdict $OK_SRC $ALT)" "fragment deny does not outlive the session"
if [[ -n "$(cnt sess-a-deny)" ]]; then
    printf "${RED}[FAIL]${RESET} F3: the fragment deny rule is still present after close\n" >&2
    RC=1
else
    printf "       F3 control: the fragment deny rule is gone, not merely unmatched\n"
fi

# ======================================================================
note "G. Cleanup boundary: what close_session leaves behind"
# ======================================================================
# Teardown is scoped to the four objects the module named: the jump rule,
# the per-session chain, and the three sets. Everything else a session
# touched stays. Some of that is deliberate (the shared chain is shared),
# some of it is a fragment's doing and documented as the admin's problem,
# and one of them is state the module never had a handle on at all.
table_down; module_up a "$CG_A" "$OK_SRC"
nft -f - <<RULES || die "G setup"
add chain inet authnft frag_extra
add rule inet authnft frag_extra tcp dport $ALT counter drop comment "frag-chain-deny"
add rule inet authnft session_a jump frag_extra
RULES
ct_rule; jump_rule a; site_deny "$SVC"
# A fragment rule in the SHARED chain. A top-level fragment cannot do this
# (check_statement rejects "add rule inet authnft filter ..."), but an
# included file is allowed to: NFT_FRAG_INCLUDED drops the shared-chain guard
# because INTEGRATIONS 4.6 makes the shared chain the documented target for
# included rules. The rule is validated, just not cleaned up: it lives outside
# the per-session chain, so close_session never had a handle on it (INTEGRATIONS
# 4.5). The point of the case is what that leftover rule does to traffic once
# the session ends. The harness adds it with plain nft because it is measuring
# the leftover, not the include walk (that path is covered by test-include-walk).
nft add rule inet authnft filter tcp dport 19102 counter drop comment '"frag-shared-deny"' || die "shared frag rule"

exec 6<>/dev/tcp/127.0.0.1/$SVC || die "G flow would not open"
printf 'one\n' >&6; read -t 3 -r _ <&6 || die "G flow never worked"
module_down a

leftover() { nft list table inet authnft 2>/dev/null | grep -c "$1"; }
G_CT=$(leftover 'ct-accept'); G_FRAG=$(leftover 'frag-chain-deny'); G_SHARED=$(leftover 'frag-shared-deny')
G_SESS=$(leftover 'session_a')
check G1 BLOCK "$([[ $G_SESS -eq 0 ]] && echo BLOCK || echo PASS)" "per-session chain and sets are gone after close"
check G2 PASS  "$([[ $G_CT -gt 0 ]] && echo PASS || echo BLOCK)"   "shared chain and its ct rule survive close (by design)"
check G3 PASS  "$([[ $G_FRAG -gt 0 ]] && echo PASS || echo BLOCK)" "chain a fragment created survives close (INTEGRATIONS 4.5)"
check G4 PASS  "$([[ $G_SHARED -gt 0 ]] && echo PASS || echo BLOCK)" "rule a fragment put in the shared chain survives close"
# And the wire consequence of G4: that leftover rule still denies traffic
# belonging to nobody's session, on a port the closed session never owned.
check G5 BLOCK "$(verdict $OK_SRC 19102)" "leftover shared-chain fragment rule still drops after close"
exec 6<&- 2>/dev/null

# ======================================================================
note "I. Conntrack revocation: the ct mark gate proposed for #103"
# ======================================================================
# D1 is the gap: a flow admitted during a session keeps passing after close,
# because the shared established-accept fires before any session jump and
# conntrack never hears about the teardown.
#
# The proposed shape. Each session tags new connections with an id in the low
# 24 bits of ct mark. The shared established-accept is split in two: untagged
# flows (the SSH connection, everything the module does not govern) accept
# unconditionally; tagged flows accept only while their id is in a live
# sessions set. Close deletes the element, so the next packet of a revoked
# flow falls through to the site deny.
#
# None of this is in the module. These arms decide whether it is worth
# building, against the real chain layout rather than a synthetic one, and
# with a real pre-session flow standing in for the SSH connection, because
# breaking that locks everyone out of the host.
SESS_MASK=0x00ffffff     # the slice a session id lives in
ADMIN_MASK=0xff000000    # bits the admin keeps
ADMIN_BITS=0xab000000    # what an admin rule puts there first
CTM_A=0x000001
CTM_B=0x000002

# The shared chain, with the established-accept split. Order matches the
# module: jumps are inserted at the head, everything else appended.
ctmark_up() { # <session-tag> <cgroup> <src> <session-id>
    local tag="$1" cg="$2" src="$3" sid="$4"
    nft -f - <<RULES || die "ct mark gate setup for $tag"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add set inet authnft live_sessions { type mark; }
add chain inet authnft session_$tag
add set inet authnft session_${tag}_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add set inet authnft session_${tag}_v6 { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }
add set inet authnft session_${tag}_cg { typeof socket cgroupv2 level 2; flags timeout; }
add element inet authnft session_${tag}_v4 { "$cg" . $src timeout 1d }
add rule inet authnft session_$tag ct state new ct mark set ct mark and $ADMIN_MASK or $sid counter comment "tag-$tag"
add rule inet authnft session_$tag socket cgroupv2 level 2 . ip saddr @session_${tag}_v4 tcp dport $SVC counter accept comment "sess-$tag"
add element inet authnft live_sessions { $sid }
RULES
    session_built "$tag"
    nft insert rule inet authnft filter jump "session_$tag" || die "jump for $tag"
}

# Order matters and cost an hour: the unsessioned flow has to be opened
# before the deny exists and before the session does, because it stands in
# for the SSH connection that carried the login in. Opening it after the
# deny hangs on the TCP connect timeout rather than failing, which is why
# hold_open() bounds the connect.
# Discard anything already queued on the socket before probing it. Without
# this a reply that was in flight when the rules changed is read by the NEXT
# probe and reports a revoked flow as alive, one assertion late. Same trap as
# the nonce matching in tests/ct_mark_revocation_matrix.sh.
drain() { local fd="$1" _junk; while read -r -t 0.3 -u "$fd" _junk 2>/dev/null; do :; done; return 0; }

hold_open() { # <fd> <port>   returns 1 rather than blocking on a dropped SYN
    local fd="$1" port="$2"
    timeout 5 bash -c "exec 9<>/dev/tcp/127.0.0.1/$port" 2>/dev/null || return 1
    eval "exec $fd<>/dev/tcp/127.0.0.1/$port" 2>/dev/null || return 1
    return 0
}

table_down
# The gate, installed before any flow exists. C3 established that a ct rule
# added after a flow opened does not rescue it, so the gate has to predate
# the connection it is meant to carry. An admin rule claims the high bits
# first, so nothing below passes by comparing against a bare zero.
nft -f - <<RULES || die "I: gate setup"
add table inet authnft
add chain inet authnft filter { type filter hook input priority filter - 1; policy accept; }
add set inet authnft live_sessions { type mark; }
add chain inet authnft adminmark { type filter hook input priority filter - 10; policy accept; }
add rule inet authnft adminmark ct state new ct mark set ct mark or $ADMIN_BITS counter comment "admin-mark"
add rule inet authnft filter ct state established,related ct mark and $SESS_MASK 0x0 counter accept comment "est-unsessioned"
add rule inet authnft filter ct state established,related ct mark and $SESS_MASK @live_sessions counter accept comment "est-live"
RULES

# The SSH connection. Established before the session and before the deny,
# never tagged. If this arm ever fails, the change locks the operator out.
hold_open 7 "$ALT" || die "I: could not open the unsessioned flow"
printf 'one\n' >&7; read -t 3 -r _ <&7 || die "I: unsessioned flow never worked"

ctmark_up a "$CG_A" "$OK_SRC" "$CTM_A"
site_deny "$SVC"; site_deny "$ALT"

hold_open 8 "$SVC" || die "I: session flow would not open"
printf 'one\n' >&8; read -t 3 -r _ <&8 || die "I: session flow never worked"
check I1 PASS "PASS" "session flow admitted while the session is live (control)"
# Earlier sections leave a dozen conntrack entries on this port in TIME_WAIT
# and SYN_SENT. Filtering to the single ESTABLISHED one is what makes this
# reproducible; head -1 over all of them returned a different mark per run.
session_mark() {
    local rows n
    rows=$(conntrack -L -p tcp --dport "$SVC" --state ESTABLISHED 2>/dev/null) || rows=""
    n=$(printf '%s' "$rows" | grep -c 'mark=') || n=0
    if [[ "$n" -ne 1 ]]; then echo "AMBIGUOUS:$n"; return 0; fi
    printf '0x%08x' "$(printf '%s' "$rows" | grep -oP 'mark=\K[0-9]+' | head -1)"
}
CTM_LIVE=$(session_mark)
printf "       session entry mark: %s (want %s | %s)\n" "$CTM_LIVE" "$ADMIN_BITS" "$CTM_A"

# Close, exactly as close_session would: drop the live-sessions element,
# then tear the per-session objects down.
nft delete element inet authnft live_sessions "{ $CTM_A }" || die "I: could not revoke"
module_down a

printf "       jumps left after close: %s (0 proves the teardown transaction committed)\n" \
    "$(nft list chain inet authnft filter 2>/dev/null | grep -c 'jump session_' || true)"
drain 8; printf 'two\n' >&8
if read -t 3 -r _ <&8; then I2=PASS; else I2=BLOCK; fi
check I2 BLOCK "$I2" "flow admitted during the session, after close (D1 fixed)"

I3_BEFORE=$(cnt est-unsessioned); I3_BEFORE=${I3_BEFORE:-0}
drain 7; printf 'two\n' >&7
if read -t 3 -r _ <&7; then I3=PASS; else I3=BLOCK; fi
check I3 PASS "$I3" "untagged flow survives the same close (the SSH connection)"
admitted_by I3 est-unsessioned "$I3_BEFORE"
printf "       est-unsessioned=%s est-live=%s\n" "$(cnt est-unsessioned)" "$(cnt est-live)"

# Id reuse. The stale entry still carries the old id, so a new session handed
# the same id resurrects a flow that was revoked. This is the constraint any
# implementation must solve, and the arm exists so it cannot be forgotten.
nft add element inet authnft live_sessions "{ $CTM_A }" || die "I: could not re-add"
drain 8; printf 'three\n' >&8
if read -t 3 -r _ <&8; then I4=PASS; else I4=BLOCK; fi
check I4 PASS "$I4" "reusing a session id resurrects the revoked flow (why ids must not repeat)"

nft delete element inet authnft live_sessions "{ $CTM_A }" || die "I: could not re-revoke"
nft add element inet authnft live_sessions "{ $CTM_B }" || die "I: could not add a fresh id"
drain 8; printf 'four\n' >&8
if read -t 3 -r _ <&8; then I5=PASS; else I5=BLOCK; fi
check I5 BLOCK "$I5" "a fresh id does not resurrect it (I4 control)"

# The tag is written once, at connection setup, so the reading taken while
# the session was live is what answers this.
if [[ "$CTM_LIVE" == AMBIGUOUS:* ]]; then
    check I6 PASS BLOCK "admin mark bits preserved (could not isolate the flow: $CTM_LIVE)"
else
    CTM_ADMIN=$(printf '0x%08x' $(( CTM_LIVE & 0xff000000 )))
    check I6 PASS "$([[ "$CTM_ADMIN" == "$ADMIN_BITS" ]] && echo PASS || echo BLOCK)" \
        "the session tag preserved the admin's mark bits ($CTM_LIVE, admin slice $CTM_ADMIN)"
fi
exec 7<&- 2>/dev/null; exec 8<&- 2>/dev/null

# ======================================================================
note "H. Packet traces: the kernel's own account of the traversal"
# ======================================================================
# Counters say a rule matched. A trace says which chains the packet walked,
# in order, and what verdict ended it. `nft monitor trace` is the kernel
# telling us directly, so it is the strongest evidence in this file.
TRACE_DIR="${AUTHNFT_TRACE_DIR:-}"
trace_case() { # <slug> <label> <src> <port>
    local slug="$1" label="$2" src="$3" port="$4" out
    out=$(mktemp)
    nft add chain inet authnft trace_hook \
        '{ type filter hook prerouting priority raw - 1; policy accept; }' 2>/dev/null
    nft add rule inet authnft trace_hook tcp dport "$port" meta nftrace set 1 2>/dev/null
    timeout 6 nft monitor trace > "$out" 2>/dev/null &
    local mon=$!
    sleep 0.4
    flow "$src" "$port" >/dev/null 2>&1
    sleep 0.4
    kill $mon 2>/dev/null; wait $mon 2>/dev/null
    printf "\n    ${YELLOW}%s${RESET}\n" "$label"
    # First packet of the flow only: the SYN decides admission, and the
    # retransmits that follow a drop are the same story repeated.
    grep -E 'rule|verdict|policy' "$out" | head -8 | sed 's/^/      /'
    [[ -n "$TRACE_DIR" ]] && cp "$out" "$TRACE_DIR/$slug.txt"
    rm -f "$out"
    nft delete chain inet authnft trace_hook 2>/dev/null
}

if nft monitor trace >/dev/null 2>&1 & sleep 0.2; kill $! 2>/dev/null; then
    table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a; site_deny "$SVC"; site_deny "$ALT"
    trace_case admitted "admitted: session rule accepts" "$OK_SRC" "$SVC"
    trace_case denied-by-site "denied: port the session does not own" "$OK_SRC" "$ALT"
    table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule a
    nft add chain inet authnft sitedeny '{ type filter hook input priority filter; policy drop; }'
    trace_case denied-by-foreign-chain \
        "denied by a separate chain the module cannot see (#105)" "$OK_SRC" "$SVC"
else
    printf "    ${YELLOW}[SKIP]${RESET} nft monitor trace unavailable\n"
fi

# ======================================================================
printf "\n${BLUE}>>> MATRIX${RESET}\n"
printf "    %-6s %-8s %-8s %s\n" CASE EXPECTED OBSERVED PINS
for row in "${ROWS[@]}"; do
    IFS='|' read -r id want got st desc <<< "$row"
    printf "    %-6s %-8s %-8s %s%s\n" "$id" "$want" "$got" "$desc" \
        "$([[ $st == MISMATCH ]] && echo '   <-- MISMATCH')"
done

# A section that dies quietly, or an arm that is edited out, shows up here
# as a short matrix rather than as a clean pass. This is the D3 class the
# codex bot found: the run reported success for cases it never executed.
EXPECTED_CASES=35
if [[ ${#ROWS[@]} -ne $EXPECTED_CASES ]]; then
    printf "\n${RED}>>> %d cases recorded, expected %d. A section did not run.${RESET}\n" \
        "${#ROWS[@]}" "$EXPECTED_CASES"
    RC=1
fi

if [[ $RC -eq 0 ]]; then
    printf "\n${BLUE}>>> EVERY CASE MATCHED THE WIRE (kernel %s)${RESET}\n" "$(uname -r)"
else
    printf "\n${RED}>>> PACKET-FLOW MATRIX FAILED (kernel %s)${RESET}\n" "$(uname -r)"
fi
exit $RC
