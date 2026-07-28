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
die() { printf "${RED}>>> SETUP FAILED: %s${RESET}\n" "$*" >&2; exit 1; }

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
}

ct_rule() { nft add rule inet authnft filter ct state established,related counter accept comment '"ct-accept"' || die "ct rule"; }
jump_rule() { nft add rule inet authnft filter jump "session_$1" || die "jump rule for $1"; }
# The same jump, prepended. `add` appends, which is what puts a later
# session behind an already-placed site deny (E4). `insert` puts every
# jump at the head of the chain, so the deny stays last however many
# sessions open after it.
jump_rule_insert() { nft insert rule inet authnft filter jump "session_$1" || die "jump insert for $1"; }
site_deny() { nft add rule inet authnft filter tcp dport "$1" counter drop comment "\"deny-$1\"" || die "site deny for $1"; }
table_down() { nft delete table inet authnft 2>/dev/null; return 0; }

# close_session, exactly as nft_handler_cleanup issues it.
module_down() { # <session-tag>
    local tag="$1" h
    h=$(nft -a list chain inet authnft filter | awk "/jump session_$tag/{print \$NF}")
    nft -f - <<RULES
delete rule inet authnft filter handle $h
flush chain inet authnft session_$tag
delete chain inet authnft session_$tag
delete set inet authnft session_${tag}_v4
delete set inet authnft session_${tag}_v6
delete set inet authnft session_${tag}_cg
RULES
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
module_down a
printf 'two\n' >&4
if read -t 3 -r _ <&4; then D1=PASS; else D1=BLOCK; fi
# PASS is the documented bound, not a bug: teardown removes the admission
# path for new flows and leaves conntrack alone. If this ever flips to
# BLOCK, revocation semantics changed and the docs need to change with it.
check D1 PASS  "$D1" "flow admitted during the session, after close_session"
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

# E4 with one verb changed. Everything else is identical: same order of
# operations, same deny already in place, same fragment. `insert` puts
# bob's jump ahead of the deny instead of behind it.
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; jump_rule_insert a; site_deny 19102
nft -f - <<RULES || die "bob's session state for E6"
add chain inet authnft session_b
add set inet authnft session_b_v4 { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }
add element inet authnft session_b_v4 { "$CG_B" . $OK_SRC timeout 1d }
add rule inet authnft session_b socket cgroupv2 level 2 . ip saddr @session_b_v4 tcp dport 19102 counter accept comment "sess-b"
RULES
jump_rule_insert b
check E6 PASS "$(verdict $OK_SRC 19102)" "same session, jump INSERTED rather than appended (#105 fix)"
printf "       sess-b=%s (>0 proves bob's jump was reached this time)\n" "$(cnt sess-b)"
# And the deny still denies: a source in nobody's set must not ride in on
# the reordering. Without this E6 could pass by breaking enforcement.
check E7 BLOCK "$(verdict $BAD_SRC 19102)" "deny still denies with jumps inserted (E6 control)"

# E2 with the jump inserted. E2 is the admin who puts the deny in the shared
# chain before any session has ever opened, which is the normal case after a
# reboot: the deny is restored from the site ruleset, then people log in.
# Appending shadowed every one of them. Inserting means position within the
# chain stops mattering at all, which is what the deployment contract in
# ADMIN_GUIDE is allowed to claim.
table_down; module_up a "$CG_A" "$OK_SRC"; ct_rule; site_deny "$SVC"; jump_rule_insert a
check E8 PASS "$(verdict $OK_SRC $SVC)" "deny placed BEFORE any session, jump inserted"
printf "       sess-a=%s (>0 proves the jump ran ahead of a deny that predates it)\n" "$(cnt sess-a)"

# ======================================================================
note "F. Complex fragments: a session chain that denies as well as allows"
# ======================================================================
# The restriction model: the fragment narrows what the session may reach.
# Denies live in the per-session chain, so they die with the session.
table_down; module_up a "$CG_A" "$OK_SRC"
nft add rule inet authnft session_a socket cgroupv2 level 2 @session_a_cg tcp dport $ALT counter drop comment '"sess-a-deny"'
nft add element inet authnft session_a_cg "{ \"$CG_A\" timeout 1d }"
ct_rule; jump_rule a
check F1 PASS  "$(verdict $OK_SRC $SVC)" "fragment allow rule, no site deny in play"
check F2 BLOCK "$(verdict $OK_SRC $ALT)" "fragment deny rule inside the session chain"
printf "       fragment deny counter: %s\n" "$(cnt sess-a-deny)"

# And the same denied port once the session closes: the deny goes with it.
module_down a
check F3 PASS "$(verdict $OK_SRC $ALT)" "fragment deny does not outlive the session"

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

if [[ $RC -eq 0 ]]; then
    printf "\n${BLUE}>>> EVERY CASE MATCHED THE WIRE (kernel %s)${RESET}\n" "$(uname -r)"
else
    printf "\n${RED}>>> PACKET-FLOW MATRIX FAILED (kernel %s)${RESET}\n" "$(uname -r)"
fi
exit $RC
